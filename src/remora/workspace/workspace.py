"""Workspace lifecycle: connection and lock ownership (issue #28).

DuckDB holds a single-writer lock: one long-lived read-write connection
blocks every other process's reads. :class:`Workspace` therefore opens
read-only by default, and in ``"rw"`` mode holds **no** persistent
connection at all — every operation acquires a short-lived read-write
connection and releases it promptly, so the file stays readable by other
processes between writes. Nothing at module level opens or caches a
connection, and duckdb itself is imported lazily inside the connect
helper, keeping the package import-pure like its siblings.

A DuckDB checkpoint truncates only *trailing* free blocks, so deleting
everything largely shrinks the file on its own while scattered deletes
leave interior free blocks the file keeps forever;
:meth:`Workspace.compact` reclaims those by rewriting into a temp file
and atomically swapping it in, holding the source's exclusive lock
across both steps so a concurrent writer cannot slip a commit into the
gap, and so an interrupted compact always leaves the original intact.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Literal

from remora.workspace.errors import WorkspaceError, WorkspaceModeError
from remora.workspace.schema import check_compatible, create_schema

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = ["Workspace"]

Mode = Literal["ro", "rw"]

_MODES: tuple[Mode, ...] = ("ro", "rw")


def _connect(path: str, *, read_only: bool) -> DuckDBPyConnection:
    """Open a DuckDB connection, importing duckdb only now.

    Raises:
        ImportError: If duckdb is not installed, naming the extra that
            provides it.
    """
    try:
        import duckdb
    except ImportError as exc:
        raise ImportError(
            "the remora workspace requires duckdb; install it with pip install 'remora[workspace]'"
        ) from exc
    return duckdb.connect(path, read_only=read_only)


def _quote_path(path: str) -> str:
    """Escape a path for interpolation into a single-quoted SQL literal."""
    return path.replace("'", "''")


def _quote_ident(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


class Workspace:
    """A remora workspace file and the discipline for connecting to it.

    Args:
        path: The workspace file. In ``"rw"`` mode a missing file is
            created; in ``"ro"`` mode it is an error.
        mode: ``"ro"`` (the default) holds one long-lived read-only
            connection for the workspace's lifetime; concurrent readers in
            other processes are unaffected. ``"rw"`` holds no connection
            between operations: each write takes the exclusive DuckDB
            write lock only for its own short transaction.
    """

    def __init__(self, path: str | os.PathLike[str], mode: Mode = "ro") -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be 'ro' or 'rw', not {mode!r}")
        self._path = Path(os.fspath(path))
        self._mode: Mode = mode
        # Held only in ro mode; rw mode never keeps a connection open.
        self._con: DuckDBPyConnection | None = None
        self._opened = False
        # Count of write()/rw-read() bodies currently executing; compact()
        # refuses while nonzero, since it would swap the file out from
        # under a connection this process is still using.
        self._busy = 0

    @property
    def path(self) -> Path:
        """The workspace file."""
        return self._path

    @property
    def mode(self) -> Mode:
        """The mode the workspace was constructed with."""
        return self._mode

    def open(self) -> Workspace:
        """Open the workspace, creating it first when rw mode needs to.

        Opening always verifies the schema version. In rw mode a brand-new
        (empty) database gets the schema; a non-empty database is never
        touched before :func:`~remora.workspace.schema.check_compatible`
        accepts it, so an old-format file is refused rather than
        half-upgraded.

        Returns:
            This workspace, for use as ``with Workspace(...) as ws:``.

        Raises:
            WorkspaceError: If already open, or ro mode finds no file.
            SchemaVersionError: If the file is not a compatible workspace.
            ImportError: If duckdb is not installed.
        """
        if self._opened:
            raise WorkspaceError("workspace is already open")
        if self._mode == "ro":
            if not self._path.exists():
                raise WorkspaceError(
                    f"no workspace at {self._path}; create one by opening "
                    f"with Workspace(path, mode='rw')"
                )
            con = _connect(str(self._path), read_only=True)
            try:
                check_compatible(con)
            except BaseException:
                con.close()
                raise
            self._con = con
        else:
            con = _connect(str(self._path), read_only=False)
            try:
                if self._is_empty(con):
                    create_schema(con)
                check_compatible(con)
            finally:
                con.close()
        self._opened = True
        return self

    def close(self) -> None:
        """Close the workspace. Idempotent."""
        if self._con is not None:
            self._con.close()
            self._con = None
        self._opened = False

    def __enter__(self) -> Workspace:
        return self.open()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _require_open(self) -> None:
        if not self._opened:
            raise WorkspaceError("workspace is not open; use it as a context manager")

    @contextmanager
    def read(self) -> Iterator[DuckDBPyConnection]:
        """Yield a connection for reading.

        In ro mode this is the workspace's held read-only connection. In
        rw mode it is a short-lived connection opened for this read and
        closed on exit — opened read-write, not read-only, because DuckDB
        refuses two live same-process connections to one file with
        different configurations, and a caller may nest a read inside
        :meth:`write`. Callers must not write through the yielded
        connection; writes go through :meth:`write`, which owns the
        one-transaction discipline.
        """
        self._require_open()
        if self._mode == "ro":
            assert self._con is not None
            yield self._con
            return
        self._busy += 1
        try:
            con = _connect(str(self._path), read_only=False)
            try:
                yield con
            finally:
                con.close()
        finally:
            self._busy -= 1

    @contextmanager
    def write(self) -> Iterator[DuckDBPyConnection]:
        """Yield a short-lived read-write connection wrapping one transaction.

        The transaction commits on clean exit and rolls back on exception;
        the connection closes either way, releasing DuckDB's exclusive
        write lock promptly so other processes can read between writes.

        Raises:
            WorkspaceModeError: In ro mode; reopen with
                ``Workspace(path, mode='rw')`` to write.
        """
        self._require_open()
        if self._mode == "ro":
            raise WorkspaceModeError(
                f"workspace {self._path} is open read-only; reopen with "
                f"Workspace(path, mode='rw') to write"
            )
        self._busy += 1
        try:
            con = _connect(str(self._path), read_only=False)
            try:
                con.execute("BEGIN")
                try:
                    yield con
                except BaseException:
                    con.execute("ROLLBACK")
                    raise
                con.execute("COMMIT")
            finally:
                con.close()
        finally:
            self._busy -= 1

    def compact(self) -> None:
        """Rewrite the workspace file to reclaim space.

        A checkpoint only truncates trailing free blocks, so a file stays
        large after scattered deletes; this copies every schema, table and
        row into ``<name>.compacting`` beside the original (same directory,
        so the final rename never crosses a filesystem) and atomically
        swaps it in with :func:`os.replace`. The original is only ever
        replaced whole: an interruption at any point leaves it intact, and
        at worst a stale temp file — plus the ``.wal`` sidecar a hard kill
        mid-copy can leave beside it — that the next compact removes.

        The copy runs on a read-write connection to the source and the
        swap happens while that connection is still open, so the source's
        exclusive lock is held across both. Other processes — readers as
        well as writers — are locked out for compact's whole duration and
        fail fast on the lock rather than losing data: a concurrent
        writer either commits before compaction begins (and is copied) or
        cannot connect until the swap is done, so no commit can land
        between the snapshot and the rename and be silently discarded.
        Conversely, compaction needs sole access: if any other process —
        even a read-only reader — is already connected when it starts, the
        connect fails with DuckDB's lock error and nothing is modified.

        A :meth:`write` or rw-mode :meth:`read` in flight on this
        workspace raises :class:`WorkspaceError` instead, since the
        same-process connections share one DuckDB instance and would not
        hit the lock. Other :class:`Workspace` objects or threads in this
        process are still the caller's responsibility.

        Raises:
            WorkspaceModeError: In ro mode; reopen with
                ``Workspace(path, mode='rw')`` to compact.
            WorkspaceError: If a :meth:`write` or rw-mode :meth:`read` on
                this workspace is in flight.
        """
        self._require_open()
        if self._mode == "ro":
            raise WorkspaceModeError(
                f"workspace {self._path} is open read-only; reopen with "
                f"Workspace(path, mode='rw') to compact"
            )
        if self._busy:
            raise WorkspaceError(
                f"workspace {self._path} has a write() or read() in flight; "
                f"compact() would swap the file out from under it"
            )
        tmp = self._path.with_name(self._path.name + ".compacting")
        tmp_wal = tmp.with_name(tmp.name + ".wal")
        tmp.unlink(missing_ok=True)
        tmp_wal.unlink(missing_ok=True)
        try:
            # Hold the source's exclusive lock through both the copy and
            # the swap: a writer in another process either commits before
            # the lock is taken (and is copied) or cannot connect until the
            # swap is done, so no commit can land between the snapshot and
            # os.replace and be silently discarded.
            con = _connect(str(self._path), read_only=False)
            try:
                row = con.execute("SELECT current_database()").fetchone()
                assert row is not None
                con.execute(f"ATTACH '{_quote_path(str(tmp))}' AS compact_dst")
                con.execute(f"COPY FROM DATABASE {_quote_ident(str(row[0]))} TO compact_dst")
                con.execute("DETACH compact_dst")
                os.replace(tmp, self._path)
            finally:
                con.close()
        except BaseException:
            tmp.unlink(missing_ok=True)
            tmp_wal.unlink(missing_ok=True)
            raise

    @staticmethod
    def _is_empty(con: DuckDBPyConnection) -> bool:
        """True when the current database holds no tables at all.

        Pinned to ``current_database()`` like every catalog probe in
        :mod:`remora.workspace.schema`, so an attached database cannot
        make a fresh file look populated.
        """
        row = con.execute(
            "SELECT count(*) FROM duckdb_tables() WHERE database_name = current_database()"
        ).fetchone()
        return row is None or int(row[0]) == 0
