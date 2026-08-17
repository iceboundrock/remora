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

The file lock cannot arbitrate *within* one process — same-process
connections to one file share DuckDB's database instance — so a
module-level registry keyed by the file's *identity* (``st_dev`` and
``st_ino``, so every spelling, symlink and hard link of one file lands on
one entry) makes writes and compaction mutually exclusive across every
:class:`Workspace` object and thread here. It holds plain counters and
flags, never a connection.
"""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Final, Literal

from remora.workspace.errors import WorkspaceError, WorkspaceModeError
from remora.workspace.schema import check_compatible, create_schema

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = ["Workspace"]

Mode = Literal["ro", "rw"]

_MODES: tuple[Mode, ...] = ("ro", "rw")

# ``(st_dev, st_ino)`` normally; the resolved pathname only as a fallback for
# a file that cannot be stat'ed (see :func:`_file_key`).
_FileKey = tuple[int, int] | str


class _FileState:
    """Per-file coordination shared by every Workspace in this process."""

    __slots__ = ("busy", "compacting")

    def __init__(self) -> None:
        self.busy = 0  # write()/rw-read() bodies currently executing
        self.compacting = False


# Same-process connections to one file share DuckDB's database instance, so
# the file lock cannot arbitrate between Workspace objects in this process.
# This registry does; it holds plain counters and flags, never a connection.
_FILE_STATES: Final[dict[_FileKey, _FileState]] = {}
_FILE_STATES_GUARD: Final[threading.Lock] = threading.Lock()


def _file_key(path: Path) -> _FileKey:
    """Identity of the file behind ``path`` for the coordination registry.

    ``os.stat`` follows symlinks, and one inode has one ``(st_dev, st_ino)``
    no matter how the path spells it — case aliases and hard links included,
    which pathname-based keys get wrong on case-insensitive filesystems.
    Computed fresh for every operation rather than cached, because
    ``compact()`` swaps the inode: operations that begin after the swap key
    on the new file, which is correct — the old inode can no longer be
    reached through any path. Falls back to the resolved pathname when the
    file cannot be stat'ed, so acquisition never masks the real error the
    connect attempt is about to raise.
    """
    try:
        st = os.stat(path)
    except OSError:
        return os.path.realpath(path)
    return (st.st_dev, st.st_ino)


def _acquire_write_slot(key: _FileKey, path: Path) -> None:
    with _FILE_STATES_GUARD:
        state = _FILE_STATES.setdefault(key, _FileState())
        if state.compacting:
            raise WorkspaceError(
                f"a compact() is in progress on {path}; writes and rw-mode "
                f"reads fail fast until it finishes"
            )
        state.busy += 1


def _release_write_slot(key: _FileKey) -> None:
    with _FILE_STATES_GUARD:
        state = _FILE_STATES[key]
        state.busy -= 1
        if state.busy == 0 and not state.compacting:
            del _FILE_STATES[key]


def _begin_compact(key: _FileKey, path: Path) -> None:
    with _FILE_STATES_GUARD:
        state = _FILE_STATES.setdefault(key, _FileState())
        if state.busy:
            raise WorkspaceError(
                f"workspace {path} has a write() or read() in flight; "
                f"compact() would swap the file out from under it"
            )
        if state.compacting:
            raise WorkspaceError(f"another compact() is already in progress on {path}")
        state.compacting = True


def _end_compact(key: _FileKey) -> None:
    with _FILE_STATES_GUARD:
        state = _FILE_STATES[key]
        state.compacting = False
        if state.busy == 0:
            del _FILE_STATES[key]


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

        Raises:
            WorkspaceError: In rw mode, if a :meth:`compact` on this file is
                in progress anywhere in this process — mirroring the
                fail-fast lock error a second process gets.
        """
        self._require_open()
        if self._mode == "ro":
            assert self._con is not None
            yield self._con
            return
        key = _file_key(self._path)
        _acquire_write_slot(key, self._path)
        try:
            con = _connect(str(self._path), read_only=False)
            try:
                yield con
            finally:
                con.close()
        finally:
            _release_write_slot(key)

    @contextmanager
    def write(self) -> Iterator[DuckDBPyConnection]:
        """Yield a short-lived read-write connection wrapping one transaction.

        The transaction commits on clean exit and rolls back on exception;
        the connection closes either way, releasing DuckDB's exclusive
        write lock promptly so other processes can read between writes.

        Raises:
            WorkspaceModeError: In ro mode; reopen with
                ``Workspace(path, mode='rw')`` to write.
            WorkspaceError: If a :meth:`compact` on this file is in progress
                anywhere in this process — mirroring the fail-fast lock
                error a second process gets.
        """
        self._require_open()
        if self._mode == "ro":
            raise WorkspaceModeError(
                f"workspace {self._path} is open read-only; reopen with "
                f"Workspace(path, mode='rw') to write"
            )
        key = _file_key(self._path)
        _acquire_write_slot(key, self._path)
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
            _release_write_slot(key)

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

        A workspace addressed through a symlink is compacted at its
        *resolved* target: the temp lives beside the real file and the swap
        replaces the real file, so the symlink itself survives instead of
        being turned into an independent regular file. A *hard* link cannot
        survive an atomic swap by construction — the replaced name gets a
        new inode while the other name keeps the old one, so the two
        diverge; coordination is unaffected (it follows file identity, so
        the compact locks out writes through every alias while it runs),
        but a hardlinked alias goes on referring to the pre-compact file.

        Permission bits are preserved across the swap: the temp is a fresh
        file with umask defaults, so the source's mode is copied onto it
        before the rename. Ownership and other metadata follow the fresh
        file — changing them would need privileges compact does not assume.

        The swap is POSIX-first (#85): on Windows a rename over a file this
        process holds open is refused, and compact raises
        :class:`WorkspaceError` naming that limitation rather than a bare
        :class:`PermissionError`. That wrapping is narrow — only
        :class:`PermissionError` is translated; any other :class:`OSError`
        from the rename propagates unchanged.

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
        Cleanup of stale artifacts from an earlier crash happens only
        *after* that exclusive lock is held, so a compact that loses the
        lock modifies nothing at all — including another process's
        in-flight temp file.

        Within this process the file lock cannot arbitrate, since
        same-process connections share one DuckDB instance; a module-level
        registry keyed by file identity does instead, so every spelling,
        symlink and hard link of one file coordinates as one. A
        :meth:`write` or rw-mode :meth:`read` in
        flight on *any* :class:`Workspace` for this file raises
        :class:`WorkspaceError` here, a second concurrent :meth:`compact`
        is rejected the same way, and for compact's duration writers and
        rw-mode readers fail fast exactly as a second process does on the
        lock.

        Raises:
            WorkspaceModeError: In ro mode; reopen with
                ``Workspace(path, mode='rw')`` to compact.
            WorkspaceError: If a :meth:`write` or rw-mode :meth:`read` on
                this file is in flight in this process, if another
                :meth:`compact` is already running, if the exclusive lock
                cannot be taken (another process, or an ro-mode
                :class:`Workspace` on this file in this process), or if the
                swap raises :class:`PermissionError` — on Windows a rename
                over a file held open by this process is refused, a known
                POSIX-first limitation (#85). Every other :class:`OSError`
                from the swap propagates as itself.
        """
        self._require_open()
        if self._mode == "ro":
            raise WorkspaceModeError(
                f"workspace {self._path} is open read-only; reopen with "
                f"Workspace(path, mode='rw') to compact"
            )
        # Compact the resolved target, never the alias: placing the temp
        # beside a symlink and replacing the symlink would turn it into an
        # independent regular file and orphan the real one.
        target = Path(os.path.realpath(self._path))
        key = _file_key(target)
        _begin_compact(key, target)
        try:
            tmp = target.with_name(target.name + ".compacting")
            tmp_wal = tmp.with_name(tmp.name + ".wal")
            # Hold the source's exclusive lock through both the copy and
            # the swap: a writer in another process either commits before
            # the lock is taken (and is copied) or cannot connect until the
            # swap is done, so no commit can land between the snapshot and
            # os.replace and be silently discarded. Connect first, before
            # touching anything on disk, so a lock-conflicted compact
            # leaves even another process's in-flight temp file alone.
            try:
                con = _connect(str(target), read_only=False)
            except ImportError:
                raise
            except Exception as exc:
                raise WorkspaceError(
                    f"compact() needs sole access to {target} but could not take its "
                    f"exclusive lock (is another connection open, perhaps an ro-mode "
                    f"Workspace in this process?): {exc}"
                ) from exc
            try:
                try:
                    # Now that the lock is ours, any temp beside the source
                    # is debris from an earlier crash, never a live compact.
                    tmp.unlink(missing_ok=True)
                    tmp_wal.unlink(missing_ok=True)
                    row = con.execute("SELECT current_database()").fetchone()
                    assert row is not None
                    con.execute(f"ATTACH '{_quote_path(str(tmp))}' AS compact_dst")
                    con.execute(f"COPY FROM DATABASE {_quote_ident(str(row[0]))} TO compact_dst")
                    con.execute("DETACH compact_dst")
                    # The temp was created fresh under this process's umask,
                    # so it would otherwise silently widen the workspace's
                    # permissions across the swap. Ownership and the rest
                    # follow the new file: chown needs privileges.
                    os.chmod(tmp, stat.S_IMODE(os.stat(target).st_mode))
                    try:
                        os.replace(tmp, target)
                    except PermissionError as exc:
                        raise WorkspaceError(
                            f"compact() could not swap the rewritten file into place: {exc}; "
                            "on Windows this is a known limitation of the swap-under-lock "
                            "design (#85)"
                        ) from exc
                finally:
                    con.close()
            except BaseException:
                # Only artifacts this compact created: the connect above
                # succeeded, so nothing here belongs to another process.
                tmp.unlink(missing_ok=True)
                tmp_wal.unlink(missing_ok=True)
                raise
        finally:
            _end_compact(key)

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
