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

Identity keys move under compaction, which is the one thing the registry
has to survive: ``compact`` swaps a new inode into the path, so its flag
is held under **both** the old and the new identity — claimed the moment
the temp is final and released only after the source connection is
closed — and every writer re-stats the file after taking its slot,
retrying if the identity moved in between. Neither side of the swap has
a window: a writer that stats before it and one that stats after it both
land on a key the compact is holding. The claim itself is validated the
same way: another *process's* compact can swap the inode between the
stat and this compact's connect, so the identity is re-checked once the
source's exclusive lock is held — under which no swap can happen — and
the claim retried against the new file on a mismatch.
"""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Literal

from remora.capture import _resolve_tshark
from remora.expr import Expr
from remora.fields import FieldRef
from remora.reader.process import TsharkProcess
from remora.workspace import annotations as _annotations
from remora.workspace.annotations import AnnotationRecord, AnnotationScope
from remora.workspace.attach import (
    Attachment,
    apply_attachments,
    attach_database,
    detach_database,
    validate_alias,
)
from remora.workspace.errors import (
    SchemaVersionError,
    WorkspaceAliasError,
    WorkspaceError,
    WorkspaceModeError,
)
from remora.workspace.export import export_parquet as _export_parquet
from remora.workspace.materialize import (
    MaterializeResult,
    TsharkRunner,
    detect_tshark_version,
    materialize_into,
)
from remora.workspace.query import Query
from remora.workspace.schema import check_compatible, create_schema
from remora.workspace.streams import StreamsResult, build_streams

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
    reached through any path — and is safe because ``compact()`` flags the
    new identity too, from the moment the temp is final. A stat is a
    snapshot either way, so callers pair it with a re-stat once their slot
    is held (:func:`_acquire_write_slot_validated`). Falls back to the
    resolved pathname when the file cannot be stat'ed, so acquisition never
    masks the real error the connect attempt is about to raise.
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


def _acquire_write_slot_validated(path: Path) -> _FileKey:
    """Acquire a write slot whose key provably matches the live file.

    A compact() can swap the inode between the stat and the acquire, leaving
    the slot keyed to a dead file. Re-statting after the acquire closes that
    window: once the slot is held, no compact can begin under this key, so a
    matching re-stat proves the key is the live file's identity; on a
    mismatch the slot is released and the acquire retried against the new
    file.
    """
    while True:
        key = _file_key(path)
        _acquire_write_slot(key, path)
        if _file_key(path) == key:
            return key
        _release_write_slot(key)


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
        # Alias -> attachment, in the order attached. Replayed onto every
        # connection this workspace opens, because a DuckDB ATTACH lives on the
        # database instance and rw mode holds no connection between operations.
        self._attachments: dict[str, Attachment] = {}

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
        """Close the workspace, dropping any recorded attachments. Idempotent.

        Attachments are per-``Workspace`` state, so closing forgets them: the
        shared read lock each one held on its peer file is released, and
        reopening this workspace starts with nothing attached.
        """
        if self._con is not None:
            self._con.close()
            self._con = None
        self._attachments.clear()
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

        Every connection carries this workspace's :attr:`attachments`: the
        rw-mode connection has them replayed onto it as it opens, and the
        ro-mode held connection is the one they were attached on.

        Raises:
            WorkspaceError: In rw mode, if a :meth:`compact` on this file is
                in progress anywhere in this process — mirroring the
                fail-fast lock error a second process gets.
            WorkspaceAliasError: If an alias this workspace recorded is
                already attached to a different file, or writable, on the
                connection's database instance.
        """
        self._require_open()
        if self._mode == "ro":
            assert self._con is not None
            yield self._con
            return
        key = _acquire_write_slot_validated(self._path)
        try:
            con = _connect(str(self._path), read_only=False)
            try:
                apply_attachments(con, self._attachments.values())
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

        This workspace's :attr:`attachments` are replayed onto the connection
        before the transaction opens, so the write body can read across them —
        read-only, as always. They stay attached even if the transaction rolls
        back, which is why the replay happens outside it.

        Raises:
            WorkspaceModeError: In ro mode; reopen with
                ``Workspace(path, mode='rw')`` to write.
            WorkspaceError: If a :meth:`compact` on this file is in progress
                anywhere in this process — mirroring the fail-fast lock
                error a second process gets.
            WorkspaceAliasError: If an alias this workspace recorded is
                already attached to a different file, or writable, on the
                connection's database instance.
        """
        self._require_open()
        if self._mode == "ro":
            raise WorkspaceModeError(
                f"workspace {self._path} is open read-only; reopen with "
                f"Workspace(path, mode='rw') to write"
            )
        key = _acquire_write_slot_validated(self._path)
        try:
            con = _connect(str(self._path), read_only=False)
            try:
                # Before BEGIN: a ROLLBACK undoes an ATTACH issued inside the
                # transaction, so replaying there would lose the attachments
                # exactly when an exception makes a caller want them least.
                apply_attachments(con, self._attachments.values())
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

    def add_annotation(
        self,
        scope: AnnotationScope,
        target_id: int,
        key: str,
        value: str | None = None,
        *,
        protocol: str | None = None,
        created_at: datetime | None = None,
    ) -> int:
        """Attach an annotation to a packet or stream in one transaction.

        A stream annotation names its target by ``(protocol, target_id)``, the
        pair ``streams`` is keyed by; see
        :mod:`remora.workspace.annotations`.

        Args:
            scope: ``"packet"`` (``target_id`` is a frame number) or
                ``"stream"`` (``target_id`` is a stream id).
            target_id: The frame number or stream id being annotated.
            key: Short label, e.g. ``"verdict"``. Must not be empty.
            value: Free-form body, or ``None`` for a bare tag.
            protocol: Required for ``scope="stream"`` (``"tcp"``/``"udp"``),
                refused for ``scope="packet"``.
            created_at: When the annotation was made; defaults to now.

        Returns:
            The new ``annotation_id``, taken from the ``meta.info``
            high-water mark :mod:`remora.workspace.annotations` documents:
            monotonic, and never reused.

        Raises:
            WorkspaceModeError: In ro mode.
            ValueError: If ``scope``, ``key`` or ``protocol`` is invalid — a
                stream annotation without a legal protocol, or a packet
                annotation with one.
            WorkspaceError: If the workspace holds annotation rows but no
                ``next_annotation_id`` mark — the deleted-id history is
                unrecoverable, so no seed can honour the never-reused
                guarantee. The message names the manual escape;
                :mod:`remora.workspace.annotations` documents the policy.
                Nothing is modified.
            duckdb.Error: If another thread's :meth:`write` transaction is
                allocating an id at the same moment — ``TransactionException``
                when both advance an existing mark, ``ConstraintException``
                when both seed a missing one. The transaction rolls back
                whole, so no annotation is written and no id is shared;
                whether to retry is the caller's decision.
        """
        with self.write() as con:
            return _annotations.add_annotation(
                con, scope, target_id, key, value, protocol=protocol, created_at=created_at
            )

    def remove_annotation(self, annotation_id: int) -> bool:
        """Remove one annotation by id, in one transaction.

        Args:
            annotation_id: The id :meth:`add_annotation` returned.

        Returns:
            Whether a row was removed.

        Raises:
            WorkspaceModeError: In ro mode.
        """
        with self.write() as con:
            return _annotations.remove_annotation(con, annotation_id)

    def remove_annotations(
        self,
        *,
        scope: AnnotationScope | None = None,
        target_id: int | None = None,
        key: str | None = None,
        protocol: str | None = None,
    ) -> int:
        """Remove every annotation matching the filters, in one transaction.

        Args:
            scope: Restrict to one scope.
            target_id: Restrict to one frame number / stream id. A bare stream
                id matches the tcp and the udp conversation alike; pair it with
                ``protocol`` to mean one.
            key: Restrict to one label.
            protocol: Restrict to one stream protocol.

        Returns:
            How many annotations were removed.

        Raises:
            WorkspaceModeError: In ro mode.
            ValueError: If no filter is given.
        """
        with self.write() as con:
            return _annotations.remove_annotations(
                con, scope=scope, target_id=target_id, key=key, protocol=protocol
            )

    def delete_orphan_annotations(self) -> int:
        """Remove annotations whose target is gone, in one transaction.

        Orphans are kept and flagged until this is called explicitly; see
        :mod:`remora.workspace.annotations` for the policy.

        Returns:
            How many orphaned annotations were removed.

        Raises:
            WorkspaceModeError: In ro mode.
        """
        with self.write() as con:
            return _annotations.delete_orphan_annotations(con)

    def list_annotations(
        self,
        *,
        scope: AnnotationScope | None = None,
        target_id: int | None = None,
        key: str | None = None,
        protocol: str | None = None,
    ) -> tuple[AnnotationRecord, ...]:
        """List annotations, each flagged for orphanhood. Works in ro mode.

        Args:
            scope: Restrict to one scope.
            target_id: Restrict to one frame number / stream id. A bare stream
                id matches the tcp and the udp conversation alike; pair it with
                ``protocol`` to mean one.
            key: Restrict to one label.
            protocol: Restrict to one stream protocol.

        Returns:
            Matching annotations, ascending by ``annotation_id``.
        """
        with self.read() as con:
            return _annotations.list_annotations(
                con, scope=scope, target_id=target_id, key=key, protocol=protocol
            )

    def export_parquet(self, table: str, path: str | os.PathLike[str]) -> Path:
        """Write one workspace table to a Parquet file. Works in ro mode.

        Parquet is remora's *export* format, not its storage format: the live
        workspace stays DuckDB-native because it is mutable (annotations),
        and this is how a table leaves for delivery, archival or a downstream
        Spark/Athena load. The whole export is a single DuckDB ``COPY``
        statement, so a table of any size streams to disk without a row
        passing through Python.

        This is a read, so it runs through :meth:`read` and works in ro mode;
        it never opens a write connection.

        **The export is a derivative, not a replacement for the capture.** It
        holds the table's columns and nothing else: no packet payloads, no
        fields that were never projected into a column, and no ``meta``
        catalog. The pcap remains the source of truth, and a question about a
        field nobody materialized has to go back to it.

        The exported schema mirrors the stored one with **exactly two
        deliberate exceptions**, listed here because they are the whole of the
        divergence for any schema remora wrote: DuckDB's Parquet writer cannot
        represent these two types exactly, and shipping a silent corruption is
        worse than shipping a documented type change.

        * ``UHUGEINT`` (``FT_IPv6``) would be written as a ``double`` — 53
          bits of mantissa for a 128-bit address, so
          ``7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`` and ``8000::`` collide on
          one value. It is exported as **exact decimal text** instead, the same
          form :mod:`remora.workspace.types` already binds IPv6 with; read it
          back with ``IPv6Address(int(text))`` or ``CAST(col AS UHUGEINT)``.
        * ``INTERVAL`` (``FT_RELATIVE_TIME``) would be written at Parquet's
          millisecond interval resolution, truncating microseconds. It is
          exported as text (``'00:00:00.001234'``), which casts straight back
          with ``CAST(col AS INTERVAL)``.

        Both rewrites apply at list depth too, so ``UHUGEINT[]`` exports as
        ``list<string>``. Every other column type passes through unchanged —
        ``UINTEGER`` IPv4 columns stay unsigned ``uint32``, narrow ints keep
        their width, and a multi-value ``T[]`` column stays ``list<T>``.
        :mod:`remora.workspace.export` holds the full mapping.

        Args:
            table: ``"pkts"``, ``"streams"`` or ``"annotations"``. A table name
                cannot be a bound parameter, so the set is closed and anything
                else is refused.
            path: Destination file, replaced if it exists. It must not be this
                workspace's own file or its ``.wal`` sidecar — under any
                spelling, symlink or hard link — since that would destroy the
                workspace. The export is written inside a private ``0700``
                directory beside the destination and renamed into place, so the
                replacement is atomic and a failed export leaves the previous
                file untouched. What that leaves: the destination's directory
                is trusted, and another process moving the database itself onto
                this path mid-export is not defended against — neither is
                something a writer can guard.
                :mod:`remora.workspace.export` states both boundaries.

        Returns:
            The path written.

        Raises:
            ValueError: If ``table`` is not one of the three exportable tables.
            WorkspaceError: If ``path`` is this workspace's database file or its
                write-ahead log (refused before anything is written), if the
                workspace is not open, or — in rw mode — if a :meth:`compact` on
                this file is in progress in this process.
            OSError: If the destination's directory cannot hold the temporary
                directory, or the rename into place fails.
        """
        with self.read() as con:
            return _export_parquet(con, table, path)

    def materialize(
        self,
        pcap: str | os.PathLike[str],
        fields: Sequence[FieldRef[Any]] = (),
        # `filter` shadows the builtin deliberately, mirroring Capture.filter.
        filter: Expr | None = None,
        *,
        tshark: str | None = None,
        tshark_version: str | None = None,
        batch_size: int = 1024,
        runner: TsharkRunner | None = None,
    ) -> MaterializeResult:
        """Stream a capture's projected fields into ``pkts`` in one transaction.

        Writes are rw-only, and the whole run — spawning tshark, reading its
        output, appending every batch — happens inside a single
        :meth:`write` transaction. So the exclusive write lock is held for
        as long as tshark takes on this capture, and is released when this
        method returns *or* raises: a failure rolls back every appended row
        and every column the projection added, leaving the workspace exactly
        as it was.

        ``filter`` must be fully pushable to a tshark display filter. There
        is no Python-side residual here, unlike :class:`remora.Capture`, and
        that is a correctness requirement: the cache key records the
        dfilter, so rows produced by a half-pushed filter would be stored as
        if the ``-Y`` alone had selected them, and a later query with a
        different residual would silently reuse them.

        A workspace that already holds a materialization is *reused* rather
        than re-run: a request whose fields are a subset of what is stored is
        a cache hit that spawns no dissecting tshark at all, a request adding
        fields backfills just those columns, and a request that changes the
        capture, the filter, the tshark version or its arguments is refused
        with :class:`~remora.workspace.errors.MaterializationMismatchError`.

        A backfill aligns its rescan to the stored rows by matching frame
        numbers as a set, which establishes row alignment only. Whether the
        columns it does *not* rescan still hold values from the same capture
        contents rests on the #27 fingerprint, which is a sample rather than a
        whole-file digest: an in-place middle edit preserving size, mtime and
        the sampled blocks is invisible to it, so a backfill can in principle
        join new-field values from an edited capture to older columns read
        from the original. That is an accepted cache-integrity limitation
        inherited from #27 and documented in
        :mod:`remora.workspace.materialize`; materialize into a fresh
        workspace file when a capture may have been mutated in place.
        :func:`~remora.workspace.materialize.materialize_into` documents the
        comparison rule and why refusing beats rematerializing in place.

        A hit spawns no *dissecting* tshark, which is the cost reuse exists to
        avoid — but it still runs the ``tshark --version`` probe when
        ``tshark_version`` is omitted, and that is deliberate: the version is
        one of the components the decision compares, so it must be read from
        the live binary rather than assumed from the stored key. Reusing the
        recorded version instead would make every workspace hit forever across
        a tshark upgrade that changes how the capture dissects. Pass
        ``tshark_version`` explicitly to guarantee the call spawns no
        subprocess at all.

        Args:
            pcap: Capture file to read.
            fields: Field refs to project. Duplicates of one abbrev
                collapse; ``frame.number`` / ``frame.time`` need no column
                of their own, since the ``pkts`` row key already holds them.
            filter: Display-filter expression pushed to tshark as ``-Y``.
            tshark: tshark executable to run; defaults to ``$TSHARK`` and
                then to ``tshark`` on ``PATH``.
            tshark_version: Version of that binary, recorded as a cache-key
                component. Probed with :func:`detect_tshark_version` when
                omitted, which spawns ``tshark --version``; pass it to skip
                that.
            batch_size: Rows per ``executemany``, bounding memory on a
                capture of any size.
            runner: Builds the tshark run from the argv — the injection
                seam. Defaults to
                :class:`~remora.reader.process.TsharkProcess`.

        Returns:
            What was decided and written: the outcome, row and batch counts,
            the cache key the workspace now holds, the pushed filter, every
            materialized field and the ones this call added.

        Raises:
            WorkspaceModeError: In ro mode. Raised before anything is
                spawned or probed, so a read-only workspace has no
                subprocess side effects.
            WorkspaceError: If the workspace is not one this pipeline can
                reuse — packet data no cache key describes, a cache key and
                field registry that disagree, a registered column missing from
                ``pkts`` or retyped under it, or ``pkts`` rows whose
                ``frame_number`` is duplicated or ``NULL`` when a backfill
                needs to match on it. Also if a requested field claims a
                ``pkts`` skeleton column name, if a backfill scan's row keys
                are not exactly the stored ones, or if a :meth:`compact` on
                this file is in progress in this process.
            MaterializationMismatchError: If the workspace already
                materializes a different capture, filter, tshark version or
                tshark argument vector.
            ColumnNameCollisionError: If two distinct abbrevs map onto one
                column name.
            UnsupportedExprError: If ``filter`` cannot be pushed to tshark.
            TsharkNotFoundError: If the tshark binary cannot be run — but
                which failures reach you as this error depends on the path
                taken. When ``tshark_version`` is omitted the version probe
                runs first, and :func:`detect_tshark_version` converts *any*
                OS-level failure to execute the binary into this error:
                missing, not executable, or a path naming a directory. When
                ``tshark_version`` is supplied the probe is skipped, and only
                a *missing* binary is converted — that conversion happens at
                spawn time in
                :class:`~remora.reader.process.TsharkProcess`, which handles
                ``FileNotFoundError`` alone, so every other ``OSError`` (a
                directory path, arriving as ``IsADirectoryError``)
                propagates as itself. That asymmetry lives in the M1 reader
                and is stated here rather than papered over; unifying it is
                tracked as a follow-up.
            TsharkError: If the run exits non-zero
                (:class:`remora.reader.process.TsharkError`, raised at end of
                stream). The transaction rolls back, so a partial run leaves
                the workspace as it was.
            ValueError: If ``batch_size`` is below 1, if a capture path or
                argv element cannot be stored, or if a field declared
                scalar occurs more than once in one packet.
            OSError: If ``pcap`` cannot be read for its fingerprint.
        """
        # write() first, so ro mode is refused before a subprocess is spawned.
        with self.write() as con:
            resolved = _resolve_tshark(tshark)
            version = (
                tshark_version if tshark_version is not None else detect_tshark_version(resolved)
            )
            run: TsharkRunner = TsharkProcess if runner is None else runner
            return materialize_into(
                con,
                pcap=pcap,
                fields=fields,
                filter=filter,
                tshark=resolved,
                tshark_version=version,
                runner=run,
                batch_size=batch_size,
            )

    def query(self) -> Query:
        """Start a query over this workspace's materialized rows.

        The cache-side counterpart of :class:`remora.Capture`: the same ``Expr``
        trees, compiled to a DuckDB predicate instead of a display filter, over
        columns that were dissected once. The returned query is immutable and
        chainable (``ws.query().filter(TCP.port == 443).select(IP.src)``) and
        touches the database only when it is iterated, exported or rendered.

        Every execution goes through :meth:`read`, so this works in ro mode: a
        ``Query`` never enters the write API and never writes — no :meth:`write`
        call, no DDL, no DML. (In rw mode :meth:`read` still opens a
        read-write-*configured* connection, for the same-process reason
        documented there; what the query issues on it is ``SELECT`` either way.)
        A field the workspace holds no column for, or one whose declaration
        disagrees with the stored catalog, is refused by name before any
        generated SQL reaches DuckDB; see :mod:`remora.workspace.query`.

        Returns:
            A new :class:`~remora.workspace.query.Query` over this workspace.
        """
        return Query(self)

    def build_streams(self) -> StreamsResult:
        """Roll materialized packets up into ``streams`` in one transaction.

        Sessionization is the capability a display filter cannot express: a
        filter selects packets, this aggregates the conversations they belong
        to — per-stream endpoints, packet and byte counts, first/last frame
        and timestamp — so ``pkts`` can be joined back to the stream each row
        belongs to. :mod:`remora.workspace.streams` documents the record
        shape, the byte definition (``frame.len``, matching tshark's own
        conversation statistics) and the endpoint convention.

        The whole rebuild — delete plus one grouped insert per protocol — is
        a single :meth:`write` transaction, so the exclusive lock is held
        briefly and no reader ever sees the table empty. Rerunning it after a
        re-materialization replaces the rollups rather than duplicating them.

        Returns:
            How many streams were written, per protocol.

        Raises:
            WorkspaceModeError: In ro mode.
            MissingStreamFieldsError: If the fields sessionization reads were
                not materialized. Both protocols' fields are required, and
                the message names the exact abbrevs to add to
                :meth:`materialize`'s field set; nothing is modified.
            WorkspaceError: If a :meth:`compact` on this file is in progress
                in this process.
        """
        with self.write() as con:
            return build_streams(con)

    @property
    def attachments(self) -> Mapping[str, Path]:
        """Workspaces attached to this one, alias to file, in attach order."""
        return {alias: item.path for alias, item in self._attachments.items()}

    def attach(self, path: str | os.PathLike[str], alias: str) -> None:
        """Attach another workspace file read-only under ``alias``.

        Cross-capture correlation is why the workspace is DuckDB-native: an
        attached workspace's tables are reachable as ``alias.main.pkts`` and
        ``alias.meta.fields`` from raw SQL on the connection :meth:`read` hands
        out. Joining an attached ``pkts`` against this one is ordinary SQL::

            with ws.read() as con:
                con.execute(
                    'SELECT p.ip_src FROM main.pkts p '
                    'JOIN "peer".main.pkts q ON p.ip_src = q.ip_src'
                ).fetchall()

        **Read-only, in either mode.** The ATTACH always carries
        ``(READ_ONLY)``, so DuckDB refuses every write against an attached
        workspace whatever mode this one is open in. Cross-workspace writes are
        out of scope, and this is what makes them impossible rather than merely
        unattempted.

        Attachments are recorded on this workspace and replayed onto every
        connection it opens, because a DuckDB attachment belongs to the
        *database instance* rather than the connection and ``"rw"`` mode holds
        no connection between operations. :meth:`close` clears them.

        **What an attachment costs.** It takes a shared read lock on the
        attached file for as long as it stays attached: another process cannot
        write to it, and within this process it cannot be opened read-write at
        all — so ``Workspace(peer, mode="rw")`` operations on an attached file
        fail with DuckDB's ``Unique file handle conflict`` until it is detached.
        Opening it ``mode="ro"`` is unaffected, as is :meth:`compact` on *this*
        workspace, which replays no attachment and copies only its own database.

        Args:
            path: The workspace file to attach. Must exist, must be a workspace
                of this library's layout version, and must not be this
                workspace's own file (under any spelling — the comparison is by
                resolved path).
            alias: Database name to reach it by. A bare SQL identifier
                (``[A-Za-z_][A-Za-z0-9_]*``), not one of DuckDB's reserved
                names ``main``/``temp``/``system``, not already attached here,
                and not this workspace's own database name.

        Raises:
            WorkspaceAliasError: If the alias is invalid, reserved, already in
                use here, or names this workspace's own database.
            WorkspaceError: If the workspace is not open, if ``path`` does not
                exist or is this workspace's own file, or if DuckDB refuses the
                attach — a file that is not a DuckDB database, or one another
                process holds read-write.
            SchemaVersionError: If ``path`` is not a remora workspace, or its
                layout version is not this library's. Nothing is recorded and
                the alias is detached again, so a refused attach leaves no
                trace.
        """
        self._require_open()
        validate_alias(alias)
        if alias in self._attachments:
            raise WorkspaceAliasError(
                f"alias {alias!r} is already attached to "
                f"{self._attachments[alias].path}; detach it first or choose another"
            )
        resolved = Path(os.path.realpath(os.fspath(path)))
        if resolved == Path(os.path.realpath(self._path)):
            raise WorkspaceError(
                f"{path} is this workspace's own file; its tables are already "
                f"reachable as main.pkts"
            )
        if not resolved.exists():
            raise WorkspaceError(
                f"no workspace at {path} to attach as {alias!r}; create one by "
                f"opening it with Workspace(path, mode='rw')"
            )
        attachment = Attachment(alias=alias, path=resolved)
        with self.read() as con:
            row = con.execute("SELECT current_database()").fetchone()
            if row is not None and str(row[0]).lower() == alias.lower():
                raise WorkspaceAliasError(
                    f"alias {alias!r} is this workspace's own database name; choose another alias"
                )
            try:
                attach_database(con, attachment)
            except SchemaVersionError as exc:
                raise SchemaVersionError(f"cannot attach {path} as {alias!r}: {exc}") from exc
            except ImportError:
                raise
            except WorkspaceError:
                raise
            except Exception as exc:
                raise WorkspaceError(f"cannot attach {path} as {alias!r}: {exc}") from exc
        # Recorded only after the connection block, so a refused attach leaves
        # nothing behind for the next connection to replay.
        self._attachments[alias] = attachment

    def detach(self, alias: str) -> None:
        """Detach a workspace attached by :meth:`attach`.

        Args:
            alias: The alias to detach.

        Raises:
            WorkspaceAliasError: If nothing is attached under that alias.
            WorkspaceError: If the workspace is not open.
        """
        self._require_open()
        if alias not in self._attachments:
            attached = ", ".join(self._attachments) or "none"
            raise WorkspaceAliasError(
                f"no workspace is attached as {alias!r}; attached: {attached}"
            )
        del self._attachments[alias]
        with self.read() as con:
            detach_database(con, alias)

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
        diverge; coordination is unaffected (it follows file identity, and
        this compact holds the flag under both the pre- and post-swap
        identity, so writes are locked out through every alias for its
        whole duration), but a hardlinked alias goes on referring to the
        pre-compact file.

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
        well as writers — fail fast on that lock from the moment it is
        taken *through the atomic rename*, rather than losing data: a
        concurrent writer either commits before the lock is taken (and is
        copied) or cannot connect until the rename is done, so no commit
        can land between the snapshot and the rename and be silently
        discarded. The rename, not the return, is the cross-process
        linearization point: it installs a new inode the old file's lock
        does not cover, so another process may connect the instant it
        lands — safely, because such a write goes into the compacted file
        and survives; there is nothing left for compact to discard.
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
        symlink and hard link of one file coordinates as one — and the swap
        itself does not open a gap in that, because the flag is claimed
        under the temp's identity as soon as the temp is final and both
        identities stay flagged until *after* the source connection is
        closed. Writers on the far side of the swap therefore stat the new
        inode and still find the flag, and writers that stat before it
        re-validate their key once their slot is held, so neither can slip
        through and commit into a file :func:`os.replace` has already
        discarded (DuckDB's instance cache keys on the path, so an admitted
        writer would have joined the pre-swap instance). The flag's own
        claim is validated under the exclusive lock too: another process's
        compact can swap the inode between this compact's stat and its
        connect, so the identity is re-checked once the lock is held and
        the claim retried on a mismatch — the flag always covers the live
        file for as long as the source connection is open. A
        :meth:`write` or rw-mode :meth:`read` in
        flight on *any* :class:`Workspace` for this file raises
        :class:`WorkspaceError` here, a second concurrent :meth:`compact`
        is rejected the same way, and writers and rw-mode readers fail
        fast for compact's whole duration — through the rename and until
        the source connection is closed, deliberately a hair longer than
        other processes are held out, precisely because an admitted
        same-process writer would join the pre-swap instance where a
        fresh process opens the new file.

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
        #
        # The compacting flag guards a file *identity*, and only the file's
        # exclusive lock can pin that identity down: another process's
        # compact can swap a new inode into the path at any instant this
        # process does not hold the lock — after the stat, after the flag is
        # taken, right up to the connect — leaving the flag on a dead key
        # and the live inode unguarded for a same-process writer. So the
        # source connection is opened *inside* the loop (before touching
        # anything on disk, so a lock-conflicted compact leaves even another
        # process's in-flight temp file alone) and the resolution and
        # identity are re-checked while both the flag and the lock are held:
        # no swap can happen under the lock, so a match proves the flag
        # guards the very file the connection holds, and holds it for as
        # long as the connection stays open. On a mismatch the connection is
        # closed, the flag dropped, and the whole begin retried against the
        # new file.
        while True:
            target = Path(os.path.realpath(self._path))
            key = _file_key(target)
            _begin_compact(key, target)
            try:
                # Hold the source's exclusive lock through both the copy and
                # the swap: a writer in another process either commits
                # before the lock is taken (and is copied) or cannot connect
                # until the swap is done, so no commit can land between the
                # snapshot and os.replace and be silently discarded.
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
            except BaseException:
                _end_compact(key)
                raise
            if _file_key(target) == key and Path(os.path.realpath(self._path)) == target:
                break
            con.close()
            _end_compact(key)
        # Set once the temp is final, so the flag is also visible under the
        # identity the live file is about to have (see below).
        claimed_new_key: _FileKey | None = None
        try:
            tmp = target.with_name(target.name + ".compacting")
            tmp_wal = tmp.with_name(tmp.name + ".wal")
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
                    new_key = _file_key(tmp)
                    if new_key != key:
                        # The temp is private to this compact (fresh file, held
                        # exclusive lock on the source), so claiming its identity
                        # cannot conflict with a live operation; it makes the
                        # compacting flag visible to writers that stat the path
                        # after the swap but before this compact fully ends.
                        _begin_compact(new_key, target)
                        claimed_new_key = new_key
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
            # Both identities stay flagged until here, which is *after* the
            # inner finally closed the source connection: DuckDB's instance
            # cache keys on the path, so releasing earlier could admit a
            # writer that joins the pre-swap instance and commits into the
            # file os.replace has already thrown away.
            try:
                if claimed_new_key is not None:
                    _end_compact(claimed_new_key)
            finally:
                _end_compact(key)

    @staticmethod
    def _is_empty(con: DuckDBPyConnection) -> bool:
        """True when the current database holds no user objects at all.

        A foreign database is not necessarily betrayed by a table: a file
        holding only a view, sequence, macro, user type or schema is
        foreign all the same, and counting only ``duckdb_tables()`` would
        classify it as fresh and graft the remora schema onto it. So this
        counts every user-creatable catalog object; ``internal`` objects
        (the ``main`` schema itself, built-in functions and types) are
        DuckDB's own and present in a truly fresh file. Indexes need a
        table, so tables cover them. Every probe is pinned to
        ``current_database()`` like the catalog probes in
        :mod:`remora.workspace.schema`, so an attached database cannot
        make a fresh file look populated.
        """
        row = con.execute(
            """
            SELECT count(*) FROM (
                SELECT 1 FROM duckdb_tables() WHERE database_name = current_database()
                UNION ALL
                SELECT 1 FROM duckdb_views()
                    WHERE database_name = current_database() AND NOT internal
                UNION ALL
                SELECT 1 FROM duckdb_sequences() WHERE database_name = current_database()
                UNION ALL
                SELECT 1 FROM duckdb_schemas()
                    WHERE database_name = current_database() AND NOT internal
                UNION ALL
                SELECT 1 FROM duckdb_functions()
                    WHERE database_name = current_database() AND NOT internal
                UNION ALL
                SELECT 1 FROM duckdb_types()
                    WHERE database_name = current_database() AND NOT internal
            )
            """
        ).fetchone()
        return row is None or int(row[0]) == 0
