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
from collections.abc import Iterator, Sequence
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
from remora.workspace.errors import WorkspaceError, WorkspaceModeError
from remora.workspace.materialize import (
    MaterializeResult,
    TsharkRunner,
    detect_tshark_version,
    materialize_into,
)
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
        key = _acquire_write_slot_validated(self._path)
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
        key = _acquire_write_slot_validated(self._path)
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

    def add_annotation(
        self,
        scope: AnnotationScope,
        target_id: int,
        key: str,
        value: str | None = None,
        *,
        created_at: datetime | None = None,
    ) -> int:
        """Attach an annotation to a packet or stream in one transaction.

        Args:
            scope: ``"packet"`` (``target_id`` is a frame number) or
                ``"stream"`` (``target_id`` is a stream id).
            target_id: The frame number or stream id being annotated.
            key: Short label, e.g. ``"verdict"``. Must not be empty.
            value: Free-form body, or ``None`` for a bare tag.
            created_at: When the annotation was made; defaults to now.

        Returns:
            The new ``annotation_id``, taken from the ``meta.info``
            high-water mark :mod:`remora.workspace.annotations` documents:
            monotonic, and never reused.

        Raises:
            WorkspaceModeError: In ro mode.
            ValueError: If ``scope`` or ``key`` is invalid.
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
                con, scope, target_id, key, value, created_at=created_at
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
    ) -> int:
        """Remove every annotation matching the filters, in one transaction.

        Args:
            scope: Restrict to one scope.
            target_id: Restrict to one frame number / stream id.
            key: Restrict to one label.

        Returns:
            How many annotations were removed.

        Raises:
            WorkspaceModeError: In ro mode.
            ValueError: If no filter is given.
        """
        with self.write() as con:
            return _annotations.remove_annotations(con, scope=scope, target_id=target_id, key=key)

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
    ) -> tuple[AnnotationRecord, ...]:
        """List annotations, each flagged for orphanhood. Works in ro mode.

        Args:
            scope: Restrict to one scope.
            target_id: Restrict to one frame number / stream id.
            key: Restrict to one label.

        Returns:
            Matching annotations, ascending by ``annotation_id``.
        """
        with self.read() as con:
            return _annotations.list_annotations(con, scope=scope, target_id=target_id, key=key)

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
