"""Stream tshark's projected output into the workspace ``pkts`` table (#31).

This is M4's tracer bullet: capture on disk -> tshark ``-T fields`` ->
``main.pkts`` plus the ``meta.fields`` / ``meta.cache_keys`` catalog rows that
describe what landed. Everything it needs already exists — the column-name
policy (:mod:`remora.workspace.naming`), the ftype -> column type map and its
codecs (:mod:`remora.workspace.types`), the storage layout
(:mod:`remora.workspace.schema`), the cache key (:mod:`remora.workspace.cachekey`)
— so this module composes them and owns no policy of its own.

Connection ownership
--------------------
The connection is supplied by the caller, never opened here: connection, lock
and transaction ownership belongs to ``Workspace`` (#28). :func:`materialize_into`
is one transaction's worth of work, so a caller runs it inside
``Workspace.write()`` and gets commit-on-success / rollback-on-failure for free
— including the ``ALTER`` that adds each projected column, which DuckDB rolls
back with the rest.

Why the filter must be fully pushable
-------------------------------------
An ``Expr`` filter is compiled to a ``-Y`` display filter and refused with
:class:`~remora.compile.dfilter.UnsupportedExprError` when it cannot be. Unlike
the streaming planner (:mod:`remora.planner`), there is no residual-predicate
fallback here, and that is a correctness requirement rather than a missing
feature: the cache key records the dfilter, and #32 decides hit/miss from it. A
filter that were half pushed down and half applied in Python would key the
stored table as if the ``-Y`` alone had produced it, and a later query with a
different residual would silently reuse the wrong rows.

Why ``frame.time_epoch`` feeds ``frame_time``
---------------------------------------------
The ``pkts`` skeleton's row key is ``frame_number`` / ``frame_time``. tshark's
``frame.time`` renders a human-readable, locale- and timezone-shaped string;
``frame.time_epoch`` is the epoch-seconds form
:func:`remora.values.convert` parses for ``FT_ABSOLUTE_TIME``. So the
projection always asks for ``frame.time_epoch`` and stores it in ``frame_time``,
and a caller *requesting* ``frame.time`` or ``frame.number`` gets no extra
column — the row key already holds that data.

Why batches bind plain values, never Arrow
------------------------------------------
Rows are encoded through :meth:`~remora.workspace.types.ColumnSpec.encode_raw`
and appended with ``executemany`` in bounded batches: memory stays flat on a
capture of any size, and the input is consumed lazily, one batch at a time.
Arrow record batches would be the obvious faster path and are deliberately not
taken — :mod:`remora.workspace.types` documents the hazard: DuckDB exports
``UHUGEINT`` through Arrow as ``decimal128(38, 0)`` read as *signed*, so every
``FT_IPv6`` address with the high bit set (all link-local and multicast
traffic) would arrive two's-complement negative. The DuckDB-native bind path is
exact.

Reuse: hit, backfill, or refuse (#32)
-------------------------------------
A workspace records exactly one materialization — one row in
``meta.cache_keys``, describing what ``pkts`` currently *is*. A second
:func:`materialize_into` call against it is decided against that row, never
blindly re-run:

* **hit** — the requested field set is a subset of the materialized one and
  every other component is identical. Nothing is scanned and nothing is
  written; the stored rows already answer the request. An exact repeat is the
  special case where the subset is the whole set.
* **backfill** — the components match but the request asks for fields the
  workspace does not hold. Only the new ones are scanned (tshark has to
  dissect the capture again — that cost is unavoidable), their columns are
  added, and the existing columns are left exactly as they were.
* **refuse** — any other component differs. See below.

The decision compares *components*, not digests. The stored key's digest covers
the full field set that was asked for, so two requests differing only in their
projection have different digests and comparing those would report every
widening as a mismatch. What is compared is: the capture's fingerprint, the
display filter (``None`` and ``""`` distinct, as #27 digests them), the tshark
version, and the argv **modulo the parts other components already own** —
``-e`` (owned by the field set), ``-r`` (owned by the fingerprint, which
identifies a capture by its bytes, so the same capture under a new path is the
same capture) and ``-Y`` (owned by the dfilter). What is left is argv[0] and
every option that changes how bytes are dissected — ``-X lua_script:``, ``-d``,
``-o`` — which is exactly the omission that makes a cache silently wrong. The
subset test itself is a ``list_has_all`` predicate in SQL
(:func:`~remora.workspace.schema.find_covering_cache_key`), which is why #27
canonicalizes the stored field set and #25 stores it as a native ``VARCHAR[]``.

A mismatch **refuses** with
:class:`~remora.workspace.errors.MaterializationMismatchError`, naming every
component that changed and telling the caller to materialize into a fresh
workspace file. Rematerializing in place under a policy is deliberately future
work: dropping rows a caller may already have annotated (#30) is not a decision
this function may take on its own. A workspace holding rows or registered
fields but *no* cache key is refused too — it was not written by this pipeline,
so nothing can be said about what its rows cover.

How a backfill writes
---------------------
The second scan projects ``frame.number`` plus the new fields and nothing else:
``frame.time_epoch`` is already stored, and re-projecting fields that already
have columns would rewrite data that is by definition unchanged. Rows are
matched on ``frame_number`` — the row key by convention (#25) — and each new
column is filled by ``UPDATE``, so no existing column is touched. Absent values
are encoded exactly as a fresh run encodes them (``NULL`` for a scalar, ``[]``
for a multi-value column, never ``NULL`` in a list column), which is what makes
a backfilled workspace indistinguishable from one materialized in a single run:
the recorded key is recomputed over the *union* field set with the argv that
single run would have used, so it is the same digest.

Because the fingerprint and the filter are unchanged, the scan must produce
the same *row-key set* ``pkts`` already holds — one row per stored frame
number, no more and no fewer. That is checked as a **set** comparison, not a
count: a scan emitting one frame twice and another not at all has the right
count while updating one row twice and leaving another at the ``NULL`` its
``ADD COLUMN`` back-filled. Each scanned row key is therefore staged in
DuckDB (:func:`~remora.workspace.schema.create_backfill_scan`, a session-
scoped ``TEMP`` table that never reaches the file) and compared against
``pkts`` in four directions — scanned rows with no frame number at all,
duplicates, scanned keys ``pkts`` does not hold, and stored rows the scan
never produced. Staging in the database rather than a Python set is what
keeps the check exact *and* the memory bounded on a capture of any size. Any
discrepancy refuses and the caller's transaction rolls the whole backfill
back.

What a backfill does *not* verify
---------------------------------
The check above establishes **row alignment**: that the rescan's row keys are
the ones already stored. It does not establish that the capture's bytes are
unchanged, and it deliberately cannot — value identity of the columns a
backfill does not rescan rests entirely on the #27 fingerprint, and that
fingerprint is a sample (``st_size``, ``st_mtime_ns``, sha256 of the first
and last 64 KiB), never a whole-file digest, because materializing a
multi-gigabyte capture must not be preceded by reading it twice.

So #27's named, pinned trade-off is inherited here with a sharper
consequence. An in-place edit to the middle of a large capture that preserves
size, mtime and both sampled blocks fingerprints identically
(``tests/test_workspace_cachekey.py::TestFingerprint::test_middle_change_does_not_flip``
pins exactly that); if it also preserves frame numbering, the row-key check
passes and the backfill commits the *new* fields' values read from the edited
capture beside the *old* columns read from the original — one row mixing two
capture contents, under a cache key that looks entirely valid. This is an
accepted cache-integrity limitation, not an oversight: closing it would mean
either a whole-file digest (the cost #27 explicitly refused) or re-projecting
columns that already exist (which is exactly what a backfill promises not to
do). ``tests/test_workspace_cache.py`` pins the consequence rather than
fixing it. Callers who need certainty against a mutated capture should
materialize into a fresh workspace file.

Integrity of the workspace being reused
--------------------------------------
Reuse is only as trustworthy as the file it reuses, so three things are
checked before any hit is served or any backfill delta is sized — all
refusals, never repairs, because which of two disagreeing states holds the
truth is exactly what cannot be determined from here.

1. **The two catalogs agree.** The subset rule reads ``meta.cache_keys``
   alone. It and ``meta.fields`` are written together in one transaction and
   must describe one workspace: every field a key claims has a registry row
   (bar the row-key-backed abbrevs, which get no column), and every registry
   row is claimed.
2. **The registry agrees with the table.** A ``meta.fields`` row is a
   *description* of ``main.pkts``, not evidence about it. Every registered
   column is checked to exist in the live catalog with the type it was
   registered under; otherwise a hit names a column that has been dropped —
   and the caller's next query fails with a raw binder error far from the
   cause — or one recreated with another type is read back through the wrong
   codec.
3. **A backfill's row keys are matchable.** ``pkts`` has no ``PRIMARY KEY``
   (#25), so ``frame_number``'s uniqueness is convention: a duplicate would
   make ``UPDATE ... WHERE frame_number = ?`` fan one scanned row's values
   out across several stored rows, and a ``NULL`` one would match nothing.
   Verified before a column is added or a row touched, and only on the
   backfill path — a hit writes nothing, so it cannot fan out.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, TypeAlias

from remora.compile.dfilter import compile_dfilter
from remora.expr import Expr
from remora.fields import FieldRef
from remora.reader.fields_reader import FieldsReader, escaping_is_reversible, fields_argv
from remora.reader.process import TsharkNotFoundError
from remora.workspace.cachekey import PcapFingerprint, fingerprint_pcap, make_cache_key
from remora.workspace.errors import (
    ColumnNameCollisionError,
    MaterializationMismatchError,
    WorkspaceError,
)
from remora.workspace.naming import SKELETON_ABBREVS, find_collisions
from remora.workspace.schema import (
    SKELETON_COLUMN_TYPES,
    CacheKeyRecord,
    FieldRecord,
    add_field_column,
    create_backfill_scan,
    delete_cache_key,
    find_covering_cache_key,
    find_duplicate_row_keys,
    read_cache_keys,
    read_fields,
    read_pkts_columns,
    record_cache_key,
    register_fields,
)
from remora.workspace.types import ColumnSpec, column_spec

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "MaterializeOutcome",
    "MaterializeResult",
    "TsharkRun",
    "TsharkRunner",
    "detect_tshark_version",
    "materialize_into",
]


class TsharkRun(Protocol):
    """A running tshark whose stdout lines can be iterated.

    The shape :class:`remora.reader.process.TsharkProcess` already has, named
    as a protocol so tests can inject a double and #32 can wrap the real thing
    without this module importing either.
    """

    def __enter__(self) -> Iterable[str]:
        """Start the run and yield its newline-stripped stdout lines."""
        ...

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Terminate and reap the run, whether or not the body raised."""
        ...


TsharkRunner: TypeAlias = Callable[[Sequence[str]], TsharkRun]
"""Build a :class:`TsharkRun` from an argv — the injection seam for tshark."""

#: argv options whose value another cache-key component already owns, and which
#: are therefore stripped before two argvs are compared: ``-e`` belongs to the
#: field set, ``-r`` to the capture fingerprint, ``-Y`` to the display filter.
_ARGV_OPTIONS_OWNED_ELSEWHERE: Final[frozenset[str]] = frozenset({"-e", "-r", "-Y"})


#: Wall-clock ceiling on the ``tshark --version`` probe. Generous, because it
#: only has to bound a hung binary: the probe can run while
#: ``Workspace.materialize`` holds the exclusive write lock, so a tshark that
#: never returns would otherwise lock the workspace file forever.
_VERSION_PROBE_TIMEOUT: Final[float] = 30.0

_FRAME_NUMBER_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.number",
    column_name="frame_number",
    ftype="FT_FRAMENUM",
    multi=False,
    # Deliberately not column_sql_type("FT_FRAMENUM") (UINTEGER): frame_number
    # is part of the pkts skeleton, so its type is whatever schema.py's layout
    # declares, not what the ftype map would pick for a projected column. Read
    # from that layout rather than restated, so the two cannot drift.
    sql_type=SKELETON_COLUMN_TYPES["frame_number"],
)
# frame.time renders human-readable; frame.time_epoch is the epoch-seconds
# form remora.values.convert parses for FT_ABSOLUTE_TIME, landing in the
# frame_time column.
_FRAME_TIME_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.time_epoch",
    column_name="frame_time",
    ftype="FT_ABSOLUTE_TIME",
    multi=False,
    sql_type=SKELETON_COLUMN_TYPES["frame_time"],
)

_FRAME_NUMBER_REF: Final[FieldRef[int]] = FieldRef("frame.number", "FT_FRAMENUM", False)
_FRAME_TIME_EPOCH_REF: Final[FieldRef[datetime]] = FieldRef(
    "frame.time_epoch", "FT_ABSOLUTE_TIME", False
)


def detect_tshark_version(tshark: str) -> str:
    """Read the version string of a tshark binary.

    The version is a cache-key component: the same capture dissected by two
    tshark releases can yield different fields, so a materialization records
    which one produced it.

    The probe is bounded by ``_VERSION_PROBE_TIMEOUT`` seconds, because
    ``Workspace.materialize`` calls it inside its write transaction: without a
    timeout a hung binary would hold the workspace's exclusive lock forever.

    Args:
        tshark: Path or name of the tshark executable.

    Returns:
        The ``X.Y.Z`` version string.

    Raises:
        TsharkNotFoundError: If the binary cannot be executed at all —
            missing, a directory, or not executable. All of those are the
            same problem for a caller (Remora was pointed at something that
            is not a runnable tshark), so all of them get the message that
            says how to fix it.
        subprocess.CalledProcessError: If tshark runs but exits non-zero.
        subprocess.TimeoutExpired: If it does not answer within
            ``_VERSION_PROBE_TIMEOUT`` seconds. Propagated as itself: a
            binary that cannot report its version within
            ``_VERSION_PROBE_TIMEOUT`` seconds is broken, not merely absent.
        ValueError: If its output carries no recognizable version.
    """
    # Imported here, not at module scope: remora.codegen is the code generator,
    # and importing remora.workspace must not drag it in for a version parse
    # that only a probe ever performs.
    from remora.codegen.fingerprint import parse_tshark_version

    try:
        output = subprocess.run(
            [tshark, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=_VERSION_PROBE_TIMEOUT,
        ).stdout
    except OSError as exc:
        raise TsharkNotFoundError(
            f"tshark binary not found or not runnable: {tshark!r} ({exc}). Install "
            "Wireshark (which provides tshark) or point Remora at an explicit "
            "tshark executable path."
        ) from exc
    return parse_tshark_version(output)


MaterializeOutcome: TypeAlias = Literal["materialized", "hit", "backfilled"]
"""What a :func:`materialize_into` call decided (see the module docs).

``"materialized"`` is a first materialization, ``"hit"`` is reuse with no
tshark run at all, ``"backfilled"`` is reuse plus a scan for the new fields
only.
"""


@dataclass(frozen=True)
class MaterializeResult:
    """What one :func:`materialize_into` call decided and wrote.

    Attributes:
        outcome: Whether the call materialized, hit the cache, or backfilled.
        row_count: Packet rows this call wrote — appended on a first
            materialization, updated on a backfill, ``0`` on a hit.
        batch_count: ``executemany`` batches those rows were written in.
        cache_key: The cache key the workspace now holds, and every component
            it covers. On a backfill it describes the *union* field set.
        dfilter: Display filter pushed to tshark, or ``None`` when unfiltered.
        fields: Registry entries for every materialized column in the
            workspace *after* this call, ascending by abbrev — so a request
            satisfied by the row-key skeleton is absent here, and a narrower
            request still reports the columns it did not ask for.
        added_fields: The subset of ``fields`` this call added. Empty on a hit.
    """

    outcome: MaterializeOutcome
    row_count: int
    batch_count: int
    cache_key: CacheKeyRecord
    dfilter: str | None
    fields: tuple[FieldRecord, ...]
    added_fields: tuple[FieldRecord, ...]


def _quote_identifier(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


def _argv_residue(argv: Sequence[str]) -> tuple[str, ...]:
    """Strip the argv parts other cache-key components own (module docs).

    Two materializations of one capture differ in their ``-e`` projection by
    construction, and may differ in how they spell ``-r``; the field set and
    the fingerprint compare those. What is left is argv[0] and every option
    that changes the dissection itself, which must match exactly.
    """
    residue: list[str] = []
    skip = False
    for argument in argv:
        if skip:
            skip = False
            continue
        if argument in _ARGV_OPTIONS_OWNED_ELSEWHERE:
            skip = True
            continue
        residue.append(argument)
    return tuple(residue)


def _build_argv(
    tshark: str,
    pcap: str | os.PathLike[str],
    dfilter: str | None,
    projection: Sequence[FieldRef[Any]],
) -> list[str]:
    """Build the effective tshark argv for one run."""
    argv = [tshark, "-r", os.fspath(pcap)]
    if dfilter is not None:
        argv += ["-Y", dfilter]
    return argv + fields_argv(projection)


def _full_projection(specs: Sequence[ColumnSpec]) -> tuple[FieldRef[Any], ...]:
    """The projection a single run materializing ``specs`` asks tshark for.

    Skeleton first, then the specs in the order given, deduplicated by abbrev
    so a caller who explicitly requests ``frame.time_epoch`` does not get it
    projected twice. Callers pass ``specs`` abbrev-sorted, which is what makes
    the argv — and therefore the cache key — of a backfilled workspace equal
    the argv of the one-shot run that would have produced the same columns.
    """
    projection: dict[str, FieldRef[Any]] = {
        _FRAME_NUMBER_REF.name: _FRAME_NUMBER_REF,
        _FRAME_TIME_EPOCH_REF.name: _FRAME_TIME_EPOCH_REF,
    }
    for spec in specs:
        projection.setdefault(spec.abbrev, FieldRef(spec.abbrev, spec.ftype, spec.multi))
    return tuple(projection.values())


def _sorted_specs(refs: Mapping[str, FieldRef[Any]]) -> list[ColumnSpec]:
    """Column specs for material field refs, abbrev-sorted (canonical order)."""
    return [column_spec(name, refs[name].ftype, refs[name].multi) for name in sorted(refs)]


def _spec_of(record: FieldRecord) -> ColumnSpec:
    """Rebuild the column spec of an already-materialized field."""
    return ColumnSpec(
        abbrev=record.abbrev,
        column_name=record.column_name,
        ftype=record.ftype,
        multi=record.multi,
        sql_type=record.column_type,
    )


def _refuse_unowned_workspace(con: DuckDBPyConnection) -> None:
    """Refuse a workspace holding packet data no cache key describes.

    Every run this pipeline performs records a key — including one that writes
    nothing else, since ``fields=()`` with a filter matching no packet leaves
    no rows and no registry entries. So rows or registered fields without a
    key mean the file was populated by something else, and nothing can be
    concluded about what those rows cover.
    """
    rows = con.execute("SELECT count(*) FROM main.pkts").fetchone()
    fields = con.execute("SELECT count(*) FROM meta.fields").fetchone()
    n_rows = 0 if rows is None else int(rows[0])
    n_fields = 0 if fields is None else int(fields[0])
    if n_rows or n_fields:
        raise WorkspaceError(
            f"workspace holds {n_rows} pkts rows and {n_fields} registered fields but "
            f"no cache key describing them, so it was not written by remora's "
            f"materialize pipeline and nothing about it can be reused; materialize "
            f"into a fresh workspace file"
        )


def _refuse_collisions(stored: Sequence[FieldRecord], refs: Mapping[str, FieldRef[Any]]) -> None:
    """Refuse when the union of stored and requested abbrevs shares a column.

    Checked over the union, not the request alone: the column-name policy is
    not injective, so a *new* abbrev can claim the column an earlier run's
    abbrev already owns, and that must be refused before a single column is
    added rather than discovered halfway through the ``ALTER``s.
    """
    collisions = find_collisions([record.abbrev for record in stored] + list(refs))
    if collisions:
        detail = "; ".join(
            f"{column} <- {', '.join(owners)}" for column, owners in sorted(collisions.items())
        )
        raise ColumnNameCollisionError(f"field set maps distinct abbrevs onto one column: {detail}")


def _render_component(value: object) -> str:
    """Render a mismatching component for the refusal message, bounded."""
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= 160 else text[:157] + "..."


def _refuse_mismatch(changed: Sequence[tuple[str, object, object]]) -> None:
    """Raise naming every cache-key component that changed."""
    detail = "; ".join(
        f"{component} (stored {_render_component(stored)}, "
        f"requested {_render_component(requested)})"
        for component, stored, requested in changed
    )
    raise MaterializationMismatchError(
        f"workspace already materializes a different request and cannot be reused — "
        f"changed: {detail}. Materialize into a fresh workspace file; rematerializing "
        f"in place under a policy is deliberately not done here, because it would "
        f"discard rows that may already carry annotations"
    )


def materialize_into(
    con: DuckDBPyConnection,
    *,
    pcap: str | os.PathLike[str],
    fields: Sequence[FieldRef[Any]] = (),
    # `filter` shadows the builtin deliberately, mirroring Capture.filter.
    filter: Expr | None = None,
    tshark: str,
    tshark_version: str,
    runner: TsharkRunner,
    batch_size: int = 1024,
    created_at: datetime | None = None,
) -> MaterializeResult:
    """Stream a capture's projected fields into ``main.pkts`` on ``con``.

    The whole call is one transaction's worth of work and opens no connection
    of its own — run it inside ``Workspace.write()``, which commits on success
    and rolls back every appended row and added column on failure.

    Args:
        con: A read-write connection to an open workspace, inside a
            transaction the caller owns.
        pcap: Capture file to read.
        fields: Field refs to project. Duplicates of one abbrev collapse;
            ``frame.number`` / ``frame.time`` need no column, since the ``pkts``
            row key already holds them.
        filter: Display-filter expression pushed to tshark as ``-Y``. It must
            be fully pushable — there is no Python-side residual here, because
            the cache key would not record one (see module docs).
        tshark: Path or name of the tshark executable, used as ``argv[0]``.
        tshark_version: Version of that binary, from
            :func:`detect_tshark_version`. Taken as a parameter rather than
            probed here so one detection can serve many materializations.
        runner: Builds the tshark run from the argv; the injection seam.
        batch_size: Rows per ``executemany``. Bounds memory, and the input is
            consumed lazily one batch at a time.
        created_at: Timestamp for the catalog rows; ``now`` in UTC when
            omitted.

    Reuse:
        A workspace that already holds a materialization is not re-run
        blindly. The stored cache key is compared **component by component**
        — capture fingerprint, display filter, tshark version, and the argv
        with the ``-e`` / ``-r`` / ``-Y`` parts those other components own
        stripped out — never digest against digest, because the digest covers
        the requested field set and would therefore call every widening a
        mismatch. When the components agree, the field set decides: a subset
        of what is materialized is a **hit** served without running tshark at
        all, and anything more is a **backfill** that scans the capture for
        the new fields only and leaves existing columns untouched — aligning
        the rescan to the stored rows by frame-number set, which is row
        alignment and not proof that the capture's bytes are unchanged (see
        the module docs on what a backfill does not verify). When any
        component disagrees the call is **refused**; see the module docs for
        why refusing beats rematerializing in place.

    Returns:
        What was decided and written — the outcome, row and batch counts, the
        cache key the workspace now holds, the pushed filter, every
        materialized field and the ones this call added.

    Raises:
        ValueError: If ``batch_size`` is below 1, if a capture path or argv
            element cannot be stored (see
            :func:`~remora.workspace.cachekey.make_cache_key`), or if a field
            declared scalar occurs more than once in one packet.
        ColumnNameCollisionError: If two distinct abbrevs — from the request,
            or one requested and one already materialized — claim one column.
        MaterializationMismatchError: If the workspace materializes a
            different capture, display filter, tshark version or tshark
            argument vector, or if a requested field is already materialized
            under a different ftype or multiplicity.
        WorkspaceError: If the workspace is not one this pipeline can reuse —
            packet rows or registered fields with no cache key describing them,
            more than one cache key, a stored key and ``meta.fields`` that
            disagree about which fields are materialized, a registered column
            missing from ``main.pkts`` or holding a different type than it was
            registered with, or (on the backfill path) ``pkts`` rows whose
            ``frame_number`` is duplicated or ``NULL``. Also if a requested
            field claims a ``pkts`` skeleton column name, or if a backfill
            scan's row keys are not the same set ``pkts`` already holds.
        UnsupportedExprError: If ``filter`` cannot be pushed to tshark.
        TsharkError: If the run exits non-zero — ``TsharkProcess`` raises
            :class:`remora.reader.process.TsharkError` at end of stream, so it
            surfaces from inside this call and the caller's transaction rolls
            back every row already appended.
        TsharkNotFoundError: If ``runner`` is the default
            :class:`~remora.reader.process.TsharkProcess` and the binary is
            missing. It converts ``FileNotFoundError`` alone, so every other
            spawn ``OSError`` — a path naming a directory arrives as
            ``IsADirectoryError`` — propagates as itself. This call never
            probes the binary, so the broader "not found or not runnable"
            conversion :func:`detect_tshark_version` performs does not apply
            here; ``Workspace.materialize`` documents both paths.
        OSError: If ``pcap`` cannot be read for its fingerprint, or from the
            ``runner``'s own spawn as described above.
    """
    if batch_size < 1:
        raise ValueError(f"batch_size must be at least 1, not {batch_size}")
    # Dedup requested refs by name, order-preserving (FieldRef is unhashable by design).
    requested: dict[str, FieldRef[Any]] = {}
    for ref in fields:
        requested.setdefault(ref.name, ref)
    # Skeleton-backed requests need no column; anything else claiming a
    # skeleton column name falls through to add_field_column's refusal.
    material_refs = {name: ref for name, ref in requested.items() if name not in SKELETON_ABBREVS}
    stored_fields = read_fields(con)
    stored_keys = read_cache_keys(con)
    _refuse_collisions(stored_fields, material_refs)
    dfilter = compile_dfilter(filter) if filter is not None else None
    if not stored_keys:
        _refuse_unowned_workspace(con)
        return _materialize_fresh(
            con,
            pcap=pcap,
            requested=requested,
            material_refs=material_refs,
            dfilter=dfilter,
            tshark=tshark,
            tshark_version=tshark_version,
            runner=runner,
            batch_size=batch_size,
            created_at=created_at,
        )
    if len(stored_keys) > 1:
        raise WorkspaceError(
            f"workspace holds {len(stored_keys)} cache keys, but records exactly one "
            f"materialization; its catalog was written by something other than "
            f"remora's materialize pipeline"
        )
    return _reuse_or_backfill(
        con,
        stored=stored_keys[0],
        stored_fields=stored_fields,
        pcap=pcap,
        requested=requested,
        material_refs=material_refs,
        dfilter=dfilter,
        tshark=tshark,
        tshark_version=tshark_version,
        runner=runner,
        batch_size=batch_size,
        created_at=created_at,
    )


def _materialize_fresh(
    con: DuckDBPyConnection,
    *,
    pcap: str | os.PathLike[str],
    requested: Mapping[str, FieldRef[Any]],
    material_refs: Mapping[str, FieldRef[Any]],
    dfilter: str | None,
    tshark: str,
    tshark_version: str,
    runner: TsharkRunner,
    batch_size: int,
    created_at: datetime | None,
) -> MaterializeResult:
    """Stream the whole capture into an empty workspace (the #31 pipeline)."""
    # This path binds straight into the skeleton columns, so it needs the same
    # assurance the reuse paths do that pkts is still pkts — an empty workspace
    # someone has altered would otherwise fail on the INSERT with a raw binder
    # error. No fields are registered yet, so only the skeleton is checked.
    _refuse_broken_pkts_schema(con, ())
    specs = _sorted_specs(material_refs)
    projection_refs = _full_projection(specs)
    argv = _build_argv(tshark, pcap, dfilter, projection_refs)
    # Computed before any mutation: validates storability and fingerprints the
    # capture, so a missing/unstorable input fails with nothing to roll back.
    record = make_cache_key(
        pcap=pcap,
        fields=tuple(requested),
        dfilter=dfilter,
        tshark_version=tshark_version,
        argv=argv,
        created_at=created_at,
    )
    for spec in specs:
        add_field_column(con, spec.column_name, spec.sql_type)
    insert_specs = [_FRAME_NUMBER_SPEC, _FRAME_TIME_SPEC, *specs]
    insert_sql = "INSERT INTO main.pkts ({}) VALUES ({})".format(
        ", ".join(_quote_identifier(spec.column_name) for spec in insert_specs),
        ", ".join("?" for _ in insert_specs),
    )
    row_count = 0
    batch_count = 0
    batch: list[list[Any]] = []
    # tshark only escapes -T fields values invertibly from 4.4 (see the
    # reader's module docstring); below that the text is stored as printed.
    unescape_values = escaping_is_reversible(tshark_version)
    with runner(argv) as lines:
        for row in FieldsReader(lines, projection_refs, unescape_values=unescape_values):
            batch.append([spec.encode_raw(row.get_raw(spec.abbrev)) for spec in insert_specs])
            if len(batch) >= batch_size:
                con.executemany(insert_sql, batch)
                row_count += len(batch)
                batch_count += 1
                batch = []
    if batch:
        con.executemany(insert_sql, batch)
        row_count += len(batch)
        batch_count += 1
    field_records = _field_records(specs, record.created_at)
    register_fields(con, field_records)
    record_cache_key(con, record)
    return MaterializeResult(
        outcome="materialized",
        row_count=row_count,
        batch_count=batch_count,
        cache_key=record,
        dfilter=dfilter,
        fields=field_records,
        added_fields=field_records,
    )


def _field_records(
    specs: Sequence[ColumnSpec], materialized_at: datetime
) -> tuple[FieldRecord, ...]:
    """Registry entries for freshly materialized columns."""
    return tuple(
        FieldRecord(
            abbrev=spec.abbrev,
            column_name=spec.column_name,
            ftype=spec.ftype,
            multi=spec.multi,
            column_type=spec.sql_type,
            materialized_at=materialized_at,
        )
        for spec in specs
    )


def _refuse_inconsistent_catalog(
    stored: CacheKeyRecord, stored_by_abbrev: Mapping[str, FieldRecord]
) -> None:
    """Refuse when the stored key and ``meta.fields`` describe different workspaces.

    The two are written together and must agree: every field a key claims has
    a registry row (bar the row-key-backed abbrevs, which deliberately get no
    column), and every registry row is claimed by the key. If they diverge the
    key is describing columns that are not there — and the subset rule, which
    reads the key alone, would answer a request for a field the workspace does
    not hold with a cache *hit*. That is silent wrong data, so it is refused
    loudly and **not** repaired: which of the two is the truth is exactly what
    cannot be known from here.
    """
    claimed = {field for field in stored.fields if field not in SKELETON_ABBREVS}
    registered = set(stored_by_abbrev)
    unregistered = sorted(claimed - registered)
    unclaimed = sorted(registered - claimed)
    if not unregistered and not unclaimed:
        return
    parts: list[str] = []
    if unregistered:
        parts.append(f"claimed by the cache key but absent from meta.fields: {unregistered}")
    if unclaimed:
        parts.append(f"registered in meta.fields but not claimed by the cache key: {unclaimed}")
    raise WorkspaceError(
        f"workspace catalog is inconsistent — {'; '.join(parts)}. The cache key and the "
        f"field registry are written together and must agree; reusing this workspace "
        f"would serve requests for columns it may not hold. Materialize into a fresh "
        f"workspace file"
    )


def _normalize_sql_type(sql_type: str) -> str:
    """Fold a SQL type string for comparison: case and internal spacing only.

    DuckDB reports back exactly the type string ``add_field_column`` was given
    for every type :mod:`remora.workspace.types` can produce — ``T[]`` list
    types included, which a test pins across the whole ftype table. This fold
    is therefore defensive rather than load-bearing: it keeps a
    hand-registered ``uinteger`` or ``DOUBLE  PRECISION`` from reading as a
    corrupt column.
    """
    return " ".join(sql_type.split()).upper()


def _refuse_broken_pkts_schema(
    con: DuckDBPyConnection, stored_fields: Sequence[FieldRecord]
) -> None:
    """Refuse when ``main.pkts`` is not physically the table it is described as.

    Two descriptions are checked against the one live catalog read:

    * the **skeleton** — ``frame_number`` and ``frame_time``, which every
      workspace is created with and which
      :data:`~remora.workspace.schema.SKELETON_COLUMN_TYPES` declares the types
      of. Nothing registers them in ``meta.fields``, so without this they were
      the one part of ``pkts`` no check covered: a dropped ``frame_time`` still
      answered a repeat request with a cache *hit*, and a dropped
      ``frame_number`` surfaced as a raw DuckDB catalog error from the middle
      of a backfill's row-key probe.
    * the **registry** — ``meta.fields`` is a description of ``main.pkts``, not
      evidence about it: a column dropped or recreated with another type
      outside this pipeline leaves it saying otherwise, so reuse would answer a
      request with a hit naming a column that is gone (the caller's next query
      then failing with a raw binder error, far from the cause) or silently
      read values back through the wrong codec.

    All of it is workspace corruption, refused and deliberately not repaired:
    re-deriving a column would mean rematerializing data this call promised
    only to read.
    """
    columns = read_pkts_columns(con)
    absent: list[str] = []
    retyped: list[str] = []
    for column, declared in SKELETON_COLUMN_TYPES.items():
        found = columns.get(column)
        if found is None:
            absent.append(f"{column} (pkts row key)")
        elif _normalize_sql_type(found) != _normalize_sql_type(declared):
            retyped.append(f"{column} (pkts row key) is {found}, the layout declares {declared}")
    for record in stored_fields:
        found = columns.get(record.column_name)
        if found is None:
            absent.append(f"{record.abbrev} -> {record.column_name}")
        elif _normalize_sql_type(found) != _normalize_sql_type(record.column_type):
            retyped.append(
                f"{record.abbrev} -> {record.column_name} is {found}, "
                f"registered as {record.column_type}"
            )
    if not absent and not retyped:
        return
    parts: list[str] = []
    if absent:
        parts.append(f"columns missing from pkts: {absent}")
    if retyped:
        parts.append(f"columns whose type changed: {retyped}")
    raise WorkspaceError(
        f"workspace is corrupt — {'; '.join(parts)}. main.pkts no longer matches what "
        f"the layout and meta.fields describe, so reusing this workspace would serve a "
        f"request from columns that are not there or no longer hold what they are "
        f"declared to hold. Materialize into a fresh workspace file"
    )


def _refuse_unusable_row_keys(con: DuckDBPyConnection) -> None:
    """Refuse a backfill over ``pkts`` rows that cannot be matched one to one.

    A backfill fills its new columns with ``UPDATE ... WHERE frame_number =
    ?``, which silently fans out across every row sharing a frame number and
    silently matches none for a ``NULL`` one. ``pkts`` has no ``PRIMARY KEY``
    to prevent either — DuckDB would back one with an ART index that taxes the
    bulk append path (#25) — so ``frame_number``'s uniqueness is a convention,
    and the convention is verified here rather than assumed. Checked *before*
    any column is added or any row updated, so a corrupt workspace is refused
    having been read and not written.

    The cost is one statement of two aggregate passes over a single ``BIGINT``
    column, paid once per backfill (never on a hit, which writes nothing and
    so cannot fan out). The examples it names are bounded.
    """
    null_keys, duplicates = find_duplicate_row_keys(con, limit=_DRIFT_EXAMPLES)
    if not null_keys and not duplicates:
        return
    parts: list[str] = []
    if duplicates:
        parts.append(f"frame numbers held by more than one row: {duplicates}")
    if null_keys:
        parts.append(f"rows with no frame number at all: {null_keys}")
    raise WorkspaceError(
        f"workspace is corrupt — {'; '.join(parts)}. pkts rows are matched by "
        f"frame_number, which is unique by convention rather than by constraint, so a "
        f"backfill cannot fill these rows one for one; nothing was written — "
        f"materialize into a fresh workspace file"
    )


def _refuse_redeclared_fields(
    stored_by_abbrev: Mapping[str, FieldRecord], material_refs: Mapping[str, FieldRef[Any]]
) -> None:
    """Refuse a field whose stored column disagrees with how it is now declared.

    A column's SQL type follows from the ftype and the multiplicity, so a
    request that redeclares either cannot read the stored column as it means
    to — and rewriting the column would rewrite data this call promises not to
    touch.
    """
    changed: list[tuple[str, object, object]] = []
    for name, ref in material_refs.items():
        record = stored_by_abbrev.get(name)
        if record is None:
            continue
        if record.ftype != ref.ftype or record.multi != ref.multi:
            changed.append(
                (
                    f"field {name}",
                    f"{record.ftype}{'[]' if record.multi else ''}",
                    f"{ref.ftype}{'[]' if ref.multi else ''}",
                )
            )
    if changed:
        _refuse_mismatch(changed)


def _reuse_or_backfill(
    con: DuckDBPyConnection,
    *,
    stored: CacheKeyRecord,
    stored_fields: Sequence[FieldRecord],
    pcap: str | os.PathLike[str],
    requested: Mapping[str, FieldRef[Any]],
    material_refs: Mapping[str, FieldRef[Any]],
    dfilter: str | None,
    tshark: str,
    tshark_version: str,
    runner: TsharkRunner,
    batch_size: int,
    created_at: datetime | None,
) -> MaterializeResult:
    """Decide hit / backfill / refuse against the workspace's stored key."""
    stored_by_abbrev = {record.abbrev: record for record in stored_fields}
    # Integrity first, and in this order: the two catalogs must agree with each
    # other, and the registry must agree with the physical table, before either
    # is trusted to answer a hit or to size a backfill delta.
    _refuse_inconsistent_catalog(stored, stored_by_abbrev)
    _refuse_broken_pkts_schema(con, stored_fields)
    _refuse_redeclared_fields(stored_by_abbrev, material_refs)
    fingerprint = fingerprint_pcap(pcap)
    rendered = fingerprint.render()
    # The union of what is stored and what is asked for, in the canonical
    # (abbrev-sorted) order — so its argv is the argv the equivalent one-shot
    # run would have used, which is both what gets compared and what gets
    # recorded.
    union_specs = _union_specs(stored_fields, material_refs)
    union_argv = _build_argv(tshark, pcap, dfilter, _full_projection(union_specs))
    changed: list[tuple[str, object, object]] = []
    if rendered != stored.pcap_fingerprint:
        changed.append(("capture fingerprint", stored.pcap_fingerprint, rendered))
    if dfilter != stored.dfilter:
        changed.append(("display filter", stored.dfilter, dfilter))
    if tshark_version != stored.tshark_version:
        changed.append(("tshark version", stored.tshark_version, tshark_version))
    stored_residue = _argv_residue(stored.argv)
    request_residue = _argv_residue(union_argv)
    if request_residue != stored_residue:
        changed.append(("tshark arguments", stored_residue, request_residue))
    if changed:
        _refuse_mismatch(changed)
    covering = find_covering_cache_key(
        con,
        pcap_fingerprint=rendered,
        dfilter=dfilter,
        tshark_version=tshark_version,
        fields=tuple(requested),
    )
    if covering is not None:
        return MaterializeResult(
            outcome="hit",
            row_count=0,
            batch_count=0,
            cache_key=covering,
            dfilter=dfilter,
            fields=tuple(stored_fields),
            added_fields=(),
        )
    return _backfill(
        con,
        stored=stored,
        stored_fields=stored_fields,
        stored_by_abbrev=stored_by_abbrev,
        pcap=pcap,
        fingerprint=fingerprint,
        requested=requested,
        union_specs=union_specs,
        union_argv=union_argv,
        dfilter=dfilter,
        tshark=tshark,
        tshark_version=tshark_version,
        runner=runner,
        batch_size=batch_size,
        created_at=created_at,
    )


def _union_specs(
    stored_fields: Sequence[FieldRecord], material_refs: Mapping[str, FieldRef[Any]]
) -> list[ColumnSpec]:
    """Column specs for every field the workspace will hold, abbrev-sorted."""
    specs = {record.abbrev: _spec_of(record) for record in stored_fields}
    for spec in _sorted_specs(material_refs):
        specs.setdefault(spec.abbrev, spec)
    return [specs[abbrev] for abbrev in sorted(specs)]


def _backfill(
    con: DuckDBPyConnection,
    *,
    stored: CacheKeyRecord,
    stored_fields: Sequence[FieldRecord],
    stored_by_abbrev: Mapping[str, FieldRecord],
    pcap: str | os.PathLike[str],
    fingerprint: PcapFingerprint,
    requested: Mapping[str, FieldRef[Any]],
    union_specs: Sequence[ColumnSpec],
    union_argv: Sequence[str],
    dfilter: str | None,
    tshark: str,
    tshark_version: str,
    runner: TsharkRunner,
    batch_size: int,
    created_at: datetime | None,
) -> MaterializeResult:
    """Add the requested fields' columns without rewriting the stored ones.

    The rescan is aligned to the stored rows by frame number, verified as an
    exact set match (:func:`_refuse_scan_drift`). That is **row alignment**
    only: it says the rescan covered the rows already stored, one for one, not
    that the capture still holds the bytes those rows were read from. Value
    identity of the untouched columns rests on the #27 fingerprint's sample,
    whose blind spot the module docs spell out under "What a backfill does not
    verify".
    """
    new_specs = [spec for spec in union_specs if spec.abbrev not in stored_by_abbrev]
    # The recorded key describes the union, under the argv a single run would
    # have used: a workspace built incrementally is then indistinguishable
    # from one built in one go, key included — which is also why the
    # fingerprint's blind spot is inherited rather than narrowed, since the
    # key cannot record what the sample did not see.
    record = make_cache_key(
        pcap=pcap,
        fields=tuple(set(stored.fields) | set(requested)),
        dfilter=dfilter,
        tshark_version=tshark_version,
        argv=union_argv,
        fingerprint=fingerprint,
        created_at=created_at,
    )
    if not new_specs:
        # Only row-key-backed abbrevs were added, so there is nothing to scan;
        # the key is widened all the same, so the next identical request is a
        # plain hit rather than this decision over again.
        delete_cache_key(con, stored.key)
        record_cache_key(con, record)
        return MaterializeResult(
            outcome="hit",
            row_count=0,
            batch_count=0,
            cache_key=record,
            dfilter=dfilter,
            fields=tuple(stored_fields),
            added_fields=(),
        )
    # Before a single column is added or a single row touched: the rows this
    # backfill is about to match one for one must actually be matchable.
    _refuse_unusable_row_keys(con)
    projection_refs = (
        _FRAME_NUMBER_REF,
        *(FieldRef(spec.abbrev, spec.ftype, spec.multi) for spec in new_specs),
    )
    argv = _build_argv(tshark, pcap, dfilter, projection_refs)
    for spec in new_specs:
        add_field_column(con, spec.column_name, spec.sql_type)
    update_sql = "UPDATE main.pkts SET {} WHERE frame_number = ?".format(
        ", ".join(f"{_quote_identifier(spec.column_name)} = ?" for spec in new_specs)
    )
    # Every scanned row key is staged alongside the UPDATE so the scan's frame
    # numbers can be compared against pkts' as *sets* once the scan is done —
    # a count alone admits a scan that repeats one frame and skips another.
    # Staging lives in DuckDB rather than a Python set, so a multi-million-row
    # capture costs bounded memory here (see schema.create_backfill_scan).
    scan_table = create_backfill_scan(con)
    stage_sql = f"INSERT INTO {scan_table} (frame_number) VALUES (?)"
    row_count = 0
    batch_count = 0
    batch: list[list[Any]] = []
    unescape_values = escaping_is_reversible(tshark_version)
    with runner(argv) as lines:
        for row in FieldsReader(lines, projection_refs, unescape_values=unescape_values):
            values = [spec.encode_raw(row.get_raw(spec.abbrev)) for spec in new_specs]
            values.append(_FRAME_NUMBER_SPEC.encode_raw(row.get_raw(_FRAME_NUMBER_REF.name)))
            batch.append(values)
            if len(batch) >= batch_size:
                _apply_backfill_batch(con, update_sql, stage_sql, batch)
                row_count += len(batch)
                batch_count += 1
                batch = []
    if batch:
        _apply_backfill_batch(con, update_sql, stage_sql, batch)
        row_count += len(batch)
        batch_count += 1
    _refuse_scan_drift(con, scan_table)
    new_records = _field_records(new_specs, record.created_at)
    register_fields(con, new_records)
    delete_cache_key(con, stored.key)
    record_cache_key(con, record)
    return MaterializeResult(
        outcome="backfilled",
        row_count=row_count,
        batch_count=batch_count,
        cache_key=record,
        dfilter=dfilter,
        fields=tuple(sorted((*stored_fields, *new_records), key=lambda item: item.abbrev)),
        added_fields=new_records,
    )


def _apply_backfill_batch(
    con: DuckDBPyConnection, update_sql: str, stage_sql: str, batch: Sequence[Sequence[Any]]
) -> None:
    """Apply one batch's updates and stage its row keys for validation.

    Two ``executemany`` calls over the same batch: the ``UPDATE`` that fills
    the new columns, matching on ``frame_number``, and the ``INSERT`` that
    records that row key so :func:`_refuse_scan_drift` can compare the scan's
    keys against ``pkts``'s as sets afterwards. The staged keys establish
    which rows were covered — not that the capture's bytes are unchanged,
    which the #27 fingerprint alone speaks to (module docs).
    """
    con.executemany(update_sql, [list(values) for values in batch])
    con.executemany(stage_sql, [[values[-1]] for values in batch])


#: How many offending frame numbers a drift refusal names. Enough to diagnose,
#: bounded so a wholly mismatched scan cannot build a megabyte-long message.
_DRIFT_EXAMPLES: Final[int] = 5


def _drift_examples(con: DuckDBPyConnection, sql: str) -> list[int]:
    """Run one bounded diagnostic query and return its frame numbers.

    ``NULL`` row keys are dropped rather than coerced: they are counted and
    reported separately by :func:`_refuse_scan_drift`, and an ``int(None)``
    here would replace a bounded, diagnosable refusal with a bare
    ``TypeError`` from inside the error path itself.
    """
    return [int(row[0]) for row in con.execute(sql).fetchall() if row[0] is not None]


def _refuse_scan_drift(con: DuckDBPyConnection, scan_table: str) -> None:
    """Refuse a backfill scan whose row keys are not exactly ``pkts``'s.

    Same fingerprint, same display filter, same tshark: the scan must select
    the same *row-key set* the first run did, one row per frame number, so
    every ``UPDATE`` matches exactly one stored row and every stored row is
    matched. Comparing *counts* alone is not enough — a scan that emits one
    frame twice and another not at all has the right count while updating one
    row twice and leaving another at the ``NULL`` its ``ADD COLUMN``
    back-filled — so the row keys are compared as sets, in SQL, in four
    directions: scanned rows carrying no frame number at all, duplicates
    within the scan, scanned keys absent from ``pkts``, and stored rows the
    scan never produced.

    What this establishes is **row alignment**, not that the capture's bytes
    are unchanged: value identity of the columns this backfill does not
    rescan rests on the #27 fingerprint, whose sampling blind spot is
    inherited here (see the module docs).

    Args:
        con: The connection the backfill is running on.
        scan_table: Staging table holding one row per scanned frame number.

    Raises:
        WorkspaceError: If the scan's row keys are not exactly ``pkts``'s,
            naming each kind of discrepancy with up to
            :data:`_DRIFT_EXAMPLES` frame numbers.
    """
    null_row = con.execute(
        f"SELECT count(*) FROM {scan_table} WHERE frame_number IS NULL"
    ).fetchone()
    null_keys = 0 if null_row is None else int(null_row[0])
    # NULL keys are excluded from the other three probes and reported on their
    # own: SQL equality never matches NULL, so they would otherwise masquerade
    # as "keys pkts does not hold" (and two of them as a duplicate of each
    # other), naming the symptom instead of the cause.
    duplicated = _drift_examples(
        con,
        f"SELECT frame_number FROM {scan_table} WHERE frame_number IS NOT NULL "
        f"GROUP BY frame_number HAVING count(*) > 1 "
        f"ORDER BY frame_number LIMIT {_DRIFT_EXAMPLES}",
    )
    unmatched = _drift_examples(
        con,
        f"SELECT s.frame_number FROM {scan_table} s ANTI JOIN main.pkts p "
        f"ON s.frame_number = p.frame_number WHERE s.frame_number IS NOT NULL "
        f"ORDER BY s.frame_number LIMIT {_DRIFT_EXAMPLES}",
    )
    missing = _drift_examples(
        con,
        f"SELECT p.frame_number FROM main.pkts p ANTI JOIN {scan_table} s "
        f"ON s.frame_number = p.frame_number ORDER BY p.frame_number LIMIT {_DRIFT_EXAMPLES}",
    )
    if not null_keys and not duplicated and not unmatched and not missing:
        return
    parts: list[str] = []
    if null_keys:
        parts.append(f"scanned rows carrying no frame number at all: {null_keys}")
    if duplicated:
        parts.append(f"frame numbers the scan produced more than once: {duplicated}")
    if unmatched:
        parts.append(f"frame numbers the scan produced that pkts does not hold: {unmatched}")
    if missing:
        parts.append(f"pkts rows the scan never produced: {missing}")
    raise WorkspaceError(
        f"backfill scan does not match the stored rows — {'; '.join(parts)} (up to "
        f"{_DRIFT_EXAMPLES} shown each). The capture no longer dissects to the rows "
        f"this workspace stores even though its fingerprint is unchanged; nothing was "
        f"written — materialize into a fresh workspace file"
    )
