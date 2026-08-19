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

One materialization per workspace
---------------------------------
A workspace that already holds packet rows or registered fields is refused.
Appending a second run's rows would misalign them against columns the first run
added, and deciding that a stored table already covers a request — or
backfilling the columns it lacks — is issue #32's job, not this one's.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, TypeAlias

from remora.codegen.fingerprint import parse_tshark_version
from remora.compile.dfilter import compile_dfilter
from remora.expr import Expr
from remora.fields import FieldRef
from remora.reader.fields_reader import FieldsReader, fields_argv
from remora.reader.process import TsharkNotFoundError
from remora.workspace.cachekey import make_cache_key
from remora.workspace.errors import ColumnNameCollisionError, WorkspaceError
from remora.workspace.naming import find_collisions
from remora.workspace.schema import (
    CacheKeyRecord,
    FieldRecord,
    add_field_column,
    record_cache_key,
    register_fields,
)
from remora.workspace.types import ColumnSpec, column_spec

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
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

#: Requested abbrevs whose data already lives in the pkts row-key skeleton.
_SKELETON_ABBREVS: Final[frozenset[str]] = frozenset({"frame.number", "frame.time"})

_FRAME_NUMBER_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.number",
    column_name="frame_number",
    ftype="FT_FRAMENUM",
    multi=False,
    # Deliberately not column_sql_type("FT_FRAMENUM") (UINTEGER): frame_number
    # is part of the pkts skeleton, so this must match what schema.py's layout
    # declares, not what the ftype map would pick for a projected column.
    sql_type="BIGINT",
)
# frame.time renders human-readable; frame.time_epoch is the epoch-seconds
# form remora.values.convert parses for FT_ABSOLUTE_TIME, landing in the
# frame_time column.
_FRAME_TIME_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.time_epoch",
    column_name="frame_time",
    ftype="FT_ABSOLUTE_TIME",
    multi=False,
    sql_type="TIMESTAMP",
)


def detect_tshark_version(tshark: str) -> str:
    """Read the version string of a tshark binary.

    The version is a cache-key component: the same capture dissected by two
    tshark releases can yield different fields, so a materialization records
    which one produced it.

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
        ValueError: If its output carries no recognizable version.
    """
    try:
        output = subprocess.run(
            [tshark, "--version"], check=True, capture_output=True, text=True
        ).stdout
    except OSError as exc:
        raise TsharkNotFoundError(
            f"tshark binary not found or not runnable: {tshark!r} ({exc}). Install "
            "Wireshark (which provides tshark) or point Remora at an explicit "
            "tshark executable path."
        ) from exc
    return parse_tshark_version(output)


@dataclass(frozen=True)
class MaterializeResult:
    """What one :func:`materialize_into` call wrote.

    Attributes:
        row_count: Packet rows appended to ``main.pkts``.
        batch_count: ``executemany`` batches those rows were written in.
        cache_key: The recorded cache key and every component it covers.
        dfilter: Display filter pushed to tshark, or ``None`` when unfiltered.
        fields: Registry entries written to ``meta.fields`` — one per
            materialized column, so a request satisfied by the row-key
            skeleton is absent here.
    """

    row_count: int
    batch_count: int
    cache_key: CacheKeyRecord
    dfilter: str | None
    fields: tuple[FieldRecord, ...]


def _quote_identifier(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


def _refuse_second_materialization(con: DuckDBPyConnection) -> None:
    """Refuse a workspace that already holds packet rows or registered fields."""
    rows = con.execute("SELECT count(*) FROM main.pkts").fetchone()
    fields = con.execute("SELECT count(*) FROM meta.fields").fetchone()
    n_rows = 0 if rows is None else int(rows[0])
    n_fields = 0 if fields is None else int(fields[0])
    if n_rows or n_fields:
        raise WorkspaceError(
            f"workspace already holds a materialization ({n_rows} pkts rows, "
            f"{n_fields} registered fields); cache-hit and backfill land with "
            f"issue #32 — materialize into a fresh workspace file"
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

    Returns:
        What was written — row and batch counts, the cache key, the pushed
        filter and the field registry entries.

    Raises:
        ValueError: If ``batch_size`` is below 1, if a capture path or argv
            element cannot be stored (see
            :func:`~remora.workspace.cachekey.make_cache_key`), or if a field
            declared scalar occurs more than once in one packet.
        ColumnNameCollisionError: If two distinct abbrevs claim one column.
        WorkspaceError: If the workspace already holds a materialization, or
            if a requested field claims a ``pkts`` skeleton column name.
        UnsupportedExprError: If ``filter`` cannot be pushed to tshark.
        OSError: If ``pcap`` cannot be read for its fingerprint.
    """
    if batch_size < 1:
        raise ValueError(f"batch_size must be at least 1, not {batch_size}")
    # Dedup requested refs by name, order-preserving (FieldRef is unhashable by design).
    requested: dict[str, FieldRef[Any]] = {}
    for ref in fields:
        requested.setdefault(ref.name, ref)
    collisions = find_collisions(requested)
    if collisions:
        detail = "; ".join(
            f"{column} <- {', '.join(owners)}" for column, owners in sorted(collisions.items())
        )
        raise ColumnNameCollisionError(f"field set maps distinct abbrevs onto one column: {detail}")
    # Skeleton-backed requests need no column; anything else claiming a
    # skeleton column name falls through to add_field_column's refusal.
    material_specs = [
        column_spec(ref.name, ref.ftype, ref.multi)
        for name, ref in requested.items()
        if name not in _SKELETON_ABBREVS
    ]
    _refuse_second_materialization(con)
    dfilter = compile_dfilter(filter) if filter is not None else None
    # Projection: skeleton first, then requested fields, dedup by name so a
    # requested frame.time_epoch is projected once.
    projection: dict[str, FieldRef[Any]] = {
        "frame.number": FieldRef("frame.number", "FT_FRAMENUM", False),
        "frame.time_epoch": FieldRef("frame.time_epoch", "FT_ABSOLUTE_TIME", False),
    }
    for name, ref in requested.items():
        if name not in _SKELETON_ABBREVS:
            projection.setdefault(name, ref)
    projection_refs = tuple(projection.values())
    argv = [tshark, "-r", os.fspath(pcap)]
    if dfilter is not None:
        argv += ["-Y", dfilter]
    argv += fields_argv(projection_refs)
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
    for spec in material_specs:
        add_field_column(con, spec.column_name, spec.sql_type)
    insert_specs = [_FRAME_NUMBER_SPEC, _FRAME_TIME_SPEC, *material_specs]
    insert_sql = "INSERT INTO main.pkts ({}) VALUES ({})".format(
        ", ".join(_quote_identifier(spec.column_name) for spec in insert_specs),
        ", ".join("?" for _ in insert_specs),
    )
    row_count = 0
    batch_count = 0
    batch: list[list[Any]] = []
    with runner(argv) as lines:
        for row in FieldsReader(lines, projection_refs):
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
    field_records = tuple(
        FieldRecord(
            abbrev=spec.abbrev,
            column_name=spec.column_name,
            ftype=spec.ftype,
            multi=spec.multi,
            column_type=spec.sql_type,
            materialized_at=record.created_at,
        )
        for spec in material_specs
    )
    register_fields(con, field_records)
    record_cache_key(con, record)
    return MaterializeResult(
        row_count=row_count,
        batch_count=batch_count,
        cache_key=record,
        dfilter=dfilter,
        fields=field_records,
    )
