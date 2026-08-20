"""Workspace storage schema: the single DDL code path and its catalog.

Layout
------
Packet data lives in ``main``; the catalog lives in a dedicated ``meta``
schema, so ``meta.fields`` is a literal table reference and user SQL over
``pkts`` never trips on catalog names.

===================  =======================================================
Table                Holds
===================  =======================================================
``main.pkts``        One row per packet. Created with only the row-key
                     skeleton (``frame_number``, ``frame_time``); projected
                     field columns are added by the materialize pipeline
                     (#31) through :func:`add_field_column`.
``main.streams``     One row per transport stream, rolled up from ``pkts`` by
                     :mod:`remora.workspace.streams` (#33): endpoints, packet
                     and byte counts, first/last frame and timestamp.
                     ``(protocol, stream_id)`` is the key — tcp and udp each
                     number their streams from zero.
``main.annotations`` Analyst annotations on packets and streams; the API and
                     the kept-but-flagged orphan policy live in
                     :mod:`remora.workspace.annotations` (#30). A stream
                     annotation names its target by ``(protocol, target_id)``,
                     matching ``streams``' own key.
``meta.info``        Key/value catalog, including ``schema_version``.
``meta.fields``      What has been materialized: abbrev, column, ftype,
                     multiplicity, column type, timestamp.
``meta.cache_keys``  Materialization cache keys and their components. This
                     module stores them; #27 computes them and #32 decides
                     reuse from them — one row per workspace, describing the
                     materialization the file currently is.
===================  =======================================================

``pkts`` deliberately has no ``PRIMARY KEY``: DuckDB backs one with an ART
index that taxes exactly the bulk append path #31 must keep cheap.
``frame_number`` is the row key by convention — unique within a workspace and
ascending in capture order. The small catalog tables keep their keys; they take
single-row writes, and the constraint is the point.

``streams`` keeps a key too — ``UNIQUE (protocol, stream_id)`` — because it is
on the catalog side of that trade rather than the bulk side: it holds one row
per conversation, not one per packet, and is rebuilt wholesale rather than
appended to. tcp and udp both number their streams from zero, so the pair is
the key and the stream id alone is not. The index cost is what makes the
duplicate impossible instead of merely unintended, and it does not obstruct the
rebuild: deleting every row and re-inserting the same keys inside one
transaction is accepted (pinned by a test, since an index that still held the
deleted keys until commit would reject it).

Column types come from the caller. :mod:`remora.workspace.types` maps an ftype
to its column type; nothing here invents a type mapping. ``streams``' endpoint
columns are the one place the layout writes such a type out by hand — they
must hold exactly what the ``pkts`` columns they are rolled up from hold, so
``src_addr``/``dst_addr`` are ``FT_IPv4``'s ``UINTEGER`` and
``src_port``/``dst_port`` are ``FT_UINT16``'s ``USMALLINT``, and a test pins
them against :func:`remora.workspace.types.column_sql_type` so the two cannot
drift.

Timestamps follow the UTC convention stated in :mod:`remora.workspace.types`
and use its :func:`~remora.workspace.types.to_db_timestamp` /
:func:`~remora.workspace.types.from_db_timestamp` pair on every catalog
column.

There is exactly one supported layout version at a time and no migration path:
a file whose recorded version differs from :data:`SCHEMA_VERSION` in either
direction is refused by :func:`check_compatible`. Changing a table here is
therefore always a version bump, even when the table is one nothing has
populated yet: ``create_schema`` is ``IF NOT EXISTS``-only, so it cannot add a
column to an existing file, and an older file that still *opened* would carry
a ``streams`` table missing the columns SQL written against this layout names —
surfacing as a raw DuckDB binder error deep inside a query rather than as a
refusal at open. That is what version 2 is: #33 added ``main.streams``'
endpoint columns and its ``UNIQUE`` key, so a version 1 workspace is now
refused by name of both versions and has to be recreated.

Connections are supplied by the caller — this module never opens one, because
connection and lock ownership belongs to ``Workspace`` (#28). It therefore
imports duckdb only for typing and stays importable without it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from remora.workspace.errors import SchemaVersionError, WorkspaceError
from remora.workspace.naming import SKELETON_COLUMNS
from remora.workspace.types import from_db_timestamp, to_db_timestamp

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "BACKFILL_SCAN_TABLE",
    "SCHEMA_VERSION",
    "SKELETON_COLUMN_TYPES",
    "CacheKeyRecord",
    "FieldRecord",
    "add_field_column",
    "check_compatible",
    "create_backfill_scan",
    "create_schema",
    "delete_cache_key",
    "find_covering_cache_key",
    "find_duplicate_row_keys",
    "iter_ddl",
    "iter_scratch_ddl",
    "read_cache_key",
    "read_cache_keys",
    "read_fields",
    "read_pkts_columns",
    "read_schema_version",
    "record_cache_key",
    "register_fields",
]

SCHEMA_VERSION: Final[int] = 2
"""Storage layout version written into ``meta.info`` at creation.

Version 2 is #33's: ``main.streams``' four endpoint columns and its
``UNIQUE (protocol, stream_id)`` key, plus the ``main.annotations.protocol``
column that key forced — a stream annotation has to name the same pair the
stream itself is keyed by. A version 1 file is refused at open by
:func:`check_compatible` rather than migrated — see the module docstring.
"""

_SCHEMA_VERSION_KEY: Final[str] = "schema_version"

_DDL: Final[tuple[str, ...]] = (
    """
    CREATE TABLE IF NOT EXISTS main.pkts (
        frame_number BIGINT,
        frame_time   TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS main.streams (
        stream_id   BIGINT,
        protocol    VARCHAR,
        src_addr    UINTEGER,
        src_port    USMALLINT,
        dst_addr    UINTEGER,
        dst_port    USMALLINT,
        first_frame BIGINT,
        last_frame  BIGINT,
        pkt_count   BIGINT,
        byte_count  BIGINT,
        first_time  TIMESTAMP,
        last_time   TIMESTAMP,
        UNIQUE (protocol, stream_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS main.annotations (
        annotation_id BIGINT,
        scope         VARCHAR,
        target_id     BIGINT,
        protocol      VARCHAR,
        key           VARCHAR,
        value         VARCHAR,
        created_at    TIMESTAMP
    )
    """,
    "CREATE SCHEMA IF NOT EXISTS meta",
    """
    CREATE TABLE IF NOT EXISTS meta.info (
        key   VARCHAR PRIMARY KEY,
        value VARCHAR NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS meta.fields (
        abbrev          VARCHAR PRIMARY KEY,
        column_name     VARCHAR NOT NULL UNIQUE,
        ftype           VARCHAR NOT NULL,
        multi           BOOLEAN NOT NULL,
        column_type     VARCHAR NOT NULL,
        materialized_at TIMESTAMP NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS meta.cache_keys (
        key              VARCHAR PRIMARY KEY,
        pcap_path        VARCHAR NOT NULL,
        pcap_fingerprint VARCHAR NOT NULL,
        fields           VARCHAR[] NOT NULL,
        dfilter          VARCHAR,
        tshark_version   VARCHAR NOT NULL,
        argv             VARCHAR[] NOT NULL,
        created_at       TIMESTAMP NOT NULL
    )
    """,
)


BACKFILL_SCAN_TABLE: Final[str] = "temp.main.backfill_scan"
"""Fully qualified name of the staging table :func:`create_backfill_scan` makes."""

_SCRATCH_DDL: Final[tuple[str, ...]] = (
    """
    CREATE TEMP TABLE backfill_scan (
        frame_number BIGINT
    )
    """,
)


SKELETON_COLUMN_TYPES: Final[Mapping[str, str]] = MappingProxyType(
    {"frame_number": "BIGINT", "frame_time": "TIMESTAMP"}
)
"""SQL types the layout declares for the ``pkts`` skeleton columns.

The single authoritative statement of what ``frame_number`` and ``frame_time``
*are*, for every layer that needs to know: the materialize pipeline binds
values into them (#31) and verifies the live table still matches them before
reusing a workspace (#32). Both used to restate the literals, which is the
drift this constant exists to prevent — ``naming.SKELETON_COLUMNS`` does the
same job for the names.

It is declared beside :data:`_DDL` rather than parsed out of it: production
code should not carry a SQL parser for two values. Drift is prevented
executably instead —
``tests/test_workspace_schema.py::TestCreateSchema::test_skeleton_column_types_match_the_ddl``
runs :func:`create_schema` and asserts the live catalog reports exactly this
mapping, so changing the DDL without changing this constant fails a test
rather than silently disagreeing.
"""


def iter_ddl() -> tuple[str, ...]:
    """Return every DDL statement the workspace *layout* is made of.

    The statements are the single source of the layout: :func:`create_schema`
    executes exactly these, and no CREATE statement building a layout name
    exists elsewhere. Scratch DDL — objects that never reach the file — is
    declared separately in :func:`iter_scratch_ddl`.
    """
    return _DDL


def iter_scratch_ddl() -> tuple[str, ...]:
    """Return the DDL for objects this module creates but the layout excludes.

    Exactly one today: the backfill staging table (#32). It is ``TEMP``, so it
    lives in DuckDB's ``temp`` database rather than the workspace file —
    invisible to every ``current_database()`` catalog probe here, dropped with
    the connection, and rolled back with the transaction that made it. It is
    declared as a constant for the same reason the layout is: so no helper can
    build DDL inline, which is what the schema tests pin.
    """
    return _SCRATCH_DDL


def create_schema(con: DuckDBPyConnection) -> None:
    """Create the workspace schema on ``con`` if it is not already there.

    Idempotent: every statement is ``IF NOT EXISTS`` and the version row is
    inserted only when absent, so this is the one open-or-create code path.
    Existing data is left untouched.

    This does **not** imply :func:`check_compatible`. Because every statement is
    ``IF NOT EXISTS``, running it against a workspace written by a different
    layout version silently no-ops on the stale tables; an opener (#28) must
    call :func:`check_compatible` on an existing file before trusting it.

    Args:
        con: An open DuckDB connection to the workspace.
    """
    for statement in _DDL:
        con.execute(statement)
    con.execute(
        "INSERT INTO meta.info (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
        [_SCHEMA_VERSION_KEY, str(SCHEMA_VERSION)],
    )


def read_pkts_columns(con: DuckDBPyConnection) -> dict[str, str]:
    """Return ``main.pkts``'s live columns as name -> SQL type.

    The physical truth about the table, as opposed to what ``meta.fields``
    says about it: #32 compares the two before reusing a workspace, because a
    registry row is not evidence that its column is still there or still has
    the type it was created with.

    Pinned to ``current_database()`` and the ``main`` schema like every other
    catalog probe here, so an attached workspace's ``pkts`` cannot answer for
    this one's.

    Args:
        con: An open connection to the workspace.

    Returns:
        Column name to the SQL type DuckDB reports for it, in ordinal order.
        The reported spelling round-trips what :func:`add_field_column` was
        given for every type :mod:`remora.workspace.types` can produce,
        ``T[]`` list types included — a test pins that over the whole ftype
        table, which is what lets callers compare the strings directly.
    """
    rows = con.execute(
        "SELECT column_name, data_type FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' ORDER BY column_index"
    ).fetchall()
    return {str(name): str(data_type) for name, data_type in rows}


def find_duplicate_row_keys(con: DuckDBPyConnection, limit: int = 5) -> tuple[int, list[int]]:
    """Probe ``main.pkts`` for row keys that are not usable as row keys.

    ``pkts`` has no ``PRIMARY KEY`` — DuckDB would back one with an ART index
    that taxes the bulk append path (#25) — so ``frame_number``'s uniqueness
    is a convention, and a backfill that matches rows on it has to verify the
    convention holds before it writes. One statement, two aggregate passes
    over a single ``BIGINT`` column, with the examples bounded by ``limit``.

    Args:
        con: An open connection to the workspace.
        limit: How many duplicate frame numbers to name.

    Returns:
        The number of rows whose ``frame_number`` is ``NULL``, and up to
        ``limit`` frame numbers that occur more than once.
    """
    row = con.execute(
        f"""
        SELECT
            (SELECT count(*) FROM main.pkts WHERE frame_number IS NULL),
            (SELECT list(frame_number) FROM (
                SELECT frame_number FROM main.pkts WHERE frame_number IS NOT NULL
                GROUP BY frame_number HAVING count(*) > 1
                ORDER BY frame_number LIMIT {int(limit)}
            ))
        """
    ).fetchone()
    if row is None:
        return 0, []
    return int(row[0]), [int(value) for value in (row[1] or [])]


def create_backfill_scan(con: DuckDBPyConnection) -> str:
    """Create the session-scoped staging table a backfill validates against (#32).

    A backfill has to prove that its second tshark scan produced exactly the
    rows ``pkts`` already holds — no duplicate frame number, none missing,
    none extra — and proving that with a Python set would hold every frame
    number of a multi-million-row capture in memory. Staging the scanned row
    keys in DuckDB instead keeps the check set-based and the memory bounded
    (the database spills to disk; the caller still streams in batches).

    Only ``frame_number`` is staged, never the scanned values: a column per
    projected field would mean DDL built inline from a caller's field set,
    which is exactly what this module's constants exist to prevent. The values
    take the pipeline's ordinary bound-parameter path.

    Any previous staging table on this connection is dropped first, so a
    caller running two materializations on one connection starts clean.

    Args:
        con: A read-write connection to an open workspace, inside a
            transaction the caller owns. Rolling that transaction back removes
            the table with everything else.

    Returns:
        The fully qualified table name (:data:`BACKFILL_SCAN_TABLE`), so
        callers do not restate it.
    """
    con.execute(f"DROP TABLE IF EXISTS {BACKFILL_SCAN_TABLE}")
    for statement in _SCRATCH_DDL:
        con.execute(statement)
    return BACKFILL_SCAN_TABLE


def read_schema_version(con: DuckDBPyConnection) -> int:
    """Return the schema version recorded in ``meta.info``.

    Args:
        con: An open DuckDB connection to the workspace.

    Returns:
        The recorded schema version.

    Raises:
        SchemaVersionError: If the catalog or the version row is missing, or
            the recorded value is not an integer.
    """
    # duckdb_tables() spans every attached database, so pin the probe to the
    # current one — otherwise an unrelated workspace attached alongside makes a
    # blank database look like a workspace and the next statement escapes as a
    # raw duckdb.CatalogException.
    catalog = con.execute(
        "SELECT count(*) FROM duckdb_tables() "
        "WHERE database_name = current_database() "
        "AND schema_name = 'meta' AND table_name = 'info'"
    ).fetchone()
    if catalog is None or catalog[0] == 0:
        raise SchemaVersionError("not a remora workspace: the meta.info catalog table is missing")
    row = con.execute("SELECT value FROM meta.info WHERE key = ?", [_SCHEMA_VERSION_KEY]).fetchone()
    if row is None:
        raise SchemaVersionError("not a remora workspace: meta.info has no schema_version row")
    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise SchemaVersionError(f"workspace schema_version is not an integer: {row[0]!r}") from exc


def check_compatible(con: DuckDBPyConnection) -> None:
    """Verify this library can read the workspace opened on ``con``.

    Only the exact :data:`SCHEMA_VERSION` is accepted. There is no migration
    path in either direction, and an older file must be refused loudly rather
    than half-upgraded: :func:`create_schema` is ``IF NOT EXISTS``-only, so it
    would no-op on the stale tables and hand back a workspace whose layout
    silently disagrees with this library.

    Args:
        con: An open DuckDB connection to the workspace.

    Raises:
        SchemaVersionError: If the file's schema version is not
            :data:`SCHEMA_VERSION`, or the workspace catalog is missing.
    """
    found = read_schema_version(con)
    if found > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"workspace schema version {found} is newer than this remora "
            f"supports ({SCHEMA_VERSION}); upgrade remora to open it"
        )
    if found < SCHEMA_VERSION:
        raise SchemaVersionError(
            f"workspace schema version {found} was written by an older remora "
            f"than this one ({SCHEMA_VERSION}); there is no migration path, so "
            f"recreate the workspace"
        )


_SQL_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z][A-Za-z0-9_ ]*(\(\s*\d+(\s*,\s*\d+)?\s*\))?(\[\])*$"
)


@dataclass(frozen=True)
class FieldRecord:
    """One materialized field in the ``meta.fields`` registry.

    Attributes:
        abbrev: Full tshark field name, e.g. ``"tcp.port"``.
        column_name: Column in ``pkts``, from
            :func:`remora.workspace.naming.column_name`.
        ftype: tshark ftype name, e.g. ``"FT_UINT16"``.
        multi: Whether the field can occur more than once per packet.
        column_type: SQL type of the column, from
            :func:`remora.workspace.types.column_sql_type`.
        materialized_at: When the column was materialized (aware, UTC).
    """

    abbrev: str
    column_name: str
    ftype: str
    multi: bool
    column_type: str
    materialized_at: datetime


@dataclass(frozen=True)
class CacheKeyRecord:
    """A materialization cache key and the components it was computed from.

    This module stores the record; #27 computes the key and #32 decides
    hit/miss. Components are kept individually for diagnostics.

    Attributes:
        key: The cache-key digest.
        pcap_path: Capture file the materialization read.
        pcap_fingerprint: Cheap identity of that file's contents.
        fields: tshark field abbrevs that were projected.
        dfilter: Display filter pushed down, or ``None`` when unfiltered.
        tshark_version: Version string of the tshark that produced the data.
        argv: The exact tshark argv that was run.
        created_at: When the entry was recorded (aware, UTC).
    """

    key: str
    pcap_path: str
    pcap_fingerprint: str
    fields: tuple[str, ...]
    dfilter: str | None
    tshark_version: str
    argv: tuple[str, ...]
    created_at: datetime


def _quote_identifier(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def register_fields(con: DuckDBPyConnection, records: Iterable[FieldRecord]) -> None:
    """Write field registry entries, replacing any entry with the same abbrev.

    Args:
        con: A read-write connection to the workspace.
        records: Registry entries to upsert, keyed by ``abbrev``.
    """
    for record in records:
        con.execute(
            """
            INSERT INTO meta.fields
                (abbrev, column_name, ftype, multi, column_type, materialized_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (abbrev) DO UPDATE SET
                column_name = excluded.column_name,
                ftype = excluded.ftype,
                multi = excluded.multi,
                column_type = excluded.column_type,
                materialized_at = excluded.materialized_at
            """,
            [
                record.abbrev,
                record.column_name,
                record.ftype,
                record.multi,
                record.column_type,
                to_db_timestamp(record.materialized_at),
            ],
        )


def read_fields(con: DuckDBPyConnection) -> tuple[FieldRecord, ...]:
    """Read the whole field registry, ordered by abbrev.

    Args:
        con: An open connection to the workspace.

    Returns:
        Every registry entry, ascending by ``abbrev``.
    """
    rows = con.execute(
        """
        SELECT abbrev, column_name, ftype, multi, column_type, materialized_at
        FROM meta.fields ORDER BY abbrev
        """
    ).fetchall()
    return tuple(
        FieldRecord(
            abbrev=abbrev,
            column_name=column,
            ftype=ftype,
            multi=bool(multi),
            column_type=column_type,
            materialized_at=from_db_timestamp(materialized_at),
        )
        for abbrev, column, ftype, multi, column_type, materialized_at in rows
    )


def record_cache_key(con: DuckDBPyConnection, record: CacheKeyRecord) -> None:
    """Store a materialization cache key, replacing any entry with the same key.

    Args:
        con: A read-write connection to the workspace.
        record: The cache key and the components it was computed from.
    """
    con.execute(
        """
        INSERT INTO meta.cache_keys
            (key, pcap_path, pcap_fingerprint, fields, dfilter, tshark_version,
             argv, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (key) DO UPDATE SET
            pcap_path = excluded.pcap_path,
            pcap_fingerprint = excluded.pcap_fingerprint,
            fields = excluded.fields,
            dfilter = excluded.dfilter,
            tshark_version = excluded.tshark_version,
            argv = excluded.argv,
            created_at = excluded.created_at
        """,
        [
            record.key,
            record.pcap_path,
            record.pcap_fingerprint,
            list(record.fields),
            record.dfilter,
            record.tshark_version,
            list(record.argv),
            to_db_timestamp(record.created_at),
        ],
    )


_CACHE_KEY_COLUMNS: Final[str] = (
    "key, pcap_path, pcap_fingerprint, fields, dfilter, tshark_version, argv, created_at"
)


def _to_cache_key_record(row: tuple[Any, ...]) -> CacheKeyRecord:
    """Build a record from one ``_CACHE_KEY_COLUMNS`` row."""
    return CacheKeyRecord(
        key=row[0],
        pcap_path=row[1],
        pcap_fingerprint=row[2],
        fields=tuple(row[3]),
        dfilter=row[4],
        tshark_version=row[5],
        argv=tuple(row[6]),
        created_at=from_db_timestamp(row[7]),
    )


def read_cache_key(con: DuckDBPyConnection, key: str) -> CacheKeyRecord | None:
    """Read one cache key by digest, or ``None`` when it is not stored.

    Args:
        con: An open connection to the workspace.
        key: The cache-key digest to look up.

    Returns:
        The stored record, or ``None`` when the key is not present.
    """
    row = con.execute(
        f"SELECT {_CACHE_KEY_COLUMNS} FROM meta.cache_keys WHERE key = ?",
        [key],
    ).fetchone()
    return None if row is None else _to_cache_key_record(row)


def read_cache_keys(con: DuckDBPyConnection) -> tuple[CacheKeyRecord, ...]:
    """Read every stored cache key, oldest first.

    A workspace written by :mod:`remora.workspace.materialize` holds at most
    one: the key describes *the* materialization the file currently is, and a
    backfill replaces it with the key of the widened one. Reading them all is
    what lets that invariant be checked rather than assumed.

    Args:
        con: An open connection to the workspace.

    Returns:
        Every stored key, ascending by ``created_at`` then ``key``.
    """
    rows = con.execute(
        f"SELECT {_CACHE_KEY_COLUMNS} FROM meta.cache_keys ORDER BY created_at, key"
    ).fetchall()
    return tuple(_to_cache_key_record(row) for row in rows)


def find_covering_cache_key(
    con: DuckDBPyConnection,
    *,
    pcap_fingerprint: str,
    dfilter: str | None,
    tshark_version: str,
    fields: Iterable[str],
) -> CacheKeyRecord | None:
    """Find a stored key that already covers a request's field set (#32).

    This is the subset rule as a SQL predicate, which is why #27 canonicalizes
    the stored field set (sorted, deduplicated) and #25 stores it as a native
    ``VARCHAR[]``: ``list_has_all`` decides coverage inside the database
    instead of fetching every key and comparing in Python, and the same
    predicate is available to anyone querying the workspace file directly.

    The components matched here are the ones that must be *identical* for
    stored rows to answer the request. ``argv`` is deliberately not among
    them: parts of it are derived from the very things compared separately
    (the projection, the capture path, the display filter), so the caller
    compares what is left — see
    :func:`remora.workspace.materialize.materialize_into`.

    Args:
        con: An open connection to the workspace.
        pcap_fingerprint: Rendered fingerprint of the capture being requested.
        dfilter: Display filter of the request, or ``None``. ``NULL`` matches
            ``None`` and nothing else (``IS NOT DISTINCT FROM``), so an
            unfiltered materialization never answers a filtered request.
        tshark_version: Version of the tshark producing the request.
        fields: Field abbrevs the request asks for.

    Returns:
        The newest matching key whose field set contains every requested
        field, or ``None`` when no stored key covers the request.
    """
    row = con.execute(
        f"""
        SELECT {_CACHE_KEY_COLUMNS} FROM meta.cache_keys
        WHERE pcap_fingerprint = ?
          AND tshark_version = ?
          AND dfilter IS NOT DISTINCT FROM CAST(? AS VARCHAR)
          AND list_has_all(fields, CAST(? AS VARCHAR[]))
        ORDER BY created_at DESC, key DESC
        LIMIT 1
        """,
        [pcap_fingerprint, tshark_version, dfilter, list(fields)],
    ).fetchone()
    return None if row is None else _to_cache_key_record(row)


def delete_cache_key(con: DuckDBPyConnection, key: str) -> bool:
    """Remove one stored cache key.

    A backfill widens the materialization, so the key describing the narrower
    one must go: the workspace records what it *is*, not what it once was.

    Args:
        con: A read-write connection to the workspace.
        key: The cache-key digest to remove.

    Returns:
        Whether a row was removed.
    """
    before = con.execute("SELECT count(*) FROM meta.cache_keys WHERE key = ?", [key]).fetchone()
    con.execute("DELETE FROM meta.cache_keys WHERE key = ?", [key])
    return before is not None and int(before[0]) > 0


def add_field_column(con: DuckDBPyConnection, column: str, sql_type: str = "VARCHAR") -> None:
    """Add a projected field column to ``pkts``.

    Args:
        con: Read-write connection.
        column: Column name from :func:`remora.workspace.naming.column_name`.
            Quoted, so a hostile name cannot inject SQL.
        sql_type: SQL type for the column, from
            :func:`remora.workspace.types.column_sql_type`; ``"VARCHAR"`` is
            the default because it holds anything. Types cannot be bound as
            parameters, so the value is validated against a conservative
            pattern: letters, digits, underscores and *spaces* (multi-word
            types such as ``DOUBLE PRECISION`` are real), then an optional
            precision and any number of ``[]`` suffixes. Spaces mean the
            pattern also admits type-and-modifier strings like
            ``"BIGINT NOT NULL"``; what it excludes is punctuation, and with
            it every way out of the type position.

    Raises:
        ValueError: If ``sql_type`` is not a plain SQL type.
        WorkspaceError: If ``column`` is a ``pkts`` skeleton column, or ``pkts``
            already has that column.
    """
    if column in SKELETON_COLUMNS:
        raise WorkspaceError(
            f"{column!r} is already the pkts row key and does not need "
            f"materializing; drop it from the field set"
        )
    if not _SQL_TYPE_RE.fullmatch(sql_type):
        raise ValueError(f"not a plain SQL type: {sql_type!r}")
    existing = con.execute(
        "SELECT count(*) FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' AND column_name = ?",
        [column],
    ).fetchone()
    if existing is not None and existing[0] > 0:
        raise WorkspaceError(f"pkts already has a column named {column!r}")
    con.execute(f"ALTER TABLE main.pkts ADD COLUMN {_quote_identifier(column)} {sql_type}")
