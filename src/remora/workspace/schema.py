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
``main.streams``     Stream sessionization output — a documented placeholder
                     here; #33 owns the semantics.
``main.annotations`` User annotations — a placeholder here; #30 owns the API.
``meta.info``        Key/value catalog, including ``schema_version``.
``meta.fields``      What has been materialized: abbrev, column, ftype,
                     multiplicity, column type, timestamp.
``meta.cache_keys``  Materialization cache keys and their components. This
                     module stores them; #27 computes them.
===================  =======================================================

``pkts`` deliberately has no ``PRIMARY KEY``: DuckDB backs one with an ART
index that taxes exactly the bulk append path #31 must keep cheap.
``frame_number`` is the row key by convention — unique within a workspace and
ascending in capture order. The small catalog tables keep their keys; they take
single-row writes, and the constraint is the point.

Column types are ``VARCHAR`` placeholders until the FType -> column-type map
lands (#26); nothing here invents a type mapping.

Timestamps are UTC. DuckDB ``TIMESTAMP`` is timezone-naive, so aware datetimes
are converted to naive UTC on write and re-tagged as UTC on read.

Connections are supplied by the caller — this module never opens one, because
connection and lock ownership belongs to ``Workspace`` (#28). It therefore
imports duckdb only for typing and stays importable without it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from remora.workspace.errors import SchemaVersionError

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "SCHEMA_VERSION",
    "check_compatible",
    "create_schema",
    "iter_ddl",
    "read_schema_version",
]

SCHEMA_VERSION: Final[int] = 1
"""Storage layout version written into ``meta.info`` at creation."""

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
        first_frame BIGINT,
        last_frame  BIGINT,
        pkt_count   BIGINT,
        byte_count  BIGINT,
        first_time  TIMESTAMP,
        last_time   TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS main.annotations (
        annotation_id BIGINT,
        scope         VARCHAR,
        target_id     BIGINT,
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
        column_name     VARCHAR NOT NULL,
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
        fields           VARCHAR NOT NULL,
        dfilter          VARCHAR,
        tshark_version   VARCHAR NOT NULL,
        argv             VARCHAR NOT NULL,
        created_at       TIMESTAMP NOT NULL
    )
    """,
)


def iter_ddl() -> tuple[str, ...]:
    """Return every DDL statement the workspace schema is made of.

    The statements are the single source of the layout: :func:`create_schema`
    executes exactly these, and no CREATE statement exists elsewhere.
    """
    return _DDL


def create_schema(con: DuckDBPyConnection) -> None:
    """Create the workspace schema on ``con`` if it is not already there.

    Idempotent: every statement is ``IF NOT EXISTS`` and the version row is
    inserted only when absent, so this is the one open-or-create code path.
    Existing data is left untouched.

    Args:
        con: An open DuckDB connection to the workspace.
    """
    for statement in _DDL:
        con.execute(statement)
    con.execute(
        "INSERT INTO meta.info (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
        [_SCHEMA_VERSION_KEY, str(SCHEMA_VERSION)],
    )


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
    catalog = con.execute(
        "SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'meta' AND table_name = 'info'"
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

    Args:
        con: An open DuckDB connection to the workspace.

    Raises:
        SchemaVersionError: If the file's schema version is newer than
            :data:`SCHEMA_VERSION`, or the workspace catalog is missing. Older
            versions are accepted — only version 1 exists, so there is nothing
            to migrate yet.
    """
    found = read_schema_version(con)
    if found > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"workspace schema version {found} is newer than this remora "
            f"supports ({SCHEMA_VERSION}); upgrade remora to open it"
        )
