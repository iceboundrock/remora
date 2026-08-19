"""Workspace storage schema tests (issue #25)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from remora.workspace.errors import SchemaVersionError, WorkspaceError
from remora.workspace.naming import column_name
from remora.workspace.schema import (
    SCHEMA_VERSION,
    CacheKeyRecord,
    FieldRecord,
    add_field_column,
    check_compatible,
    create_backfill_scan,
    create_schema,
    iter_ddl,
    iter_scratch_ddl,
    read_cache_key,
    read_fields,
    read_schema_version,
    record_cache_key,
    register_fields,
)

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_MODULE = REPO_ROOT / "src" / "remora" / "workspace" / "schema.py"

# Matches a DDL statement head, through every spelling of the modifiers that
# sit between CREATE and the object kind. TEMP is included deliberately: a
# temporary table never reaches the workspace file, but it is still DDL and
# still has to be declared in schema.py rather than built inline wherever it
# is convenient (#32's backfill staging table is the first one). "\s+" is a
# literal backslash-s in this source, so this pattern does not match its own
# definition.
_DDL_MODIFIERS = r"(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?"
DDL_STATEMENT = re.compile(
    rf"CREATE\s+{_DDL_MODIFIERS}(?:TABLE|SCHEMA|VIEW|INDEX)\b", re.IGNORECASE
)

# The same head plus the name it creates, through the "OR REPLACE", "TEMP" and
# "IF NOT EXISTS" spellings. Self-matching is avoided the same way
# DDL_STATEMENT avoids it.
DDL_TARGET = re.compile(
    rf"CREATE\s+{_DDL_MODIFIERS}(?:TABLE|SCHEMA|VIEW|INDEX)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)",
    re.IGNORECASE,
)

# Files under src/ and tests/ exempt from the file-level DDL rule below. A file
# qualifies only if every DDL statement in it creates a throwaway probe object —
# never a workspace-layout name, which the name-level rule enforces separately
# and without exemption. test_workspace_types.py probes column types on tables
# it creates on a bare in-memory connection; test_workspace_lifecycle.py plants
# foreign objects (a view, a schema) in throwaway files precisely to pin that
# rw open() refuses a foreign database instead of grafting the layout onto it.
DDL_SCRATCH_FILES = frozenset(
    {
        REPO_ROOT / "tests" / "test_workspace_types.py",
        REPO_ROOT / "tests" / "test_workspace_lifecycle.py",
    }
)

EXPECTED_TABLES = {
    ("main", "pkts"),
    ("main", "streams"),
    ("main", "annotations"),
    ("meta", "info"),
    ("meta", "fields"),
    ("meta", "cache_keys"),
}

# Schemas the layout creates. "main" is DuckDB's own default schema, not ours.
WORKSPACE_SCHEMAS = {schema for schema, _ in EXPECTED_TABLES} - {"main"}

# Every name the workspace layout owns, bare and schema-qualified, derived from
# the layout itself so a table added to _DDL is protected without a second list.
WORKSPACE_NAMES = frozenset(
    {table for _, table in EXPECTED_TABLES}
    | {f"{schema}.{table}" for schema, table in EXPECTED_TABLES}
    | WORKSPACE_SCHEMAS
)


def py_sources() -> Iterator[tuple[Path, str]]:
    """Every .py file under src/ and tests/ that could contain DDL, with its text."""
    for tree in (REPO_ROOT / "src", REPO_ROOT / "tests"):
        for path in sorted(tree.rglob("*.py")):
            raw = path.read_bytes()
            # Cheap prefilter: the generated proto tree is ~1 MB and has no DDL.
            if b"create" not in raw.lower():
                continue
            yield path, raw.decode("utf-8", errors="replace")


def files_declaring_ddl() -> set[Path]:
    """Every .py file under src/ and tests/ that contains a DDL statement head."""
    return {path for path, text in py_sources() if DDL_STATEMENT.search(text)}


def workspace_names_created_in(text: str) -> set[str]:
    """Workspace-layout names that DDL in ``text`` creates.

    Keyed on the name a statement *creates*, not on any mention of it: a query
    against pkts is fine anywhere, a DDL statement making one is not.
    """
    hits: set[str] = set()
    for match in DDL_TARGET.finditer(text):
        parts = match.group(1).replace('"', "").lower().split(".")
        # Bare ("pkts") and qualified ("main.pkts", and the trailing two parts
        # of a database-qualified "memory.main.pkts") spellings alike.
        candidates = {parts[-1]} | ({".".join(parts[-2:])} if len(parts) > 1 else set())
        hits |= candidates & WORKSPACE_NAMES
    return hits


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    """An in-memory DuckDB connection with the workspace schema created."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


def table_names(connection: DuckDBPyConnection) -> set[tuple[str, str]]:
    rows = connection.execute("SELECT schema_name, table_name FROM duckdb_tables()").fetchall()
    return {(schema, table) for schema, table in rows}


def database_table_names(connection: DuckDBPyConnection) -> set[tuple[str, str]]:
    """Tables of the current database only — temp objects excluded."""
    rows = connection.execute(
        "SELECT schema_name, table_name FROM duckdb_tables() "
        "WHERE database_name = current_database()"
    ).fetchall()
    return {(schema, table) for schema, table in rows}


def column_names(connection: DuckDBPyConnection, schema: str, table: str) -> list[str]:
    rows = connection.execute(
        "SELECT column_name FROM duckdb_columns() "
        "WHERE schema_name = ? AND table_name = ? ORDER BY column_index",
        [schema, table],
    ).fetchall()
    return [name for (name,) in rows]


class TestCreateSchema:
    def test_creates_exactly_the_core_tables(self, con: DuckDBPyConnection) -> None:
        # Cross-checks the DDL against the live catalog: no table is missing, and
        # none is created that the layout does not document.
        assert table_names(con) == EXPECTED_TABLES

    def test_pkts_skeleton_columns(self, con: DuckDBPyConnection) -> None:
        assert column_names(con, "main", "pkts") == ["frame_number", "frame_time"]

    def test_ddl_is_the_only_source(self) -> None:
        # Rule A, file level: a file in src/ or tests/ containing a DDL head is
        # schema.py or a declared scratch file (DDL_SCRATCH_FILES — a test that
        # creates only throwaway probe tables on a bare in-memory connection).
        # Equality, not containment, so an exemption that stops being needed has
        # to be removed. If this fails, the fix is almost always to delete the
        # DDL or move it into iter_ddl(); adding an exemption is a decision to
        # argue for, and it never buys the right to create a workspace name,
        # which Rule B below forbids everywhere outside schema.py.
        assert files_declaring_ddl() == {SCHEMA_MODULE} | DDL_SCRATCH_FILES

    def test_no_workspace_name_is_created_outside_schema_module(self) -> None:
        # Rule B, name level, no exemptions: nothing outside schema.py may
        # create a name belonging to the layout — the tables of EXPECTED_TABLES
        # bare or schema-qualified, and the meta schema itself. This is what
        # makes Rule A's exemption safe: a scratch file may create t, never pkts.
        offenders = {
            str(path): sorted(names)
            for path, text in py_sources()
            if path != SCHEMA_MODULE and (names := workspace_names_created_in(text))
        }
        assert offenders == {}

    def test_schema_module_keeps_all_ddl_in_its_constants(self) -> None:
        # Within schema.py, every DDL statement belongs to one of the two
        # declared constants — none is built inline by a helper (the risk when
        # #31 added add_field_column, and again when #32 added the backfill
        # staging table). iter_scratch_ddl() is counted alongside iter_ddl()
        # rather than exempted: it is DDL this module owns, held to the same
        # "declared, never assembled" rule, and merely excluded from the
        # *layout* because it never reaches the file.
        in_source = len(DDL_STATEMENT.findall(SCHEMA_MODULE.read_text(encoding="utf-8")))
        declared = (*iter_ddl(), *iter_scratch_ddl())
        in_constants = sum(len(DDL_STATEMENT.findall(statement)) for statement in declared)
        assert in_source == in_constants > 0

    def test_scratch_ddl_is_temporary_and_owns_no_layout_name(self) -> None:
        # What keeps scratch DDL from being a hole in the layout rule: every
        # statement is TEMP (so it dies with the connection and never lands in
        # the workspace file) and creates nothing the layout names.
        assert iter_scratch_ddl()
        for statement in iter_scratch_ddl():
            assert re.search(r"CREATE\s+(?:OR\s+REPLACE\s+)?TEMP\b", statement, re.IGNORECASE)
            assert workspace_names_created_in(statement) == set()

    def test_backfill_scan_staging_stays_out_of_the_workspace(
        self, con: DuckDBPyConnection
    ) -> None:
        # The staging table lives in DuckDB's temp database, so it is invisible
        # to every current_database() catalog probe in this package — including
        # the one that decides whether an rw open() may create the schema.
        table = create_backfill_scan(con)
        con.execute(f"INSERT INTO {table} (frame_number) VALUES (1)")
        # It exists — in the temp database, which is not the workspace.
        assert con.execute(
            "SELECT database_name FROM duckdb_tables() WHERE table_name = 'backfill_scan'"
        ).fetchall() == [("temp",)]
        row = con.execute(
            "SELECT count(*) FROM duckdb_tables() "
            "WHERE database_name = current_database() AND table_name = 'backfill_scan'"
        ).fetchone()
        assert row is not None
        assert row[0] == 0
        # The layout the workspace file holds is untouched by it.
        assert database_table_names(con) == EXPECTED_TABLES
        # Creating it again resets it, so two runs on one connection cannot
        # validate against each other's row keys.
        create_backfill_scan(con)
        row = con.execute(f"SELECT count(*) FROM {table}").fetchone()
        assert row is not None
        assert row[0] == 0

    def test_idempotent(self, con: DuckDBPyConnection) -> None:
        con.execute("INSERT INTO pkts VALUES (1, TIMESTAMP '2026-08-08 00:00:00')")
        create_schema(con)  # second call must not raise or wipe data
        row = con.execute("SELECT count(*) FROM pkts").fetchone()
        assert row is not None
        assert row[0] == 1


class TestSchemaVersion:
    def test_written_on_creation(self, con: DuckDBPyConnection) -> None:
        assert read_schema_version(con) == SCHEMA_VERSION

    def test_compatible_version_passes(self, con: DuckDBPyConnection) -> None:
        check_compatible(con)  # does not raise

    def test_newer_version_names_both_versions(self, con: DuckDBPyConnection) -> None:
        con.execute(
            "UPDATE meta.info SET value = ? WHERE key = 'schema_version'",
            [str(SCHEMA_VERSION + 1)],
        )
        with pytest.raises(SchemaVersionError) as excinfo:
            check_compatible(con)
        message = str(excinfo.value)
        assert str(SCHEMA_VERSION + 1) in message
        assert str(SCHEMA_VERSION) in message

    def test_older_version_names_both_versions(self, con: DuckDBPyConnection) -> None:
        con.execute(
            "UPDATE meta.info SET value = ? WHERE key = 'schema_version'",
            [str(SCHEMA_VERSION - 1)],
        )
        with pytest.raises(SchemaVersionError) as excinfo:
            check_compatible(con)
        message = str(excinfo.value)
        assert str(SCHEMA_VERSION - 1) in message
        assert str(SCHEMA_VERSION) in message

    def test_missing_catalog_is_not_a_workspace(self) -> None:
        blank = duckdb.connect(":memory:")
        try:
            with pytest.raises(SchemaVersionError, match="not a remora workspace"):
                check_compatible(blank)
        finally:
            blank.close()

    def test_a_workspace_attached_alongside_does_not_count(self, con: DuckDBPyConnection) -> None:
        # duckdb_tables() spans every attached database, so the catalog probe
        # must be pinned to the current one. Otherwise a real workspace attached
        # next to a blank current database makes the probe pass and the *next*
        # statement escape as a raw duckdb.CatalogException.
        con.execute("ATTACH ':memory:' AS blank")
        con.execute("USE blank")
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            check_compatible(con)

    def test_missing_version_row(self, con: DuckDBPyConnection) -> None:
        con.execute("DELETE FROM meta.info WHERE key = 'schema_version'")
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            check_compatible(con)

    def test_survives_close_and_reopen(self, tmp_path: Path) -> None:
        path = str(tmp_path / "ws.duckdb")
        first = duckdb.connect(path)
        create_schema(first)
        first.close()
        second = duckdb.connect(path)
        assert read_schema_version(second) == SCHEMA_VERSION
        second.close()


UTC_NOW = datetime(2026, 8, 8, 12, 30, 45, 123456, tzinfo=timezone.utc)


def sample_fields() -> tuple[FieldRecord, ...]:
    return (
        FieldRecord(
            abbrev="ip.src",
            column_name="ip_src",
            ftype="FT_IPv4",
            multi=False,
            column_type="VARCHAR",
            materialized_at=UTC_NOW,
        ),
        FieldRecord(
            abbrev="tcp.port",
            column_name="tcp_port",
            ftype="FT_UINT16",
            multi=True,
            column_type="VARCHAR",
            materialized_at=UTC_NOW,
        ),
    )


class TestFieldRegistry:
    def test_round_trip_over_a_fresh_connection(self, con: DuckDBPyConnection) -> None:
        register_fields(con, sample_fields())
        # cursor() is a separate connection over the same in-memory database.
        assert read_fields(con.cursor()) == sample_fields()

    def test_round_trip_across_close_and_reopen(self, tmp_path: Path) -> None:
        path = str(tmp_path / "ws.duckdb")
        first = duckdb.connect(path)
        create_schema(first)
        register_fields(first, sample_fields())
        first.close()
        second = duckdb.connect(path)
        assert read_fields(second) == sample_fields()
        second.close()

    def test_multiplicity_and_ftype_survive(self, con: DuckDBPyConnection) -> None:
        register_fields(con, sample_fields())
        by_abbrev = {record.abbrev: record for record in read_fields(con)}
        assert by_abbrev["tcp.port"].multi is True
        assert by_abbrev["ip.src"].multi is False
        assert by_abbrev["ip.src"].ftype == "FT_IPv4"

    def test_timestamp_comes_back_as_aware_utc(self, con: DuckDBPyConnection) -> None:
        register_fields(con, sample_fields())
        stored = read_fields(con)[0].materialized_at
        assert stored.tzinfo is timezone.utc
        assert stored == UTC_NOW

    def test_ordered_by_abbrev(self, con: DuckDBPyConnection) -> None:
        register_fields(con, reversed(sample_fields()))
        assert [record.abbrev for record in read_fields(con)] == ["ip.src", "tcp.port"]

    def test_reregistering_an_abbrev_updates_it(self, con: DuckDBPyConnection) -> None:
        register_fields(con, sample_fields())
        later = FieldRecord(
            abbrev="ip.src",
            column_name="ip_src",
            ftype="FT_IPv4",
            multi=False,
            column_type="UINTEGER",
            materialized_at=UTC_NOW,
        )
        register_fields(con, [later])
        assert len(read_fields(con)) == 2
        assert read_fields(con)[0].column_type == "UINTEGER"

    def test_empty_registry_reads_empty(self, con: DuckDBPyConnection) -> None:
        assert read_fields(con) == ()

    def test_column_names_follow_the_naming_policy(self) -> None:
        # The registry stores what naming.column_name derives; nothing else may
        # invent a column name for an abbrev.
        for record in sample_fields():
            assert column_name(record.abbrev) == record.column_name

    def test_two_abbrevs_cannot_claim_one_column(self, con: DuckDBPyConnection) -> None:
        # The policy is non-injective, so storage must refuse the collision
        # rather than let one abbrev silently overwrite the other's column.
        register_fields(con, sample_fields())
        clashing = FieldRecord(
            abbrev="ip.Src",
            column_name="ip_src",
            ftype="FT_IPv4",
            multi=False,
            column_type="VARCHAR",
            materialized_at=UTC_NOW,
        )
        with pytest.raises(duckdb.ConstraintException):
            register_fields(con, [clashing])

    def test_naive_timestamp_is_stored_as_utc(self, con: DuckDBPyConnection) -> None:
        # A naive datetime is taken to already be UTC, not local time.
        naive = FieldRecord(
            abbrev="ip.src",
            column_name="ip_src",
            ftype="FT_IPv4",
            multi=False,
            column_type="VARCHAR",
            materialized_at=UTC_NOW.replace(tzinfo=None),
        )
        register_fields(con, [naive])
        assert read_fields(con)[0].materialized_at == UTC_NOW


class TestCacheKeys:
    def make_record(self) -> CacheKeyRecord:
        return CacheKeyRecord(
            key="deadbeef",
            pcap_path="/caps/a.pcapng",
            pcap_fingerprint="size=12:head=aa:tail=bb",
            fields=("ip.src", "tcp.port"),
            dfilter="tcp.port == 80",
            tshark_version="4.6.7",
            argv=("tshark", "-r", "/caps/a.pcapng", "-Y", "tcp.port == 80"),
            created_at=UTC_NOW,
        )

    def test_round_trip(self, con: DuckDBPyConnection) -> None:
        record = self.make_record()
        record_cache_key(con, record)
        assert read_cache_key(con.cursor(), "deadbeef") == record

    def test_unfiltered_dfilter_is_none(self, con: DuckDBPyConnection) -> None:
        record = self.make_record()
        unfiltered = CacheKeyRecord(**{**record.__dict__, "dfilter": None})
        record_cache_key(con, unfiltered)
        assert read_cache_key(con, "deadbeef") == unfiltered

    def test_unknown_key_is_none(self, con: DuckDBPyConnection) -> None:
        assert read_cache_key(con, "nope") is None

    def test_fields_are_queryable_as_a_sql_list(self, con: DuckDBPyConnection) -> None:
        # fields/argv are native VARCHAR[] so #32's subset rule ("requested
        # fields are a subset of the materialized ones") is a SQL predicate
        # rather than a fetch-everything-and-decode scan.
        record_cache_key(con, self.make_record())
        hit = con.execute(
            "SELECT key FROM meta.cache_keys WHERE list_has_all(fields, ?)", [["ip.src"]]
        ).fetchall()
        assert hit == [("deadbeef",)]
        miss = con.execute(
            "SELECT key FROM meta.cache_keys WHERE list_has_all(fields, ?)", [["udp.port"]]
        ).fetchall()
        assert miss == []
        argv = con.execute("SELECT argv[1] FROM meta.cache_keys").fetchone()
        assert argv is not None
        assert argv[0] == "tshark"

    def test_empty_field_set_round_trips(self, con: DuckDBPyConnection) -> None:
        record = CacheKeyRecord(**{**self.make_record().__dict__, "fields": (), "argv": ()})
        record_cache_key(con, record)
        assert read_cache_key(con, "deadbeef") == record

    def test_rerecording_a_key_updates_it(self, con: DuckDBPyConnection) -> None:
        record = self.make_record()
        record_cache_key(con, record)
        record_cache_key(con, CacheKeyRecord(**{**record.__dict__, "tshark_version": "4.7.0"}))
        stored = read_cache_key(con, "deadbeef")
        assert stored is not None
        assert stored.tshark_version == "4.7.0"


class TestAddFieldColumn:
    def test_adds_a_column_to_pkts(self, con: DuckDBPyConnection) -> None:
        add_field_column(con, "tcp_port")
        assert "tcp_port" in column_names(con, "main", "pkts")

    def test_explicit_type_is_used(self, con: DuckDBPyConnection) -> None:
        add_field_column(con, "ip_src", "UINTEGER")
        rows = con.execute(
            "SELECT data_type FROM duckdb_columns() "
            "WHERE table_name = 'pkts' AND column_name = 'ip_src'"
        ).fetchall()
        assert rows[0][0] == "UINTEGER"

    def test_list_type_is_accepted(self, con: DuckDBPyConnection) -> None:
        add_field_column(con, "tcp_port", "UINTEGER[]")
        assert "tcp_port" in column_names(con, "main", "pkts")

    def test_duplicate_column_raises_workspace_error(self, con: DuckDBPyConnection) -> None:
        add_field_column(con, "tcp_port")
        with pytest.raises(WorkspaceError, match="tcp_port"):
            add_field_column(con, "tcp_port")

    def test_a_column_in_another_attached_database_is_not_a_duplicate(
        self, con: DuckDBPyConnection
    ) -> None:
        # duckdb_columns() spans every attached database, so the existence check
        # must be pinned to the current one — otherwise an unrelated workspace
        # attached alongside would make every column look like a duplicate.
        con.execute("ATTACH ':memory:' AS other")
        con.execute("USE other")
        create_schema(con)
        add_field_column(con, "tcp_port")
        con.execute("USE memory")
        add_field_column(con, "tcp_port")  # must not raise
        rows = con.execute(
            "SELECT count(*) FROM duckdb_columns() WHERE database_name = 'memory' "
            "AND schema_name = 'main' AND table_name = 'pkts' AND column_name = 'tcp_port'"
        ).fetchone()
        assert rows is not None
        assert rows[0] == 1

    def test_skeleton_column_is_refused_by_name(self, con: DuckDBPyConnection) -> None:
        # frame.number is the first field anyone asks for and find_collisions
        # calls it clean, so the refusal has to say "already the row key"
        # instead of the generic duplicate-column message.
        with pytest.raises(WorkspaceError, match="row key"):
            add_field_column(con, column_name("frame.number"))
        with pytest.raises(WorkspaceError, match="row key"):
            add_field_column(con, column_name("frame.time"))

    def test_hostile_column_name_cannot_inject(self, con: DuckDBPyConnection) -> None:
        hostile = 'evil"; DROP TABLE pkts; --'
        add_field_column(con, hostile)
        assert ("main", "pkts") in table_names(con)
        # The name must actually land as a column: a no-op would also leave
        # pkts standing.
        assert hostile in column_names(con, "main", "pkts")

    def test_hostile_sql_type_is_rejected(self, con: DuckDBPyConnection) -> None:
        with pytest.raises(ValueError, match="SQL type"):
            add_field_column(con, "x", "VARCHAR; DROP TABLE pkts")
        assert ("main", "pkts") in table_names(con)

    def test_a_trailing_newline_does_not_smuggle_a_second_line(
        self, con: DuckDBPyConnection
    ) -> None:
        # re.match stops at the first newline; the check must span the whole
        # string or a type can carry a second statement past it.
        with pytest.raises(ValueError, match="SQL type"):
            add_field_column(con, "x", "VARCHAR\n")
        assert ("main", "pkts") in table_names(con)
