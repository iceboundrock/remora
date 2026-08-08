"""Workspace storage schema tests (issue #25)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from remora.workspace.errors import SchemaVersionError
from remora.workspace.schema import (
    SCHEMA_VERSION,
    check_compatible,
    create_schema,
    iter_ddl,
    read_schema_version,
)

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_MODULE = REPO_ROOT / "src" / "remora" / "workspace" / "schema.py"

# Matches a DDL statement head. "\s+" is a literal backslash-s in this source,
# so this pattern does not match its own definition.
DDL_STATEMENT = re.compile(r"CREATE\s+(?:TABLE|SCHEMA|VIEW|INDEX)\b", re.IGNORECASE)

EXPECTED_TABLES = {
    ("main", "pkts"),
    ("main", "streams"),
    ("main", "annotations"),
    ("meta", "info"),
    ("meta", "fields"),
    ("meta", "cache_keys"),
}


def files_declaring_ddl() -> set[Path]:
    """Every .py file under src/ and tests/ that contains a DDL statement head."""
    found: set[Path] = set()
    for tree in (REPO_ROOT / "src", REPO_ROOT / "tests"):
        for path in tree.rglob("*.py"):
            raw = path.read_bytes()
            # Cheap prefilter: the generated proto tree is ~1 MB and has no DDL.
            if b"create" not in raw.lower():
                continue
            if DDL_STATEMENT.search(raw.decode("utf-8", errors="replace")):
                found.add(path)
    return found


@pytest.fixture
def con() -> DuckDBPyConnection:
    """An in-memory DuckDB connection with the workspace schema created."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    return connection


def table_names(connection: DuckDBPyConnection) -> set[tuple[str, str]]:
    rows = connection.execute("SELECT schema_name, table_name FROM duckdb_tables()").fetchall()
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
        # schema.py is the one file in src/ and tests/ allowed to contain DDL.
        assert files_declaring_ddl() == {SCHEMA_MODULE}

    def test_schema_module_keeps_all_ddl_in_the_constant(self) -> None:
        # Within schema.py, every DDL statement belongs to iter_ddl() — none is
        # built inline by a helper (the risk when #31 adds add_field_column).
        in_source = len(DDL_STATEMENT.findall(SCHEMA_MODULE.read_text(encoding="utf-8")))
        in_constant = sum(len(DDL_STATEMENT.findall(statement)) for statement in iter_ddl())
        assert in_source == in_constant > 0

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

    def test_missing_catalog_is_not_a_workspace(self) -> None:
        blank = duckdb.connect(":memory:")
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            check_compatible(blank)

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
