"""Workspace storage schema tests (issue #25)."""

from __future__ import annotations

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
    from pathlib import Path

    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")


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
    def test_creates_all_core_tables(self, con: DuckDBPyConnection) -> None:
        assert table_names(con) >= {
            ("main", "pkts"),
            ("main", "streams"),
            ("main", "annotations"),
            ("meta", "info"),
            ("meta", "fields"),
            ("meta", "cache_keys"),
        }

    def test_pkts_skeleton_columns(self, con: DuckDBPyConnection) -> None:
        assert column_names(con, "main", "pkts") == ["frame_number", "frame_time"]

    def test_ddl_is_the_only_source(self) -> None:
        # Every table the schema creates is created by a statement in iter_ddl().
        ddl = "\n".join(iter_ddl())
        for table in (
            "pkts",
            "streams",
            "annotations",
            "meta.info",
            "meta.fields",
            "meta.cache_keys",
        ):
            assert table in ddl

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
