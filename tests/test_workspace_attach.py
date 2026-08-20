"""Attach policy and the ATTACH/DETACH/replay SQL (issue #37)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from remora.workspace.attach import (
    RESERVED_ALIASES,
    Attachment,
    apply_attachments,
    attach_database,
    attached_databases,
    detach_database,
    validate_alias,
)
from remora.workspace.errors import SchemaVersionError, WorkspaceAliasError
from remora.workspace.schema import create_schema

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")


def make_peer(path: Path, version: str | None = None) -> Path:
    """A real workspace file, optionally downgraded to another schema version."""
    con = duckdb.connect(str(path))
    try:
        create_schema(con)
        if version is not None:
            con.execute("UPDATE meta.info SET value = ? WHERE key = 'schema_version'", [version])
    finally:
        con.close()
    return path


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


class TestValidateAlias:
    @pytest.mark.parametrize("alias", ["peer", "_p", "peer2", "A_1"])
    def test_accepts_identifier_shapes(self, alias: str) -> None:
        validate_alias(alias)

    @pytest.mark.parametrize("alias", ["", "1peer", "peer-1", "my peer", 'we"ird', "peer.x"])
    def test_refuses_non_identifiers(self, alias: str) -> None:
        with pytest.raises(WorkspaceAliasError, match="not a valid workspace alias"):
            validate_alias(alias)

    @pytest.mark.parametrize("alias", ["main", "temp", "system", "MAIN", "Temp"])
    def test_refuses_reserved_names(self, alias: str) -> None:
        with pytest.raises(WorkspaceAliasError, match="reserved"):
            validate_alias(alias)

    def test_reserved_set_is_lowercase(self) -> None:
        assert frozenset({"main", "temp", "system"}) == RESERVED_ALIASES


class TestAttachDatabase:
    def test_attaches_read_only(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        attach_database(con, Attachment("peer", make_peer(tmp_path / "peer.duckdb")))
        live = attached_databases(con)
        assert live["peer"] == (os.path.realpath(tmp_path / "peer.duckdb"), True)

    def test_attached_tables_are_reachable(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        attach_database(con, Attachment("peer", make_peer(tmp_path / "peer.duckdb")))
        assert con.execute('SELECT count(*) FROM "peer".main.pkts').fetchone() == (0,)
        assert con.execute('SELECT count(*) FROM "peer".meta.fields').fetchone() == (0,)

    def test_writes_to_an_attached_database_are_refused(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        attach_database(con, Attachment("peer", make_peer(tmp_path / "peer.duckdb")))
        with pytest.raises(duckdb.Error, match="read-only"):
            con.execute('INSERT INTO "peer".main.pkts (frame_number) VALUES (1)')

    def test_incompatible_version_is_refused_and_detached(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        stale = make_peer(tmp_path / "old.duckdb", version="1")
        with pytest.raises(SchemaVersionError, match="older remora"):
            attach_database(con, Attachment("old", stale))
        # The failed attach left nothing behind.
        assert "old" not in attached_databases(con)

    def test_foreign_database_is_refused_and_detached(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        blank = tmp_path / "blank.duckdb"
        other = duckdb.connect(str(blank))
        other.execute("SELECT 1")
        other.close()
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            attach_database(con, Attachment("blank", blank))
        assert "blank" not in attached_databases(con)


class TestDetachDatabase:
    def test_round_trip(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        attach_database(con, Attachment("peer", make_peer(tmp_path / "peer.duckdb")))
        detach_database(con, "peer")
        assert "peer" not in attached_databases(con)

    def test_detaching_what_is_not_attached_is_silent(self, con: DuckDBPyConnection) -> None:
        detach_database(con, "peer")  # no raise: DuckDB has no DETACH IF EXISTS


class TestApplyAttachments:
    def test_attaches_everything_once(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        wanted = [
            Attachment("a", make_peer(tmp_path / "a.duckdb")),
            Attachment("b", make_peer(tmp_path / "b.duckdb")),
        ]
        apply_attachments(con, wanted)
        assert set(attached_databases(con)) == {"a", "b"}

    def test_is_idempotent(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        wanted = [Attachment("a", make_peer(tmp_path / "a.duckdb"))]
        apply_attachments(con, wanted)
        apply_attachments(con, wanted)
        assert set(attached_databases(con)) == {"a"}

    def test_refuses_an_alias_pointing_somewhere_else(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        attach_database(con, Attachment("a", make_peer(tmp_path / "a.duckdb")))
        other = Attachment("a", make_peer(tmp_path / "other.duckdb"))
        with pytest.raises(WorkspaceAliasError, match="already attached to"):
            apply_attachments(con, [other])
