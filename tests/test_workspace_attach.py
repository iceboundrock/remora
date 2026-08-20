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
from remora.workspace.errors import SchemaVersionError, WorkspaceAliasError, WorkspaceError
from remora.workspace.schema import create_schema
from remora.workspace.workspace import Mode, Workspace

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

    def test_invalid_alias_is_refused_without_sql(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        peer = make_peer(tmp_path / "peer.duckdb")
        with pytest.raises(WorkspaceAliasError, match="not a valid workspace alias"):
            attach_database(con, Attachment("my peer", peer))
        # The failed attach left nothing behind.
        assert "my peer" not in attached_databases(con)


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

    def test_refuses_a_writable_alias(self, con: DuckDBPyConnection, tmp_path: Path) -> None:
        peer_path = make_peer(tmp_path / "peer.duckdb")
        # Attach it read-write on this connection (default ATTACH mode is read-write)
        con.execute(f"ATTACH '{peer_path}' AS w")
        # Try to apply it as read-only via apply_attachments
        with pytest.raises(WorkspaceAliasError, match="read-write"):
            apply_attachments(con, [Attachment("w", peer_path)])


def make_workspace(path: Path) -> Path:
    """A real workspace file created through the public opener."""
    with Workspace(path, mode="rw"):
        pass
    return path


class TestWorkspaceAttach:
    @pytest.mark.parametrize("mode", ["ro", "rw"])
    def test_attaches_and_records(self, tmp_path: Path, mode: Mode) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary, mode=mode) as ws:
            ws.attach(peer, "peer")
            assert dict(ws.attachments) == {"peer": Path(os.path.realpath(peer))}
            with ws.read() as connection:
                assert connection.execute('SELECT count(*) FROM "peer".main.pkts').fetchone() == (
                    0,
                )

    @pytest.mark.parametrize("mode", ["ro", "rw"])
    def test_attachment_is_read_only_in_either_mode(self, tmp_path: Path, mode: Mode) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary, mode=mode) as ws:
            ws.attach(peer, "peer")
            with ws.read() as connection:
                assert attached_databases(connection)["peer"][1] is True
                with pytest.raises(duckdb.Error, match="read-only"):
                    connection.execute('INSERT INTO "peer".main.pkts (frame_number) VALUES (1)')

    def test_write_connection_also_carries_the_attachment(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            with ws.write() as connection:
                assert connection.execute('SELECT count(*) FROM "peer".main.pkts').fetchone() == (
                    0,
                )
                with pytest.raises(duckdb.Error, match="read-only"):
                    connection.execute('INSERT INTO "peer".main.pkts (frame_number) VALUES (1)')

    def test_replay_survives_rw_short_lived_connections(self, tmp_path: Path) -> None:
        # rw mode holds no connection between operations, so the DuckDB instance
        # (and its attachments) dies in between; only replay makes this pass.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            for _ in range(3):
                with ws.read() as connection:
                    assert connection.execute(
                        'SELECT count(*) FROM "peer".main.pkts'
                    ).fetchone() == (0,)

    def test_multiple_workspaces_attach(self, tmp_path: Path) -> None:
        a = make_workspace(tmp_path / "a.duckdb")
        b = make_workspace(tmp_path / "b.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            ws.attach(a, "a")
            ws.attach(b, "b")
            assert list(ws.attachments) == ["a", "b"]
            with ws.read() as connection:
                assert set(attached_databases(connection)) == {"a", "b"}

    def test_detach(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            ws.attach(peer, "peer")
            ws.detach("peer")
            assert dict(ws.attachments) == {}
            with ws.read() as connection:
                assert "peer" not in attached_databases(connection)

    def test_detach_unknown_alias(self, tmp_path: Path) -> None:
        primary = make_workspace(tmp_path / "ws.duckdb")
        with (
            Workspace(primary) as ws,
            pytest.raises(WorkspaceAliasError, match="no workspace is attached as 'peer'"),
        ):
            ws.detach("peer")

    def test_close_clears_attachments(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        ws = Workspace(make_workspace(tmp_path / "ws.duckdb")).open()
        ws.attach(peer, "peer")
        ws.close()
        assert dict(ws.attachments) == {}

    def test_attach_requires_an_open_workspace(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        ws = Workspace(make_workspace(tmp_path / "ws.duckdb"))
        with pytest.raises(WorkspaceError, match="not open"):
            ws.attach(peer, "peer")


class TestWorkspaceAttachRefusals:
    def test_duplicate_alias(self, tmp_path: Path) -> None:
        a = make_workspace(tmp_path / "a.duckdb")
        b = make_workspace(tmp_path / "b.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            ws.attach(a, "peer")
            with pytest.raises(WorkspaceAliasError, match="already attached"):
                ws.attach(b, "peer")
            assert dict(ws.attachments) == {"peer": Path(os.path.realpath(a))}

    def test_invalid_alias(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with (
            Workspace(primary) as ws,
            pytest.raises(WorkspaceAliasError, match="not a valid workspace alias"),
        ):
            ws.attach(peer, "my peer")

    def test_reserved_alias(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary) as ws, pytest.raises(WorkspaceAliasError, match="reserved"):
            ws.attach(peer, "main")

    def test_alias_naming_the_primarys_own_database(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary) as ws, pytest.raises(WorkspaceAliasError, match="own database"):
            ws.attach(peer, "ws")

    def test_missing_file(self, tmp_path: Path) -> None:
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            with pytest.raises(WorkspaceError, match="no workspace at"):
                ws.attach(tmp_path / "absent.duckdb", "peer")
            assert dict(ws.attachments) == {}

    def test_incompatible_schema_version_names_the_path(self, tmp_path: Path) -> None:
        stale = make_peer(tmp_path / "old.duckdb", version="1")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            with pytest.raises(SchemaVersionError, match="cannot attach") as excinfo:
                ws.attach(stale, "old")
            message = str(excinfo.value)
            assert str(stale) in message
            assert "'old'" in message
            assert "older remora" in message
            assert dict(ws.attachments) == {}

    def test_foreign_file_names_the_path(self, tmp_path: Path) -> None:
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"not a duckdb database" * 8)
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            with pytest.raises(WorkspaceError, match="cannot attach") as excinfo:
                ws.attach(junk, "junk")
            assert str(junk) in str(excinfo.value)
            assert dict(ws.attachments) == {}

    def test_attaching_the_workspaces_own_file(self, tmp_path: Path) -> None:
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary) as ws, pytest.raises(WorkspaceError, match="own file"):
            ws.attach(primary, "self")

    def test_attaching_the_workspaces_own_file_through_a_symlink(self, tmp_path: Path) -> None:
        primary = make_workspace(tmp_path / "ws.duckdb")
        alias_path = tmp_path / "link.duckdb"
        alias_path.symlink_to(primary)
        with Workspace(primary) as ws, pytest.raises(WorkspaceError, match="own file"):
            ws.attach(alias_path, "self")


class TestCompactIsUnaffectedByAttachments:
    def test_compact_copies_only_the_primary(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary, mode="rw") as ws:
            ws.attach(peer, "peer")
            ws.compact()
            with ws.read() as connection:
                # The compacted file is a workspace, and holds no trace of the peer.
                assert connection.execute("SELECT count(*) FROM main.pkts").fetchone() == (0,)
                names = connection.execute(
                    "SELECT count(*) FROM duckdb_tables() WHERE database_name = current_database()"
                ).fetchone()
                assert names == (6,)
