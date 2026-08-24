"""Attach policy and the ATTACH/DETACH/replay SQL (issue #37)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import remora.workspace.attach as attach_module
import remora.workspace.workspace as workspace_module
from remora.workspace.attach import (
    RESERVED_ALIASES,
    Attachment,
    apply_attachments,
    attach_database,
    attached_databases,
    detach_database,
    file_stamp,
    is_duplicate_database_error,
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

    def test_detach_in_rw_mode_opens_no_connection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # rw mode holds no connection between operations, so nothing is attached
        # and there is nothing to DETACH from: the record is the whole of the
        # attachment there. Opening a connection for it bought nothing and could
        # fail (a compact in flight) on an operation whose record deletion had
        # already happened.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")

            def forbidden(self: Workspace) -> Iterator[DuckDBPyConnection]:
                raise AssertionError("detach must open no connection in rw mode")

            monkeypatch.setattr(Workspace, "read", forbidden)
            ws.detach("peer")
            assert dict(ws.attachments) == {}

    def test_detach_keeps_the_record_when_the_statement_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ro mode does issue the DETACH, on the held connection, and drops the
        # record only afterwards: a failure must not report itself on an
        # operation that already took effect.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            ws.attach(peer, "peer")

            def boom(con: DuckDBPyConnection, alias: str) -> None:
                raise RuntimeError("DETACH failed")

            monkeypatch.setattr(workspace_module, "detach_database", boom)
            with pytest.raises(RuntimeError, match="DETACH failed"):
                ws.detach("peer")
            assert dict(ws.attachments) == {"peer": Path(os.path.realpath(peer))}
            # Still live on the connection, exactly as the record says.
            with ws.read() as connection:
                assert "peer" in attached_databases(connection)

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

    def test_alias_differing_only_in_case(self, tmp_path: Path) -> None:
        """DuckDB compares database names case-insensitively, so 'Peer' is 'peer'.

        Without the fold this reached the ATTACH and came back as DuckDB's
        generic ``database with name "peer" already exists`` wrapped in a bare
        WorkspaceError, where the same-case duplicate gets the named type.
        """
        a = make_workspace(tmp_path / "a.duckdb")
        b = make_workspace(tmp_path / "b.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            ws.attach(a, "peer")
            with pytest.raises(WorkspaceAliasError, match="differs only in case"):
                ws.attach(b, "Peer")
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

    @pytest.mark.skipif(os.name != "posix", reason="hard links need privileges on Windows")
    @pytest.mark.parametrize("mode", ["ro", "rw"])
    def test_attaching_the_workspaces_own_file_through_a_hard_link(
        self, tmp_path: Path, mode: Mode
    ) -> None:
        # realpath preserves a hard link's own name, so a pathname comparison
        # lets the primary attach itself: in ro mode that takes a shared read
        # lock on the file the held connection already owns, and a later
        # Workspace(primary, mode="rw") fails on the configuration conflict.
        primary = make_workspace(tmp_path / "ws.duckdb")
        alias_path = tmp_path / "hard.duckdb"
        os.link(primary, alias_path)
        with Workspace(primary, mode=mode) as ws:
            with pytest.raises(WorkspaceError, match="own file"):
                ws.attach(alias_path, "self")
            assert dict(ws.attachments) == {}


class TestReplayFailuresAreTyped:
    """#100 M1: a failed replay must not escape read()/write() as a duckdb error.

    ``read()``/``write()`` replay recorded attachments onto every connection they
    open, so an attachment DuckDB can no longer honour — a peer deleted, or held
    read-write by another process — fails *every* operation, including ones that
    have nothing to do with the attachment. Measured before the fix: deleting an
    attached peer made ``write()`` raise a bare ``_duckdb.IOException`` reading
    ``IO Error: Cannot open database "…" in read-only mode: database does not
    exist``, which names neither the alias nor what to do about it.
    """

    def test_write_wraps_a_replay_failure(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            with pytest.raises(WorkspaceError) as caught, ws.write():
                pass  # pragma: no cover - the body is never reached
        message = str(caught.value)
        assert "peer" in message
        assert str(Path(os.path.realpath(peer))) in message
        assert "detach it to continue" in message
        assert not isinstance(caught.value, duckdb.Error)

    def test_read_wraps_a_replay_failure(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            with pytest.raises(WorkspaceError, match="cannot re-attach 'peer'"), ws.read():
                pass  # pragma: no cover - the body is never reached

    def test_an_operation_unrelated_to_the_attachment_is_wrapped_too(self, tmp_path: Path) -> None:
        # The whole point: replay runs on every connection, so an annotation
        # write that never mentions the peer fails on it as well.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            with pytest.raises(WorkspaceError, match="detach it to continue"):
                ws.add_annotation(scope="packet", target_id=1, key="k", value="v")

    def test_a_typed_refusal_is_not_rewrapped(self, tmp_path: Path) -> None:
        # The translation is for failures that have no name of their own; an
        # alias the instance holds pointing somewhere else already reads as a
        # WorkspaceAliasError and must keep that type through the wrapper.
        a = make_workspace(tmp_path / "a.duckdb")
        b = make_workspace(tmp_path / "b.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary, mode="rw") as ws:
            ws.attach(a, "peer")
            # A caller's own connection keeps the instance alive and plants the
            # alias on it, pointing at the other file, read-write.
            outside = duckdb.connect(str(primary))
            try:
                outside.execute(f"ATTACH '{b}' AS peer")
                with pytest.raises(WorkspaceAliasError, match="already attached to"), ws.read():
                    pass  # pragma: no cover - the body is never reached
            finally:
                outside.close()

    def test_detaching_restores_the_workspace(self, tmp_path: Path) -> None:
        # The remedy the message names actually works.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            ws.detach("peer")
            with ws.write() as connection:
                assert connection.execute("SELECT count(*) FROM main.pkts").fetchone() == (0,)


class TestCrossObjectAliasCollision:
    """#100 M2, second shape: two Workspace objects on one file.

    Same-process connections to one file share a DuckDB instance, so an alias
    ``w1`` attached is live for ``w2`` as well — but ``w2._attachments`` is
    empty, so ``Workspace.attach``'s own duplicate check (which compares against
    *this* workspace's record) cannot see it and the collision is caught only by
    DuckDB's binder. Decision D7 of #37 assigns a colliding alias to
    ``WorkspaceAliasError``; before the fix this shape came back as a generic
    ``WorkspaceError`` wrapping ``Binder Error: Failed to attach database:
    database with name "peer" already exists``.
    """

    def test_second_workspace_reusing_an_alias_raises_alias_error(self, tmp_path: Path) -> None:
        a = make_workspace(tmp_path / "a.duckdb")
        b = make_workspace(tmp_path / "b.duckdb")
        primary = make_workspace(tmp_path / "ws.duckdb")
        with Workspace(primary) as w1, Workspace(primary) as w2:
            w1.attach(a, "peer")
            with pytest.raises(WorkspaceAliasError, match="already exists"):
                w2.attach(b, "peer")
            assert dict(w2.attachments) == {}

    def test_duckdbs_duplicate_message_is_pinned(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        """The classifier reads DuckDB's message, so pin the message itself.

        A duckdb upgrade that rewords this fails here loudly, rather than
        silently degrading the refusal back to a generic ``WorkspaceError``.
        """
        attach_database(con, Attachment("peer", make_peer(tmp_path / "peer.duckdb")))
        other = make_peer(tmp_path / "other.duckdb")
        with pytest.raises(duckdb.Error) as caught:
            con.execute(f"ATTACH '{other}' AS peer (READ_ONLY)")
        assert 'database with name "peer" already exists' in str(caught.value)
        assert is_duplicate_database_error(caught.value)

    @pytest.mark.parametrize(
        "message",
        [
            "IO Error: Cannot open database",
            "Binder Error: Failed to attach database: something else entirely",
            "",
            # The name must be quote-delimited: a bare `.*` bridged unrelated
            # text and classified prose like this as an alias collision.
            "IO Error: Cannot open database with name resolution failure; "
            "the lock file already exists",
            # Right shape, wrong object kind.
            'Binder Error: table with name "peer" already exists',
        ],
    )
    def test_classifier_ignores_other_failures(self, message: str) -> None:
        assert not is_duplicate_database_error(RuntimeError(message))

    @pytest.mark.parametrize("quote", ['"', "'", "`"])
    def test_classifier_accepts_the_quoting_styles(self, quote: str) -> None:
        # A quote-style change is not a different error; a deeper rewording is
        # meant to fail test_duckdbs_duplicate_message_is_pinned instead.
        message = f"Binder Error: database with name {quote}peer{quote} already exists"
        assert is_duplicate_database_error(RuntimeError(message))

    def test_real_non_duplicate_attach_failures_are_not_classified(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        """Real ATTACH failures, not synthetic strings — none is a collision.

        The pin test above guards a duckdb *rewording*; this guards the other
        direction, a false positive turning some unrelated ATTACH failure into a
        ``WorkspaceAliasError`` that tells the caller to rename their alias.
        """
        junk = tmp_path / "junk.duckdb"
        junk.write_bytes(b"not a duckdb database at all\n" * 64)
        attempts = {
            "missing path": str(tmp_path / "absent.duckdb"),
            "not a duckdb file": str(junk),
            "a directory": str(tmp_path),
        }
        for label, target in attempts.items():
            with pytest.raises(duckdb.Error) as caught:
                con.execute(f"ATTACH '{target}' AS a (READ_ONLY)")
            assert not is_duplicate_database_error(caught.value), f"{label}: {caught.value}"

    def test_a_non_duckdb_file_stays_a_plain_workspace_error(self, tmp_path: Path) -> None:
        # End to end: the classification must not widen Workspace.attach's
        # generic refusal into an alias refusal.
        junk = tmp_path / "junk.duckdb"
        junk.write_bytes(b"not a duckdb database at all\n" * 64)
        with Workspace(make_workspace(tmp_path / "ws.duckdb")) as ws:
            with pytest.raises(WorkspaceError) as caught:
                ws.attach(junk, "peer")
            assert not isinstance(caught.value, WorkspaceAliasError)


class TestReplayRevalidation:
    """#100: a peer replaced at the same path is revalidated, never trusted.

    ``apply_attachments`` skips ``check_compatible`` to keep a catalog read off
    the hot path, which was sound only for a file that had not changed. In rw
    mode nothing is attached between operations and nothing holds the peer's
    lock, so the file can be replaced at the same path; before the fix the
    replacement was re-attached blind, and a foreign one surfaced as the raw
    ``Catalog Error: … schema "meta" does not exist`` that ``attach_database``'s
    refusal exists to prevent. The cheap close is an identity+mtime stamp
    recorded at attach time and one ``stat`` per attachment per connection.
    """

    def test_attach_records_the_peers_stamp(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            recorded = ws._attachments["peer"]
        assert recorded.stamp is not None
        assert recorded.stamp == file_stamp(Path(os.path.realpath(peer)))

    def test_foreign_replacement_is_refused_on_replay(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            # A DuckDB database that is not a remora workspace, built the way
            # TestAttachDatabase builds one: no DDL, so no layout name is even
            # reachable from this file (see test_workspace_schema.py's rules).
            foreign = duckdb.connect(str(peer))
            foreign.execute("SELECT 1")
            foreign.close()
            with pytest.raises(SchemaVersionError, match="not a remora workspace"), ws.read():
                pass  # pragma: no cover - the body is never reached

    def test_stale_version_replacement_is_refused_on_replay(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            make_peer(peer, version="1")
            with pytest.raises(SchemaVersionError) as caught, ws.read():
                pass  # pragma: no cover - the body is never reached
        message = str(caught.value)
        assert "cannot re-attach 'peer'" in message
        assert "older remora" in message

    def test_refusal_leaves_no_alias_attached(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            peer.unlink()
            make_peer(peer, version="1")
            with pytest.raises(SchemaVersionError), ws.read():
                pass  # pragma: no cover - the body is never reached
            ws.detach("peer")
            with ws.read() as connection:
                assert "peer" not in attached_databases(connection)

    def test_an_unchanged_peer_is_not_revalidated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The whole point of the stamp: the common case still costs one stat,
        # not the catalog read apply_attachments was written to avoid.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")

            def forbidden(connection: DuckDBPyConnection, *, database: str | None = None) -> None:
                raise AssertionError("an unchanged peer must not be revalidated")

            monkeypatch.setattr(attach_module, "check_compatible", forbidden)
            with ws.read() as connection:
                assert connection.execute('SELECT count(*) FROM "peer".main.pkts').fetchone() == (
                    0,
                )

    def test_an_attachment_without_a_stamp_is_revalidated(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        # A caller building an Attachment by hand gets the safe default: no
        # stamp means "cannot prove it is unchanged", so it is revalidated.
        peer_path = make_peer(tmp_path / "peer.duckdb", version="1")
        with pytest.raises(SchemaVersionError, match="older remora"):
            apply_attachments(con, [Attachment("peer", peer_path)])
        assert "peer" not in attached_databases(con)

    def test_an_unstattable_peer_is_revalidated_not_trusted(
        self, con: DuckDBPyConnection, tmp_path: Path
    ) -> None:
        # A peer that cannot be stat'ed has no comparable stamp, so it takes the
        # revalidating path; here the ATTACH itself is what fails, which is the
        # documented degradation — never a blind re-attach.
        gone = tmp_path / "gone.duckdb"
        stamp = file_stamp(make_peer(gone))
        gone.unlink()
        assert file_stamp(gone) is None
        with pytest.raises(duckdb.Error):
            apply_attachments(con, [Attachment("peer", gone, stamp)])

    def test_file_stamp_moves_when_the_file_is_replaced(self, tmp_path: Path) -> None:
        path = make_peer(tmp_path / "peer.duckdb")
        before = file_stamp(path)
        path.unlink()
        make_peer(path)
        assert before is not None
        assert file_stamp(path) != before


def rewrite_in_place(target: Path, source: Path) -> None:
    """Give ``target`` ``source``'s bytes without changing ``target``'s inode.

    Writing through an open handle rather than replacing the file is what makes
    the blind spot below deterministic: it is a property of the *stamp*, not of
    whatever write strategy DuckDB happens to use.
    """
    payload = source.read_bytes()
    with open(target, "r+b") as handle:
        handle.truncate(0)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


class TestStampBlindSpot:
    """#100: the stamp's accepted residual, pinned rather than claimed closed.

    ``(st_dev, st_ino, st_mtime_ns)`` answers "same file, untouched?" for one
    ``stat``, and buys that cheapness the way ``cachekey.fingerprint_pcap`` buys
    its own — with a residual that is named and executable rather than
    aspirational (``TestFingerprint::test_middle_change_does_not_flip`` and
    ``TestInheritedFingerprintBlindSpot`` are the precedent, companion test
    included). Here the residual is an in-place rewrite at the same inode whose
    mtime is *restored*: ``os.utime``, an archiver replaying timestamps, or a
    coarse-mtime filesystem. Closing it would need a content digest of the peer
    on every connection open — the catalog read this gate exists to avoid, only
    dearer — so it is accepted, and a caller who cannot rule it out should
    detach and attach again, which revalidates unconditionally.
    """

    def test_same_inode_rewrite_with_restored_mtime_is_attached_blind(self, tmp_path: Path) -> None:
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            recorded = ws._attachments["peer"].stamp
            before = os.stat(peer)

            # A v1 workspace — what check_compatible exists to refuse — written
            # into the peer's own inode, with the timestamp put back afterwards.
            rewrite_in_place(peer, make_peer(tmp_path / "v1.duckdb", version="1"))
            assert file_stamp(peer) != recorded, "the rewrite must move the mtime"
            os.utime(peer, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert file_stamp(peer) == recorded, "the blind spot must be armed"

            # No revalidation, so the incompatible peer is attached and usable.
            with ws.read() as connection:
                assert connection.execute(
                    "SELECT value FROM \"peer\".meta.info WHERE key = 'schema_version'"
                ).fetchone() == ("1",)

    def test_the_same_rewrite_without_restoring_the_mtime_is_refused(self, tmp_path: Path) -> None:
        # The companion: identical edit, timestamp left alone. The blind spot is
        # the restored mtime specifically, not in-place rewrites generally.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            rewrite_in_place(peer, make_peer(tmp_path / "v1.duckdb", version="1"))
            with pytest.raises(SchemaVersionError, match="cannot re-attach 'peer'"), ws.read():
                pass  # pragma: no cover - the body is never reached

    def test_detaching_and_attaching_again_revalidates_unconditionally(
        self, tmp_path: Path
    ) -> None:
        # The documented remedy for a caller who cannot rule the blind spot out.
        peer = make_workspace(tmp_path / "peer.duckdb")
        with Workspace(make_workspace(tmp_path / "ws.duckdb"), mode="rw") as ws:
            ws.attach(peer, "peer")
            before = os.stat(peer)
            rewrite_in_place(peer, make_peer(tmp_path / "v1.duckdb", version="1"))
            os.utime(peer, ns=(before.st_atime_ns, before.st_mtime_ns))
            ws.detach("peer")
            with pytest.raises(SchemaVersionError, match="older remora"):
                ws.attach(peer, "peer")


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


class TestPackageExports:
    def test_new_names_are_exported(self) -> None:
        import remora.workspace as pkg

        for name in (
            "Attachment",
            "WorkspaceAliasError",
            "apply_attachments",
            "attach_database",
            "attached_databases",
            "detach_database",
            "file_stamp",
            "is_duplicate_database_error",
            "qualify",
            "validate_alias",
        ):
            assert name in pkg.__all__, name
            assert getattr(pkg, name) is not None
