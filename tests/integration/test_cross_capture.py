"""Cross-capture correlation over ATTACHed workspaces (issue #37).

Three workspaces, all built by the real materialize pipeline:

* ``vantage_a`` — tcp_mixed.pcap, everything.
* ``vantage_b`` — tcp_mixed.pcap filtered to traffic *towards* 10.0.0.2, so it
  is a genuinely different row set that nonetheless saw the same hosts.
* ``elsewhere`` — dns_multi.pcap, whose 10.0.1.0/24 addresses share nothing
  with tcp_mixed's 10.0.0.0/24. The negative control: without it, a join that
  always matched would pass.
"""

from __future__ import annotations

import os
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

from remora.proto.ip import IP
from remora.proto.tcp import TCP
from remora.workspace import Workspace

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"


@pytest.fixture(scope="module")
def workspaces(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Three materialized workspaces, built once for the module."""
    root = tmp_path_factory.mktemp("cross_capture")
    paths = {
        "vantage_a": root / "vantage_a.duckdb",
        "vantage_b": root / "vantage_b.duckdb",
        "elsewhere": root / "elsewhere.duckdb",
    }
    with Workspace(paths["vantage_a"], mode="rw") as ws:
        assert ws.materialize(TCP_MIXED, [IP.src, IP.dst, TCP.port]).row_count == 5
    with Workspace(paths["vantage_b"], mode="rw") as ws:
        result = ws.materialize(TCP_MIXED, [IP.src, IP.dst, TCP.port], IP.dst == "10.0.0.2")
        assert result.row_count == 2  # frames 1 and 3
    with Workspace(paths["elsewhere"], mode="rw") as ws:
        assert ws.materialize(DNS_MULTI, [IP.src, IP.dst]).row_count == 3
    return paths


class TestAttachedWorkspaces:
    def test_multiple_workspaces_attach_read_only(self, workspaces: dict[str, Path]) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            assert ws.mode == "ro"
            ws.attach(workspaces["vantage_b"], "b")
            ws.attach(workspaces["elsewhere"], "elsewhere")
            assert list(ws.attachments) == ["b", "elsewhere"]
            with ws.read() as con:
                readonly = dict(
                    con.execute(
                        "SELECT database_name, readonly FROM duckdb_databases() "
                        "WHERE path IS NOT NULL AND database_name <> current_database()"
                    ).fetchall()
                )
                assert readonly == {"b": True, "elsewhere": True}

    def test_query_over_an_attached_workspace(self, workspaces: dict[str, Path]) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["vantage_b"], "b")
            assert [row.frame_number for row in ws.query()] == [1, 2, 3, 4, 5]
            assert [row.frame_number for row in ws.query(alias="b")] == [1, 3]
            sources = [row.get(IP.src) for row in ws.query(alias="b").select(IP.src)]
            assert sources == [IPv4Address("10.0.0.1"), IPv4Address("10.0.0.3")]


class TestCrossCaptureJoin:
    """The worked example: the same host seen from two vantage points."""

    def test_shared_hosts_are_found(self, workspaces: dict[str, Path]) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["vantage_b"], "b")
            with ws.read() as con:
                rows = con.execute(
                    """
                    SELECT a.ip_src, count(*) AS pairs
                    FROM main.pkts a
                    JOIN "b".main.pkts b ON a.ip_src = b.ip_src
                    GROUP BY a.ip_src
                    ORDER BY a.ip_src
                    """
                ).fetchall()
        # ip.src is FT_IPv4, stored as its UINTEGER integer form (#26).
        seen = {IPv4Address(int(value)) for value, _pairs in rows}
        assert seen == {IPv4Address("10.0.0.1"), IPv4Address("10.0.0.3")}

    def test_a_host_seen_only_at_one_vantage_point_is_not_shared(
        self, workspaces: dict[str, Path]
    ) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["vantage_b"], "b")
            with ws.read() as con:
                row = con.execute(
                    """
                    SELECT count(*) FROM "b".main.pkts b
                    WHERE b.ip_src = CAST(? AS UINTEGER)
                    """,
                    [int(IPv4Address("10.0.0.2"))],
                ).fetchone()
        assert row == (0,)  # 10.0.0.2 is only ever a destination at vantage B

    def test_disjoint_captures_share_nothing(self, workspaces: dict[str, Path]) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["elsewhere"], "elsewhere")
            with ws.read() as con:
                row = con.execute(
                    """
                    SELECT count(*) FROM main.pkts a
                    JOIN "elsewhere".main.pkts e ON a.ip_src = e.ip_src
                    """
                ).fetchone()
        assert row == (0,)

    def test_three_way_join_across_two_attachments(self, workspaces: dict[str, Path]) -> None:
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["vantage_b"], "b")
            ws.attach(workspaces["elsewhere"], "elsewhere")
            with ws.read() as con:
                row = con.execute(
                    """
                    SELECT count(DISTINCT a.ip_src)
                    FROM main.pkts a
                    JOIN "b".main.pkts b ON a.ip_src = b.ip_src
                    LEFT JOIN "elsewhere".main.pkts e ON a.ip_src = e.ip_src
                    WHERE e.frame_number IS NULL
                    """
                ).fetchone()
        assert row == (2,)


class TestAttachRefusalsEndToEnd:
    def test_incompatible_and_missing_files_are_refused(
        self, workspaces: dict[str, Path], tmp_path: Path
    ) -> None:
        from remora.workspace.errors import WorkspaceError

        with Workspace(workspaces["vantage_a"]) as ws:
            with pytest.raises(WorkspaceError, match="no workspace at"):
                ws.attach(tmp_path / "absent.duckdb", "gone")
            with pytest.raises(WorkspaceError, match="cannot attach"):
                ws.attach(TCP_MIXED, "pcap")  # a pcap is not a DuckDB database
            assert dict(ws.attachments) == {}

    def test_an_attached_workspace_cannot_be_written(self, workspaces: dict[str, Path]) -> None:
        duckdb = pytest.importorskip("duckdb")
        with Workspace(workspaces["vantage_a"]) as ws:
            ws.attach(workspaces["vantage_b"], "b")
            with ws.read() as con, pytest.raises(duckdb.Error, match="read-only"):
                con.execute('DELETE FROM "b".main.pkts')
