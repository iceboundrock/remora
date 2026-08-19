"""Materialize integration suite over the tests/fixtures/ pcaps (issue #31).

Unlike ``tests/test_workspace_materialize.py``, which drives the pipeline with
a canned-line runner, this suite spawns a real tshark: it pins that the argv
the pipeline builds actually dissects, that a pushed ``-Y`` selects exactly the
rows tshark itself selects for that filter, that real ftype text survives the
values -> column codec round trip, and that a real multi-occurrence field
(``dns.qry.name``) lands as a list.

The filtered test's row set is compared against a *live* tshark run of the same
display filter rather than against frame numbers copied from
``tests/fixtures/README.md``: the point of an integration test here is that
Remora and tshark agree, which a hard-coded constant cannot show.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

from remora import DNS, IP, TCP
from remora.capture import _resolve_tshark
from remora.reader.process import TsharkProcess
from remora.workspace import (
    MaterializationMismatchError,
    Workspace,
    column_spec,
    detect_tshark_version,
    read_cache_key,
    read_cache_keys,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

# REMORA_REQUIRE_TSHARK (set in CI) turns "tshark missing" from a skip into a
# hard failure, so a broken CI install can never silently skip the suite.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


def tshark_frame_numbers(pcap: Path, dfilter: str) -> list[int]:
    """Frame numbers a raw tshark run selects for ``dfilter`` — the ground truth."""
    argv = [
        _resolve_tshark(None),
        "-r",
        str(pcap),
        "-Y",
        dfilter,
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    with TsharkProcess(argv) as process:
        return [int(line) for line in process if line.strip()]


class TestFilteredMaterialize:
    def test_filtered_materialize_matches_tshark_ground_truth(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            result = ws.materialize(TCP_MIXED, [IP.src, TCP.port], TCP.port == 443)
            # Pin the rendered filter, not just that one exists: comparing
            # against a live run of result.dfilter alone would pass just as
            # happily on a wrong-but-self-consistent filter.
            assert result.dfilter == "tcp.port == 443"
            expected = tshark_frame_numbers(TCP_MIXED, result.dfilter)
            with ws.read() as con:
                stored = [
                    row[0]
                    for row in con.execute(
                        "SELECT frame_number FROM main.pkts ORDER BY frame_number"
                    ).fetchall()
                ]
        # Non-empty guards against a vacuous pass: two empty lists are equal.
        assert expected
        assert stored == expected
        assert result.row_count == len(expected)

    def test_values_round_trip(self, tmp_path: Path) -> None:
        ip_src = column_spec("ip.src", "FT_IPv4", False)
        tcp_port = column_spec("tcp.port", "FT_UINT16", True)
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, [IP.src, TCP.port], TCP.port == 443)
            with ws.read() as con:
                rows = con.execute(
                    "SELECT ip_src, tcp_port, frame_time FROM main.pkts ORDER BY frame_number"
                ).fetchall()

        assert [ip_src.decode(row[0]) for row in rows] == [
            IPv4Address("10.0.0.1"),
            IPv4Address("10.0.0.2"),
        ]
        # Both directions of the flow carry both ports; order differs per row.
        for row in rows:
            assert set(tcp_port.decode(row[1])) == {51234, 443}
        # tests/fixtures/make_fixtures.py stamps frame i of tcp_mixed at
        # base_ts 1700000100 + i seconds and i * 1000 microseconds, so the two
        # selected frames (1 and 2) have exactly known timestamps. DuckDB
        # TIMESTAMP is timezone-naive by design (#26): the workspace stores
        # UTC and never lets a session time zone reshape it, so these are the
        # naive-UTC renderings of those epochs.
        assert [row[2] for row in rows] == [
            datetime(2023, 11, 14, 22, 15, 0),
            datetime(2023, 11, 14, 22, 15, 1, 1000),
        ]
        for row in rows:
            assert row[2].tzinfo is None


class TestUnfilteredMaterialize:
    def test_unfiltered_materialize_covers_absent_fields(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            result = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
            assert result.dfilter is None
            assert result.row_count == 5
            with ws.read() as con:
                rows = con.execute(
                    "SELECT frame_number, ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
                ).fetchall()
                stored_key = read_cache_key(con, result.cache_key.key)

        assert [row[0] for row in rows] == [1, 2, 3, 4, 5]
        # Frame 5 is ARP: no ip.*, no tcp.*. A scalar absence is NULL, a
        # multi-value absence is [] — never NULL in a list column.
        arp = rows[4]
        assert arp[1] is None
        assert arp[2] == []
        # Frame 4 is UDP/DNS: ip.src present, tcp.port absent.
        assert rows[3][1] == int(IPv4Address("10.0.0.1"))
        assert rows[3][2] == []

        assert stored_key is not None
        assert stored_key.tshark_version == detect_tshark_version(_resolve_tshark(None))
        assert stored_key.fields == ("ip.src", "tcp.port")
        assert stored_key.dfilter is None


class TestReuse:
    """#32's hit/backfill/refuse decision against a real dissection."""

    def test_identical_request_is_a_hit(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            first = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
            second = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
            with ws.read() as con:
                rows = con.execute("SELECT count(*) FROM main.pkts").fetchone()
        assert first.outcome == "materialized"
        assert second.outcome == "hit"
        assert second.cache_key == first.cache_key
        # The second call appended nothing: reuse, not a second run's rows
        # landing on top of the first's.
        assert rows is not None
        assert rows[0] == first.row_count

    def test_backfill_matches_a_one_shot_materialization(self, tmp_path: Path) -> None:
        incremental = tmp_path / "incremental.duckdb"
        with Workspace(incremental, mode="rw") as ws:
            ws.materialize(TCP_MIXED, [IP.src])
            with ws.read() as con:
                before = con.execute(
                    "SELECT frame_number, frame_time, ip_src FROM main.pkts ORDER BY frame_number"
                ).fetchall()
            backfilled = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
            with ws.read() as con:
                after = con.execute(
                    "SELECT frame_number, frame_time, ip_src FROM main.pkts ORDER BY frame_number"
                ).fetchall()
                incremental_rows = con.execute(
                    "SELECT frame_number, ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
                ).fetchall()

        one_shot_path = tmp_path / "one_shot.duckdb"
        with Workspace(one_shot_path, mode="rw") as ws:
            one_shot = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
            with ws.read() as con:
                one_shot_rows = con.execute(
                    "SELECT frame_number, ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
                ).fetchall()

        assert backfilled.outcome == "backfilled"
        assert [record.abbrev for record in backfilled.added_fields] == ["tcp.port"]
        # The columns that were already there are untouched by the backfill...
        assert after == before
        # ...and what the workspace holds afterwards — rows and cache key
        # alike — is exactly what materializing both fields at once produces.
        assert incremental_rows == one_shot_rows
        assert backfilled.cache_key.key == one_shot.cache_key.key

    def test_changed_dfilter_refused(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, [IP.src], TCP.port == 443)
            with pytest.raises(MaterializationMismatchError, match="display filter"):
                ws.materialize(TCP_MIXED, [IP.src], TCP.port == 80)
            with ws.read() as con:
                stored = read_cache_keys(con)
        assert len(stored) == 1
        assert stored[0].dfilter == "tcp.port == 443"


class TestMultiOccurrenceField:
    def test_multi_occurrence_field_from_real_dissection(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            result = ws.materialize(DNS_MULTI, [DNS.qry_name])
            assert result.row_count == 3
            with ws.read() as con:
                rows = con.execute(
                    "SELECT frame_number, dns_qry_name FROM main.pkts ORDER BY frame_number"
                ).fetchall()

        assert [row[0] for row in rows] == [1, 2, 3]
        # Frame 1 asks two questions in one packet; frame 3 is TCP, no dns.*.
        assert rows[0][1] == ["alpha.example", "beta.example"]
        assert rows[1][1] == ["gamma.example"]
        assert rows[2][1] == []
