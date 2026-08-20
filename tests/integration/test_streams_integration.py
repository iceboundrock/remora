"""Sessionization integration suite over the tests/fixtures/ pcaps (issue #33).

``tests/test_workspace_streams.py`` drives ``build_streams`` over hand-inserted
rows; this suite materializes a real capture with a real tshark and then checks
the rollups against **tshark's own conversation statistics** — ``tshark -q -z
conv,tcp`` and ``-z conv,udp`` — parsed out of a live run rather than copied
into a constant. That is the point of an integration test here: a hard-coded
expectation cannot show that Remora and tshark count the same thing.

They can only agree if ``byte_count`` means what tshark's Bytes column means,
which is frame bytes on the wire — hence ``frame.len`` as the source field.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("duckdb")

from remora import IP, TCP, UDP
from remora.capture import _resolve_tshark
from remora.fields import FieldRef
from remora.workspace import MissingStreamFieldsError, Workspace

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

# frame.len has no generated protocol module (frame is not in codegen.toml's
# core set), so the byte-count source is spelled out as a field ref.
FRAME_LEN: FieldRef[int] = FieldRef("frame.len", "FT_UINT32", False)

# Every prerequisite build_streams() needs, in the form a caller passes them.
# Annotated because the refs carry different parsed types (int, IPv4Address),
# which a bare list literal would unify to object.
STREAM_FIELDS: list[FieldRef[Any]] = [
    FRAME_LEN,
    IP.src,
    IP.dst,
    TCP.stream,
    TCP.srcport,
    TCP.dstport,
    UDP.stream,
    UDP.srcport,
    UDP.dstport,
]

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


@dataclass(frozen=True)
class Conversation:
    """One row of tshark's ``-z conv,<proto>`` table — the ground truth.

    Attributes:
        endpoint_a: Address and port tshark lists first, i.e. the initiator's.
        endpoint_b: The other end.
        frames: Total frames in both directions.
        byte_count: Total bytes in both directions — frame bytes on the wire.
        duration: Seconds between the conversation's first and last frame.
    """

    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    frames: int
    byte_count: int
    duration: float


def parse_endpoint(text: str) -> tuple[str, int]:
    address, _, port = text.rpartition(":")
    return address, int(port)


def tshark_conversations(pcap: Path, protocol: str) -> dict[tuple[str, int], Conversation]:
    """Run ``tshark -q -z conv,<protocol>`` and parse its table.

    Keyed by the initiator endpoint, so a comparison checks the direction of
    the endpoints too, not merely the unordered pair.
    """
    output = subprocess.run(
        [_resolve_tshark(None), "-r", str(pcap), "-q", "-z", f"conv,{protocol}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    conversations: dict[tuple[str, int], Conversation] = {}
    for line in output.splitlines():
        if "<->" not in line:
            continue
        left, _, right = line.partition("<->")
        # addrB:portB, <- frames, <- bytes, unit, -> frames, -> bytes, unit,
        # total frames, total bytes, unit, relative start, duration
        parts = right.split()
        assert len(parts) == 12, f"unexpected conv row shape: {line!r}"
        # tshark renders large byte counts as "1 kB"; the fixtures are far
        # below that, and an assertion beats silently comparing kilobytes.
        assert parts[3] == parts[6] == parts[9] == "bytes", f"unexpected byte unit: {line!r}"
        conversation = Conversation(
            endpoint_a=parse_endpoint(left.split()[0]),
            endpoint_b=parse_endpoint(parts[0]),
            frames=int(parts[7]),
            byte_count=int(parts[8]),
            duration=float(parts[11]),
        )
        conversations[conversation.endpoint_a] = conversation
    return conversations


def remora_conversations(ws: Workspace, protocol: str) -> dict[tuple[str, int], Conversation]:
    """The same shape, read back out of ``main.streams``."""
    with ws.read() as con:
        rows = con.execute(
            """
            SELECT src_addr, src_port, dst_addr, dst_port, pkt_count, byte_count,
                   epoch(last_time) - epoch(first_time)
            FROM main.streams WHERE protocol = ? ORDER BY stream_id
            """,
            [protocol],
        ).fetchall()
    conversations: dict[tuple[str, int], Conversation] = {}
    for src_addr, src_port, dst_addr, dst_port, pkt_count, byte_count, duration in rows:
        conversation = Conversation(
            endpoint_a=(str(IPv4Address(src_addr)), src_port),
            endpoint_b=(str(IPv4Address(dst_addr)), dst_port),
            frames=pkt_count,
            byte_count=byte_count,
            duration=float(duration),
        )
        conversations[conversation.endpoint_a] = conversation
    return conversations


def assert_matches_tshark(ws: Workspace, pcap: Path, protocol: str, *, expected: int) -> None:
    """Compare every rollup against tshark's own conversation statistics."""
    ground_truth = tshark_conversations(pcap, protocol)
    # Non-empty and of the expected size, so two empty dicts cannot pass and a
    # tshark that grew a different table shape is caught rather than skipped.
    assert len(ground_truth) == expected
    built = remora_conversations(ws, protocol)
    assert built.keys() == ground_truth.keys()
    for endpoint, truth in ground_truth.items():
        mine = built[endpoint]
        assert mine.endpoint_b == truth.endpoint_b
        assert mine.frames == truth.frames
        assert mine.byte_count == truth.byte_count
        # tshark prints the duration to four decimals.
        assert mine.duration == pytest.approx(truth.duration, abs=1e-4)


class TestAgainstTsharkConversations:
    def test_tcp_mixed_rollups_match_tshark(self, tmp_path: Path) -> None:
        # tcp_mixed.pcap holds two TCP conversations, one UDP/DNS query and an
        # ARP frame that belongs to no stream at all.
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, STREAM_FIELDS)
            result = ws.build_streams()
            assert result.tcp_streams == 2
            assert result.udp_streams == 1
            assert result.total == 3
            assert_matches_tshark(ws, TCP_MIXED, "tcp", expected=2)
            assert_matches_tshark(ws, TCP_MIXED, "udp", expected=1)

    def test_dns_multi_rollups_match_tshark(self, tmp_path: Path) -> None:
        # The other way round: two UDP conversations and one TCP.
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(DNS_MULTI, STREAM_FIELDS)
            result = ws.build_streams()
            assert result.tcp_streams == 1
            assert result.udp_streams == 2
            assert_matches_tshark(ws, DNS_MULTI, "tcp", expected=1)
            assert_matches_tshark(ws, DNS_MULTI, "udp", expected=2)


class TestJoiningPacketsToStreams:
    def test_pkts_join_to_streams_by_stream_id(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, STREAM_FIELDS)
            ws.build_streams()
            with ws.read() as con:
                joined = con.execute(
                    """
                    SELECT p.frame_number, s.stream_id, s.pkt_count
                    FROM main.pkts p
                    JOIN main.streams s
                      ON s.protocol = 'tcp' AND s.stream_id = p.tcp_stream
                    ORDER BY p.frame_number
                    """
                ).fetchall()
                # The endpoint representation is the pkts one, so the address
                # join is a plain integer comparison.
                endpoints = con.execute(
                    "SELECT count(*) FROM main.streams s JOIN main.pkts p "
                    "ON p.frame_number = s.first_frame AND p.ip_src = s.src_addr "
                    "AND p.ip_dst = s.dst_addr"
                ).fetchone()
        # Frames 1 and 2 are stream 0, frame 3 is stream 1; 4 (UDP) and 5 (ARP)
        # carry no tcp.stream and drop out of the join.
        assert joined == [(1, 0, 2), (2, 0, 2), (3, 1, 1)]
        assert endpoints is not None
        assert endpoints[0] == 3

    def test_udp_pkts_join_to_streams_by_stream_id(self, tmp_path: Path) -> None:
        # dns_multi.pcap is the UDP-heavy fixture: frames 1 and 2 are two
        # separate DNS queries (udp streams 0 and 1), frame 3 is TCP and drops
        # out. The udp join has its own columns on both sides, so the tcp test
        # above does not cover it.
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(DNS_MULTI, STREAM_FIELDS)
            ws.build_streams()
            with ws.read() as con:
                joined = con.execute(
                    """
                    SELECT p.frame_number, s.stream_id, s.pkt_count, s.src_port
                    FROM main.pkts p
                    JOIN main.streams s
                      ON s.protocol = 'udp' AND s.stream_id = p.udp_stream
                    ORDER BY p.frame_number
                    """
                ).fetchall()
                endpoints = con.execute(
                    "SELECT count(*) FROM main.streams s JOIN main.pkts p "
                    "ON p.frame_number = s.first_frame AND p.ip_src = s.src_addr "
                    "AND p.ip_dst = s.dst_addr WHERE s.protocol = 'udp'"
                ).fetchone()
        assert joined == [(1, 0, 1, 50001), (2, 1, 1, 50002)]
        assert endpoints is not None
        assert endpoints[0] == 2


class TestRebuild:
    def test_rebuilding_is_idempotent(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, STREAM_FIELDS)
            first = ws.build_streams()
            with ws.read() as con:
                before = con.execute(
                    "SELECT * FROM main.streams ORDER BY protocol, stream_id"
                ).fetchall()
            second = ws.build_streams()
            with ws.read() as con:
                after = con.execute(
                    "SELECT * FROM main.streams ORDER BY protocol, stream_id"
                ).fetchall()
        assert second == first
        assert before
        assert after == before


class TestPrerequisites:
    def test_a_partial_materialization_names_the_missing_fields(self, tmp_path: Path) -> None:
        # A real capture materialized with the tcp half only: the refusal must
        # name the udp abbrevs, not surface as a DuckDB "column not found".
        tcp_only: list[FieldRef[Any]] = [
            FRAME_LEN,
            IP.src,
            IP.dst,
            TCP.stream,
            TCP.srcport,
            TCP.dstport,
        ]
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(TCP_MIXED, tcp_only)
            with pytest.raises(MissingStreamFieldsError) as excinfo:
                ws.build_streams()
        assert excinfo.value.missing == ("udp.dstport", "udp.srcport", "udp.stream")
