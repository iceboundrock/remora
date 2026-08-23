"""End-to-end integration suite over the tests/fixtures/ pcaps (issue #20).

Covers the pipeline dimensions this issue owns: pushdown-only queries,
residual-lambda ek fallback, exact -T fields projection, multi-value
(any-occurrence) matching, and absent-field semantics. DSL ``!=`` parity
against raw tshark ``!(x == v)`` is deliberately NOT asserted here — that
check lives in the #18 dfilter-validation suite.

M1's Capture has no projection/select API, so the fields-mode test drives
the same pipeline Capture would (make_plan -> argv -> TsharkProcess ->
FieldsReader) with an explicit ``select``.
"""

from __future__ import annotations

import os
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from typing_extensions import assert_type

from remora import DNS, IP, TCP, UDP, Capture
from remora.capture import _build_argv, _resolve_tshark
from remora.fields import FieldNotProjectedError, Packet
from remora.planner import make_plan
from remora.reader.fields_reader import FieldsReader, escaping_is_reversible
from remora.reader.process import TsharkProcess, probe_tshark_version

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


class TestPushdownOnly:
    def test_pure_expr_is_fully_pushed_and_filters_in_tshark(self) -> None:
        cap = Capture(TCP_MIXED).filter(TCP.port == 8080)
        plan = cap.plan()
        assert plan.dfilter == "(tcp.port == 8080)"
        assert plan.residual is None
        matched = list(cap)
        assert len(matched) == 1
        assert matched[0][IP].src == IPv4Address("10.0.0.3")

    def test_multi_value_field_matches_on_any_occurrence(self) -> None:
        # Frame 1 carries tcp.port = (51234, 443): src and dst differ, and a
        # query on EITHER occurrence must match it (Wireshark any-occurrence
        # semantics). Both directions of the flow carry both values.
        by_srcport = list(Capture(TCP_MIXED).filter(TCP.port == 51234))
        by_dstport = list(Capture(TCP_MIXED).filter(TCP.port == 443))
        assert len(by_srcport) == 2
        assert len(by_dstport) == 2
        ports = by_srcport[0][TCP].port
        assert_type(ports, tuple[int, ...])
        assert ports == (51234, 443)

    def test_absent_field_packets_are_excluded_not_errors(self) -> None:
        # tcp_mixed also contains a DNS/UDP frame and an ARP frame with no
        # tcp.* fields at all; a tcp.port filter must drop them silently.
        matched = list(Capture(TCP_MIXED).filter(TCP.port == 53534))
        assert matched == []


class TestAbsentFieldAccess:
    def test_absent_fields_read_as_none_and_empty_tuple(self) -> None:
        packets = list(Capture(TCP_MIXED))
        assert len(packets) == 5
        arp = packets[4]  # frame 5: ARP — no ip.*, no tcp.*
        src = arp[IP].src
        ports = arp[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src is None
        assert ports == ()


class TestEkFallback:
    def test_residual_lambda_forces_ek_and_filters_in_python(self) -> None:
        cap = Capture(DNS_MULTI).filter(IP.src.present()).filter(lambda pkt: pkt[UDP].dstport == 53)
        plan = cap.plan()
        assert plan.mode == "ek"
        assert plan.dfilter == "(ip.src)"
        assert plan.residual is not None
        matched = list(cap)
        # Frame 3 is TCP: udp.dstport reads None there, the lambda returns
        # False, and only the two DNS frames survive.
        assert len(matched) == 2

    def test_multi_occurrence_dns_qry_name_round_trips(self) -> None:
        matched = list(
            Capture(DNS_MULTI).filter(IP.src.present()).filter(lambda pkt: pkt[UDP].dstport == 53)
        )
        names = matched[0][DNS].qry_name
        assert_type(names, tuple[str, ...])
        assert names == ("alpha.example", "beta.example")
        assert matched[1][DNS].qry_name == ("gamma.example",)

    def test_residual_lambda_matches_any_occurrence_of_multi_value_field(self) -> None:
        # Same row set as the pushed-down TCP.port == 443 query, but matched
        # by the Python predicate backend over the multi-value tuple.
        matched = list(Capture(TCP_MIXED).filter(lambda pkt: 443 in pkt[TCP].port))
        assert len(matched) == 2


class TestFieldsProjection:
    def test_projection_returns_exactly_the_requested_fields(self) -> None:
        plan = make_plan((TCP.dstport == 443,), select=[IP.src, TCP.port])
        assert plan.mode == "fields"
        assert plan.dfilter == "(tcp.dstport == 443)"
        assert plan.projection is not None
        names = [ref.name for ref in plan.projection]
        assert names == ["ip.src", "tcp.port"]

        tshark = _resolve_tshark(None)
        argv = _build_argv(tshark, TCP_MIXED, plan)
        process = TsharkProcess(argv)
        try:
            # unescape_values mirrors what Capture itself passes (#74): this
            # test stands in for Capture's fields path, so leaving it at the
            # safe default would quietly exercise a configuration Capture
            # never uses. No value here carries a control byte, so the flag
            # cannot change the assertions — which is the point: the pipeline
            # is the same one, not merely a similar one.
            rows: list[Packet] = list(
                FieldsReader(
                    process,
                    plan.projection,
                    unescape_values=escaping_is_reversible(probe_tshark_version(tshark)),
                )
            )
        finally:
            process.close()

        assert len(rows) == 1  # only frame 1 has tcp.dstport == 443
        row = rows[0]
        src = row[IP].src
        ports = row[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src == IPv4Address("10.0.0.1")
        assert ports == (51234, 443)  # multi-value survives -T fields

        # Exactly the requested fields: anything else was not projected and
        # must raise rather than silently reading as absent.
        with pytest.raises(FieldNotProjectedError):
            row.get_raw("ip.dst")
