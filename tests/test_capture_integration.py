"""End-to-end acceptance tests for issue #15: Capture over sample.pcap with real tshark.

This file is also the M1 quickstart snippet: it is type-checked by
``mypy --strict`` (the CI gate covers tests/), and the ``assert_type`` calls
pin the static type flow from ``FieldRef`` declarations to packet values.
``assert_type`` lines come BEFORE runtime asserts — an equality assert first
would narrow the type and break them.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from typing_extensions import assert_type

import remora.capture as capture_module
from remora import DNS, IP, TCP, UDP, Capture
from remora.fields import Packet
from remora.reader.process import TsharkProcess

DATA_DIR = Path(__file__).resolve().parent / "data"
PCAP = DATA_DIR / "sample.pcap"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed"),
]


class TestQuickstart:
    def test_pure_expr_query_returns_exactly_matching_packets(self) -> None:
        cap = Capture(PCAP).filter((IP.src == "10.0.0.1") & (TCP.port == 443))
        matched = list(cap)
        assert len(matched) == 1
        pkt = matched[0]
        src = pkt[IP].src
        ports = pkt[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src == IPv4Address("10.0.0.1")
        assert ports == (51234, 443)
        assert pkt[TCP].dstport == 443

    def test_no_match_is_empty(self) -> None:
        assert list(Capture(PCAP).filter(IP.src == "192.168.99.99")) == []

    def test_unfiltered_capture_yields_every_packet(self) -> None:
        assert len(list(Capture(PCAP))) == 3


class TestEkFallback:
    def test_expr_plus_lambda_takes_ek_path_end_to_end(self) -> None:
        cap = Capture(PCAP).filter(IP.src.present()).filter(lambda pkt: pkt[UDP].dstport == 53)
        assert cap.plan().mode == "ek"
        assert cap.plan().dfilter == "(ip.src)"
        matched = list(cap)
        assert len(matched) == 1
        names = matched[0][DNS].qry_name
        assert_type(names, tuple[str, ...])
        assert names == ("foo,bar.example",)


class TestProcessLifecycle:
    def test_early_break_terminates_tshark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        created: list[TsharkProcess] = []
        real = TsharkProcess

        def spy(argv: Sequence[str]) -> TsharkProcess:
            proc = real(argv)
            created.append(proc)
            return proc

        monkeypatch.setattr(capture_module, "TsharkProcess", spy)
        for pkt in Capture(PCAP):
            # Iteration is statically typed as Packet, not bare RawPacket.
            assert_type(pkt, Packet)
            break
        assert len(created) == 1
        # close() ran and reaped the child: a live or zombie process would
        # still poll() as None.
        assert created[0].returncode is not None
