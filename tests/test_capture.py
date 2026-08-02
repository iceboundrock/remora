"""Unit tests for remora.capture — no tshark is spawned; TsharkProcess is faked."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import remora.capture as capture_module
from remora.capture import Capture, _build_argv, _resolve_tshark
from remora.fields import FieldRef
from remora.planner import make_plan
from remora.proto import IP, TCP
from remora.reader.fields_reader import UNIT_SEP

# Golden display-filter strings this module asserts plans/argv against.
DF_SRC = "(ip.src == 10.0.0.1)"
DF_PORT = "(tcp.port == 443)"
DF_SRC_AND_PORT = "(ip.src == 10.0.0.1) && (tcp.port == 443)"

#: Imported by tests/test_dfilter_validation.py so a real tshark accepts each
#: string this module puts into a tshark argv (#18). Any new `plan.dfilter`
#: golden asserted in this file must be added here too, or it goes unvalidated.
CAPTURE_DFILTER_GOLDENS: tuple[str, ...] = (DF_SRC, DF_PORT, DF_SRC_AND_PORT)


def ek_line(layers: dict[str, Any]) -> str:
    return json.dumps({"layers": layers})


#: Two data packets (each preceded by an ek index line, as real tshark emits).
EK_LINES = [
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.1"}, "tcp": {"tcp_tcp_port": ["51234", "443"]}}),
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.3"}, "udp": {"udp_udp_dstport": "53"}}),
]


class FakeProcess:
    """Stands in for TsharkProcess: canned stdout lines plus close bookkeeping."""

    def __init__(self, argv: Sequence[str], lines: Sequence[str]) -> None:
        self.argv = list(argv)
        self.lines = list(lines)
        self.closed = False

    def __iter__(self) -> Any:
        yield from self.lines

    def close(self) -> None:
        self.closed = True


class FakeTshark:
    """Factory installed in place of capture_module.TsharkProcess."""

    def __init__(self) -> None:
        self.lines: list[str] = list(EK_LINES)
        self.created: list[FakeProcess] = []

    def __call__(self, argv: Sequence[str]) -> FakeProcess:
        proc = FakeProcess(argv, self.lines)
        self.created.append(proc)
        return proc


@pytest.fixture
def fake_tshark(monkeypatch: pytest.MonkeyPatch) -> FakeTshark:
    factory = FakeTshark()
    monkeypatch.setattr(capture_module, "TsharkProcess", factory)
    return factory


class TestFilterBuilder:
    def test_filter_returns_new_capture(self) -> None:
        cap = Capture("x.pcap")
        filtered = cap.filter(IP.src == "10.0.0.1")
        assert filtered is not cap
        assert cap.plan().dfilter is None
        assert filtered.plan().dfilter == DF_SRC

    def test_filters_accumulate_across_calls(self) -> None:
        cap = Capture("x.pcap").filter(IP.src == "10.0.0.1").filter(TCP.port == 443)
        assert cap.plan().dfilter == DF_SRC_AND_PORT

    def test_filter_preserves_the_resolved_tshark_binary(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap", tshark="/opt/tshark").filter(IP.src == "10.0.0.1"))
        assert fake_tshark.created[0].argv[0] == "/opt/tshark"

    def test_m1_plans_are_ek_mode(self) -> None:
        # No projection API in M1: select is always None, so mode is always ek.
        assert Capture("x.pcap").filter(IP.src == "10.0.0.1").plan().mode == "ek"


class TestArgvAssembly:
    def test_ek_argv_with_dfilter(self) -> None:
        plan = make_plan([IP.src == "10.0.0.1"])
        argv = _build_argv("tshark", Path("x.pcap"), plan)
        assert argv[:3] == ["tshark", "-r", "x.pcap"]
        assert argv[3:5] == ["-Y", DF_SRC]
        assert argv[5:] == ["-T", "ek"]

    def test_ek_argv_without_dfilter(self) -> None:
        plan = make_plan([])
        argv = _build_argv("tshark", Path("x.pcap"), plan)
        assert argv == ["tshark", "-r", "x.pcap", "-T", "ek"]

    def test_fields_argv_projects_selected_fields(self) -> None:
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        plan = make_plan([TCP.port == 443], select=select)
        argv = _build_argv("tshark", Path("x.pcap"), plan)
        assert argv[3:5] == ["-Y", DF_PORT]
        assert argv[5:7] == ["-T", "fields"]
        assert argv[-2:] == ["-e", "ip.src"]

    def test_resolve_tshark_explicit_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TSHARK", "/env/tshark")
        assert _resolve_tshark("/explicit/tshark") == "/explicit/tshark"

    def test_resolve_tshark_env_then_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TSHARK", "/env/tshark")
        assert _resolve_tshark(None) == "/env/tshark"
        monkeypatch.delenv("TSHARK")
        assert _resolve_tshark(None) == "tshark"


class TestIteration:
    def test_unfiltered_yields_every_packet(self, fake_tshark: FakeTshark) -> None:
        packets = list(Capture("x.pcap"))
        assert len(packets) == 2
        assert packets[0].get_raw("ip.src") == ("10.0.0.1",)
        assert packets[1].get_raw("ip.src") == ("10.0.0.3",)

    def test_residual_lambda_filters_in_python(self, fake_tshark: FakeTshark) -> None:
        cap = Capture("x.pcap").filter(lambda pkt: pkt.get_raw("udp.dstport") == ("53",))
        packets = list(cap)
        assert len(packets) == 1
        assert packets[0].get_raw("ip.src") == ("10.0.0.3",)
        # The opaque lambda cannot be pushed down: no -Y in argv.
        assert "-Y" not in fake_tshark.created[0].argv

    def test_pushed_expr_lands_in_argv(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap").filter(IP.src == "10.0.0.1"))
        argv = fake_tshark.created[0].argv
        assert argv[argv.index("-Y") + 1] == DF_SRC

    def test_typed_access_on_yielded_packet(self, fake_tshark: FakeTshark) -> None:
        first = next(iter(Capture("x.pcap")))
        assert first[TCP].port == (51234, 443)

    def test_early_break_closes_process(self, fake_tshark: FakeTshark) -> None:
        for _pkt in Capture("x.pcap"):
            break
        assert fake_tshark.created[0].closed

    def test_exhaustion_closes_process(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap"))
        assert fake_tshark.created[0].closed

    def test_consumer_exception_closes_process(self, fake_tshark: FakeTshark) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            for _pkt in Capture("x.pcap"):
                raise RuntimeError("boom")
        assert fake_tshark.created[0].closed

    def test_fields_mode_plan_uses_fields_reader(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # M1's public surface never produces a fields-mode plan (select is
        # always None), so inject one to prove the execution branch works.
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        plan = make_plan([], select=select)
        monkeypatch.setattr(Capture, "plan", lambda self: plan)
        fake_tshark.lines = ["10.0.0.1", "10.0.0.3"]
        packets = list(Capture("x.pcap"))
        assert [pkt.get_raw("ip.src") for pkt in packets] == [("10.0.0.1",), ("10.0.0.3",)]
        assert fake_tshark.created[0].argv[3:5] == ["-T", "fields"]

    def test_residual_expr_applies_in_fields_mode(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Time comparisons are never pushed to a display filter, so this term
        # is a genuine residual Expr; the planner auto-adds its field to the
        # projection so the compiled predicate can read it from a FieldsRow.
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        when = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
        plan = make_plan([when >= datetime(2021, 7, 1, tzinfo=timezone.utc)], select=select)
        assert plan.mode == "fields"
        assert plan.dfilter is None
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time"]
        monkeypatch.setattr(Capture, "plan", lambda self: plan)
        fake_tshark.lines = [
            f"10.0.0.1{UNIT_SEP}1625097600.000000000",  # exactly July 2021: kept
            f"10.0.0.3{UNIT_SEP}1625097599.999999000",  # a hair earlier: dropped
        ]
        packets = list(Capture("x.pcap"))
        assert [pkt.get_raw("ip.src") for pkt in packets] == [("10.0.0.1",)]
