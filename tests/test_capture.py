"""Unit tests for remora.capture — no tshark is spawned; TsharkProcess is faked."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import assert_type

import remora.capture as capture_module
from dfilter_corpus import DF_PORT, DF_SRC, DF_SRC_AND_PORT
from remora.capture import Capture, _build_argv, _resolve_tshark
from remora.fields import FieldNotProjectedError, FieldRef
from remora.planner import make_plan
from remora.proto import IP, TCP
from remora.reader.fields_reader import OCC_SEP, UNIT_SEP

# The DF_* golden display-filter strings asserted below live in
# dfilter_corpus.py (with CAPTURE_DFILTER_GOLDENS, which feeds them to a real
# tshark in tests/test_dfilter_validation.py); add new ones there.


def ek_line(layers: dict[str, Any]) -> str:
    return json.dumps({"layers": layers})


#: Two data packets (each preceded by an ek index line, as real tshark emits).
EK_LINES = [
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.1"}, "tcp": {"tcp_tcp_port": ["51234", "443"]}}),
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.3"}, "udp": {"udp_udp_dstport": "53"}}),
]


#: Handed to every ``Capture`` these tests drive into fields mode. Iteration in
#: that mode resolves the binary's version (the #74 unescaping gate), and the
#: probe that resolves it spawns a real ``tshark --version`` — the one
#: subprocess this file must not leave to chance. Any version above the 4.4
#: gate does; no fixture line below carries an escaped byte, so the flag it
#: selects cannot change an assertion.
FIELDS_VERSION = "4.4.5"

#: Frame-level fields have no generated protocol class, so this is a hand-built
#: ref — and it is exactly what the residual cases want: dfilter.py refuses to
#: push a time literal, so a term built from it is a guaranteed residual Expr.
#: ``frame.time_epoch`` rather than ``frame.time``, matching what a live run
#: would ask for: the planner projects the abbrev verbatim and ``-e frame.time``
#: renders a locale-shaped string where ``FT_ABSOLUTE_TIME`` parses epoch
#: seconds, so the canned columns below would be unreachable output.
FRAME_TIME = FieldRef[datetime]("frame.time_epoch", "FT_ABSOLUTE_TIME", False)

#: The instant the fields-mode fixture rows straddle, to the nanosecond.
_JULY_2021 = datetime(2021, 7, 1, tzinfo=timezone.utc)


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

    def test_filtering_alone_does_not_reach_fields_mode(self) -> None:
        # Pushing a conjunct to -Y decides nothing about the reader: the mode
        # follows the projection alone. A filter names fields, but naming a
        # field tshark filters on says nothing about which fields the consumer
        # will go on to read, so an unselected Capture still gets whole packets.
        assert Capture("x.pcap").filter(IP.src == "10.0.0.1").plan().mode == "ek"


class TestSelectBuilder:
    """``select()`` as a builder: immutability, accumulation, and what it carries."""

    def test_select_returns_new_capture(self) -> None:
        cap = Capture("x.pcap")
        projected = cap.select(IP.src)
        assert projected is not cap
        # The original is not merely a different object, it is still the
        # unprojected query it was: no select() at all is what ek mode means.
        assert cap.plan().mode == "ek"
        assert cap.plan().projection is None
        assert projected.plan().mode == "fields"

    def test_selects_accumulate_across_calls(self) -> None:
        plan = Capture("x.pcap").select(IP.src).select(TCP.port).plan()
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "tcp.port"]

    def test_filter_and_select_commute(self) -> None:
        # Terms and projection are accumulated into two independent tuples, so
        # the order the two builders are called in cannot reach the plan. Pin
        # it, because a shared clone helper is exactly where they could start
        # interfering with each other.
        term = TCP.port == 443
        first = Capture("x.pcap").filter(term).select(IP.src).plan()
        second = Capture("x.pcap").select(IP.src).filter(term).plan()
        assert first.dfilter == second.dfilter == DF_PORT
        assert first.mode == second.mode == "fields"
        assert first.projection is not None
        assert second.projection is not None
        assert [ref.name for ref in first.projection] == [ref.name for ref in second.projection]

    def test_select_with_no_fields_is_a_no_op(self) -> None:
        # An empty projection is not "project nothing": -T fields with no -e
        # is a degenerate argv that emits one blank line per packet. Empty and
        # absent are deliberately one state, and that state is ek — so a
        # zero-argument select() leaves the Capture exactly where it was.
        cap = Capture("x.pcap").select()
        assert cap.plan().mode == "ek"
        assert cap.plan().projection is None
        assert repr(cap) == repr(Capture("x.pcap"))

    def test_duplicate_field_names_collapse_keeping_first_named_order(self) -> None:
        # -e ip.src twice would give the row two identical columns, so the
        # planner dedups by field NAME (FieldRefs are unhashable by design).
        # First-named wins, so a repeat cannot reorder the columns a reader
        # already agreed on.
        plan = Capture("x.pcap").select(IP.src, TCP.port).select(IP.src).plan()
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "tcp.port"]

    def test_select_preserves_the_resolved_tshark_binary(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap", tshark="/opt/tshark", tshark_version=FIELDS_VERSION).select(IP.src))
        assert fake_tshark.created[0].argv[0] == "/opt/tshark"

    def test_select_carries_the_explicit_tshark_version(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The version memo has to survive the clone or a select() would throw
        # away an explicit tshark_version= and probe the binary anyway — which
        # is unobservable in the plan but spawns a subprocess and can answer
        # differently. A probe that raises is how the absence of one is seen.
        def explode(tshark: str) -> str | None:
            raise AssertionError(f"probed {tshark} despite an explicit tshark_version=")

        monkeypatch.setattr(capture_module, "probe_tshark_version", explode)
        fake_tshark.lines = ["10.0.0.1"]
        cap = Capture("x.pcap", tshark_version=FIELDS_VERSION).select(IP.src)
        assert [pkt.get_raw("ip.src") for pkt in cap] == [("10.0.0.1",)]


class TestProjectionDecidesMode:
    """The #105 acceptance pin: a projection is what makes a plan fields-mode."""

    def test_a_projection_plans_fields_mode_and_no_projection_plans_ek(self) -> None:
        projected = Capture("x.pcap").select(IP.src, TCP.port).plan()
        assert projected.mode == "fields"
        assert projected.projection is not None
        assert [ref.name for ref in projected.projection] == ["ip.src", "tcp.port"]

        bare = Capture("x.pcap").plan()
        assert bare.mode == "ek"
        assert bare.projection is None

    def test_an_opaque_callable_beside_a_projection_still_plans_ek(self) -> None:
        # Nothing bounds the fields an arbitrary lambda reads — it gets the
        # whole packet and may ask it anything — so an opaque term forces ek
        # however precise the caller's own projection is. The select() is
        # honoured only in the sense that every field it names is readable;
        # it buys no -T fields run, and plan().mode is where that shows.
        cap = Capture("x.pcap").select(IP.src).filter(lambda pkt: pkt.get_raw("udp.dstport") != ())
        plan = cap.plan()
        assert plan.mode == "ek"
        assert plan.projection is None

    def test_pushed_conjunct_fields_are_not_projected(self) -> None:
        # tcp.port was filtered on by tshark itself, so the row need not carry
        # it: projecting every field a filter mentions would be over-projection
        # the caller never asked to pay for.
        plan = Capture("x.pcap").select(IP.src).filter(TCP.port == 443).plan()
        assert plan.dfilter == DF_PORT
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src"]

    def test_residual_expr_fields_are_projected_automatically(self) -> None:
        # The mirror image: a residual Expr is evaluated in Python against the
        # row, so its fields MUST be in the projection or the predicate has
        # nothing to read. The caller names only what they read themselves.
        plan = Capture("x.pcap").select(IP.src).filter(FRAME_TIME >= _JULY_2021).plan()
        assert plan.dfilter is None
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time_epoch"]


class TestRepr:
    def test_repr_renders_all_when_unprojected(self) -> None:
        assert repr(Capture("x.pcap")) == "<Capture 'x.pcap' terms=0 select=all>"

    def test_repr_renders_the_projection(self) -> None:
        cap = Capture("x.pcap").filter(IP.src == "10.0.0.1").select(IP.src, TCP.port)
        assert repr(cap) == "<Capture 'x.pcap' terms=1 select=ip.src, tcp.port>"


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

    def test_select_drives_the_fields_reader_end_to_end(self, fake_tshark: FakeTshark) -> None:
        # The whole point of #105: select() alone reaches the fields branch of
        # __iter__ — no injected plan — so argv carries -T fields with one -e
        # per projected column in projection order, and the rows the
        # FieldsReader yields parse back through the same descriptors ek rows
        # would have.
        fake_tshark.lines = [
            f"10.0.0.1{UNIT_SEP}51234{OCC_SEP}443",
            f"10.0.0.3{UNIT_SEP}53",
        ]
        cap = Capture("x.pcap", tshark_version=FIELDS_VERSION).select(IP.src, TCP.port)
        packets = list(cap)
        argv = fake_tshark.created[0].argv
        assert argv[3:5] == ["-T", "fields"]
        assert [argv[i + 1] for i, arg in enumerate(argv) if arg == "-e"] == ["ip.src", "tcp.port"]
        assert [pkt[IP].src for pkt in packets] == [
            IPv4Address("10.0.0.1"),
            IPv4Address("10.0.0.3"),
        ]
        assert [pkt[TCP].port for pkt in packets] == [(51234, 443), (53,)]

    def test_injected_fields_plan_still_drives_the_fields_reader(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # __iter__ branches on the plan, never on _select, so a plan handed in
        # from outside the builder reaches the same reader. This is the seam
        # tests and callers holding their own make_plan() result rely on; the
        # public route is covered by the select() test above.
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        plan = make_plan([], select=select)
        monkeypatch.setattr(Capture, "plan", lambda self: plan)
        fake_tshark.lines = ["10.0.0.1", "10.0.0.3"]
        packets = list(Capture("x.pcap", tshark_version=FIELDS_VERSION))
        assert [pkt.get_raw("ip.src") for pkt in packets] == [("10.0.0.1",), ("10.0.0.3",)]
        assert fake_tshark.created[0].argv[3:5] == ["-T", "fields"]

    def test_residual_expr_applies_in_fields_mode(self, fake_tshark: FakeTshark) -> None:
        # Time comparisons are never pushed to a display filter, so this term
        # is a genuine residual Expr; the planner auto-adds its field to the
        # projection so the compiled predicate can read it from a FieldsRow —
        # a field the caller never selected and never reads themselves.
        cap = Capture("x.pcap", tshark_version=FIELDS_VERSION).select(IP.src)
        cap = cap.filter(FRAME_TIME >= _JULY_2021)
        plan = cap.plan()
        assert plan.mode == "fields"
        assert plan.dfilter is None
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time_epoch"]
        fake_tshark.lines = [
            f"10.0.0.1{UNIT_SEP}1625097600.000000000",  # exactly July 2021: kept
            f"10.0.0.3{UNIT_SEP}1625097599.999999000",  # a hair earlier: dropped
        ]
        packets = list(cap)
        assert [pkt.get_raw("ip.src") for pkt in packets] == [("10.0.0.1",)]


class TestFieldsModeAbsence:
    """Absence in a projected row, and the one thing a projection adds to it.

    ``FieldNotProjectedError`` is not an absence answer: it says the caller
    never asked for the field, which is a query bug rather than a fact about
    the packet. Absence proper is unchanged from ek mode — ``()`` / ``None`` /
    ``()`` — and never an exception.
    """

    def test_unprojected_field_raises_rather_than_reading_as_absent(
        self, fake_tshark: FakeTshark
    ) -> None:
        fake_tshark.lines = [f"10.0.0.1{UNIT_SEP}443"]
        packet = next(
            iter(Capture("x.pcap", tshark_version=FIELDS_VERSION).select(IP.src, TCP.port))
        )
        with pytest.raises(FieldNotProjectedError, match=r"ip\.dst"):
            packet.get_raw("ip.dst")

    def test_empty_column_is_absence_not_an_error(self, fake_tshark: FakeTshark) -> None:
        # tshark prints an empty column for a field the packet does not carry,
        # which is the same absence an ek packet expresses by omitting the key:
        # () from get_raw, None from scalar access, () from multi access.
        fake_tshark.lines = [UNIT_SEP]  # both columns empty
        packet = next(
            iter(Capture("x.pcap", tshark_version=FIELDS_VERSION).select(IP.src, TCP.port))
        )
        src = packet[IP].src
        ports = packet[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert packet.get_raw("ip.src") == ()
        assert packet.get_raw("tcp.port") == ()
        assert src is None
        assert ports == ()
