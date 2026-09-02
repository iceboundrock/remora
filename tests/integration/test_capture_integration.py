"""End-to-end acceptance tests for issue #15: Capture over sample.pcap with real tshark.

This file is also the M1 quickstart snippet: it is type-checked by
``mypy --strict`` (the CI gate covers tests/), and the ``assert_type`` calls
pin the static type flow from ``FieldRef`` declarations to packet values.
``assert_type`` lines come BEFORE runtime asserts — an equality assert first
would narrow the type and break them.

``TestProjectedPath`` extends that to issue #105's ``select()``: the same
queries run through ``-T fields`` instead of ``-T ek``. Every value asserted
there is an address, a port or an epoch timestamp — deliberately, because
tshark's ``-T fields`` value escaping changed in 4.4 and ``Capture`` probes the
binary to decide whether to invert it (see ``reader/fields_reader``). None of
those value shapes contains an escapable byte, so the assertions read the same
on CI's stock 4.2.2 as on a current build. Anything escaping-sensitive belongs
in ``tests/integration/test_control_chars.py``, which is version-aware.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Sequence
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from typing_extensions import assert_type

import remora.capture as capture_module
from remora import DNS, IP, TCP, UDP, Capture
from remora.fields import FieldNotProjectedError, FieldRef, Packet
from remora.reader.process import TsharkProcess

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PCAP = DATA_DIR / "sample.pcap"

# sample.pcap, as tshark dissects it — the ground truth every assertion below
# is grounded in:
#   frame 1  ip 10.0.0.1 -> 10.0.0.2, tcp 51234 -> 443, epoch 1700000000
#   frame 2  ARP: no IP layer at all, and so no ip.src and no tcp.port
#   frame 3  ip 10.0.0.3 -> 10.0.0.53, udp 40000 -> 53 (DNS), epoch 1700000002
# Frames 2 and 3 are what make absence testable in a projection: 2 is missing
# both projected fields, 3 only the transport one.

#: There is no generated ``FRAME`` protocol class, so frame-level fields are
#: hand-built refs. ``frame.number`` is ``FT_UINT32`` in tshark's own ``-G
#: fields`` declaration.
FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)

#: ``frame.time_epoch``, not ``frame.time`` — and the distinction is load
#: bearing rather than stylistic. The planner projects an abbrev verbatim, and
#: ``-e frame.time`` renders a human-readable, locale- and timezone-shaped
#: string ("Nov 14, 2023 14:13:20.000000000 PST") where ``FT_ABSOLUTE_TIME``'s
#: parser reads epoch seconds, so a live ``frame.time`` column raises
#: ``ValueError`` on conversion. ``materialize.py`` makes the same choice for
#: the same reason.
FRAME_TIME = FieldRef[datetime]("frame.time_epoch", "FT_ABSOLUTE_TIME", False)

#: Frame 3's arrival time (epoch 1700000002), used as a residual boundary that
#: keeps exactly the last frame.
FRAME_3_TIME = datetime(2023, 11, 14, 22, 13, 22, tzinfo=timezone.utc)

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
        # ``close()`` sets ``_closed`` unconditionally on its first call, so this
        # is a direct witness that cleanup ran on the early break. It is the
        # load-bearing assert: ``returncode`` alone proves nothing here, because
        # tshark writes all 3 packets into the pipe buffer and exits on its own
        # regardless of whether anything closed it.
        assert created[0]._closed is True
        # And the child was reaped rather than left running (poll() is None only
        # while it is still alive).
        assert created[0].returncode is not None


class TestProjectedPath:
    """Issue #105's ``select()`` against a live tshark: the ``-T fields`` branch.

    Until #105 the planner's fields mode was unreachable from the public
    surface, so every one of these paths had only ever run against canned
    stdout. What a real binary adds here is that the argv remora builds is one
    tshark actually accepts, and that its columnar output carries the same
    values through the descriptor contract that ``-T ek`` NDJSON does.
    """

    def test_projected_run_yields_the_same_frames_as_the_ek_run(self) -> None:
        # The headline claim: switching a query to -T fields changes how the
        # bytes arrive, not which packets do. Both sides run the same pushed
        # display filter against the same capture; the fields side additionally
        # has to frame, split and decode columns.
        term = IP.src.present()
        ek = Capture(PCAP).filter(term)
        projected = Capture(PCAP).select(FRAME_NUMBER, IP.src, TCP.port).filter(term)
        assert ek.plan().mode == "ek"
        assert projected.plan().mode == "fields"
        # Same -Y either way: the projection changes the reader, not pushdown.
        assert ek.plan().dfilter == projected.plan().dfilter == "(ip.src)"

        def rows(cap: Capture) -> list[tuple[tuple[str, ...], ...]]:
            return [
                (pkt.get_raw("frame.number"), pkt.get_raw("ip.src"), pkt.get_raw("tcp.port"))
                for pkt in cap
            ]

        # Compared as raw occurrences rather than converted values, so a
        # framing or splitting bug in the fields reader cannot be masked by a
        # converter that happens to normalize both sides to the same object.
        assert rows(projected) == rows(ek)
        # And not vacuously: two empty lists would also compare equal.
        assert rows(ek) == [
            (("1",), ("10.0.0.1",), ("51234", "443")),
            (("3",), ("10.0.0.3",), ()),
        ]

    def test_typed_instance_access_reads_through_a_fields_row(self) -> None:
        # The payoff of the projection API, and the one thing only a live run
        # can show: the dual-mode descriptors read a FieldsRow exactly as they
        # read an ek packet — scalar to T | None, multi to tuple[T, ...] —
        # over columns tshark itself framed and aggregated.
        cap = Capture(PCAP).select(IP.src, TCP.port).filter(TCP.port == 443)
        matched = list(cap)
        assert len(matched) == 1
        pkt = matched[0]
        src = pkt[IP].src
        ports = pkt[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src == IPv4Address("10.0.0.1")
        # Two occurrences of one field in one column: proof that the -E
        # aggregator byte survived the round trip through a real tshark.
        assert ports == (51234, 443)

    def test_absent_projected_field_is_absence_not_an_error(self) -> None:
        # The cross-cutting absence invariant, measured over -T fields output
        # rather than asserted over a fake: () from get_raw, None from scalar
        # access, () from multi access. Frame 2 is ARP, so both projected
        # fields are absent; frame 3 is UDP, so only tcp.port is.
        packets = list(Capture(PCAP).select(IP.src, TCP.port))
        assert len(packets) == 3
        arp, dns = packets[1], packets[2]

        assert arp.get_raw("ip.src") == ()
        assert arp.get_raw("tcp.port") == ()
        arp_src = arp[IP].src
        arp_ports = arp[TCP].port
        assert_type(arp_src, IPv4Address | None)
        assert_type(arp_ports, tuple[int, ...])
        assert arp_src is None
        assert arp_ports == ()

        # An absent column next to a present one, which is the case a column
        # framing bug would show up as (a dropped empty column shifts every
        # later value onto the wrong field).
        assert dns[IP].src == IPv4Address("10.0.0.3")
        assert dns.get_raw("tcp.port") == ()
        assert dns[TCP].port == ()

    def test_unprojected_field_raises_rather_than_reading_as_absent(self) -> None:
        # The one observable difference between the two modes. udp.dstport is
        # genuinely present on frame 3 — the ek path answers 53 for it — so a
        # row that reported () here would be indistinguishable from real
        # absence and would silently drop the packet from a residual.
        pkt = next(iter(Capture(PCAP).select(IP.src).filter(UDP.dstport == 53)))
        with pytest.raises(FieldNotProjectedError, match=r"udp\.dstport"):
            pkt.get_raw("udp.dstport")
        # Through the descriptor too, not just the raw accessor: the refusal
        # has to reach the typed surface a caller actually writes.
        with pytest.raises(FieldNotProjectedError, match=r"udp\.dstport"):
            _ = pkt[UDP].dstport

    def test_residual_expr_filters_in_fields_mode_over_an_auto_projected_column(self) -> None:
        # Time comparisons are never renderable as a display filter, so this is
        # a genuine residual Expr; the planner auto-adds frame.time_epoch to
        # the projection so the compiled predicate can read it back off the
        # row. Both pushdown levels run at once here: -Y drops the ARP frame,
        # and the residual then drops frame 1 in Python.
        cap = Capture(PCAP).select(IP.src).filter(IP.src.present(), FRAME_TIME >= FRAME_3_TIME)
        plan = cap.plan()
        assert plan.mode == "fields"
        assert plan.dfilter == "(ip.src)"
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time_epoch"]
        assert plan.residual is not None

        matched = list(cap)
        assert [pkt[IP].src for pkt in matched] == [IPv4Address("10.0.0.3")]

    def test_argv_carries_T_fields_and_one_dash_e_per_projected_field(self) -> None:
        # What the planner decided has to survive into the argv that actually
        # reaches exec, in the projection's order — so the spy watches the real
        # process being constructed rather than re-deriving argv from the plan.
        # The recorded value is the argv the constructor was handed, not one
        # read back off the process: TsharkProcess keeps it private, and what
        # matters here is what reached exec, which is the same list.
        created: list[list[str]] = []
        real = TsharkProcess

        def spy(argv: Sequence[str]) -> TsharkProcess:
            created.append(list(argv))
            return real(argv)

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(capture_module, "TsharkProcess", spy)
            packets = list(Capture(PCAP).select(IP.src, TCP.port).filter(IP.src == "10.0.0.1"))

        assert len(created) == 1
        argv = created[0]
        # Resolved the same way pytestmark's skip check resolves it, rather
        # than through capture's private helper — test_capture.py owns that.
        assert argv[:3] == [os.environ.get("TSHARK") or "tshark", "-r", str(PCAP)]
        # Parenthesized because the planner wraps every pushed conjunct, so a
        # second one AND-ed on cannot reassociate against dfilter precedence.
        assert argv[3:5] == ["-Y", "(ip.src == 10.0.0.1)"]
        assert "-T" in argv and argv[argv.index("-T") + 1] == "fields"
        assert [argv[i + 1] for i, arg in enumerate(argv) if arg == "-e"] == ["ip.src", "tcp.port"]
        # tshark accepted that argv and produced the expected row, so the
        # assertions above are about a command line that really ran.
        assert len(packets) == 1
        assert packets[0][TCP].port == (51234, 443)

    def test_an_opaque_callable_still_forces_ek_despite_a_projection(self) -> None:
        # Nothing bounds the fields an arbitrary lambda reads, so the planner
        # must hand it whole packets. The observable consequence, live: the
        # yielded packet answers a field the projection never named, where a
        # fields-mode row would have raised FieldNotProjectedError for it.
        cap = Capture(PCAP).select(IP.src).filter(lambda pkt: pkt[UDP].dstport == 53)
        assert cap.plan().mode == "ek"
        assert cap.plan().projection is None
        matched = list(cap)
        assert len(matched) == 1
        assert matched[0][DNS].qry_name == ("foo,bar.example",)

    def test_select_with_no_arguments_stays_on_the_ek_path(self) -> None:
        # An empty projection and no projection at all are one state, and that
        # state is ek: -T fields with no -e is a degenerate argv emitting blank
        # lines, so it stays unreachable by construction.
        cap = Capture(PCAP).select()
        assert cap.plan().mode == "ek"
        assert len(list(cap)) == 3
