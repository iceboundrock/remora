"""``FT_ABSOLUTE_TIME`` through a live tshark, in both reader modes (issue #117).

The bug this pins survived because no test read an absolute time through a
*live* packet: the unit suites feed canned epoch text to a ``FakePacket`` or a
``FieldsRow``, while tshark renders absolute times as ISO 8601 in ``-T ek``
(every field, ``frame.time_epoch`` included) and, in ``-T fields``, as epoch
seconds, ISO 8601 or pre-4.6 text depending on the display base and version.
``docs/semantics.md`` has the measured table.

Everything here is asserted against the instants the captures were built
with, not against another reading of the same capture, and the ek and
``-T fields`` paths are asserted equal to each other — the parity
``test_control_chars.py`` asserts for control characters, applied to times.
Nothing is version-gated: the forms differ by version, the values must not,
so CI's stock 4.2.2 and a current build run the same assertions.
"""

from __future__ import annotations

import os
import shutil
import struct
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typing_extensions import assert_type

from remora import IP, Capture
from remora.expr import Expr
from remora.fields import FieldRef, Packet, RawPacket
from remora.proto import NTP
from remora.values import convert

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample.pcap"
NTP_TIMES = ROOT / "fixtures" / "ntp_times.pcap"

#: Hand-built: there is no generated ``FRAME`` class. One ref per display base
#: the frame layer has — local, UTC and Unix — so each ``-T fields`` rendering
#: is exercised by the same three frames.
FRAME_TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
FRAME_TIME_UTC = FieldRef[datetime]("frame.time_utc", "FT_ABSOLUTE_TIME", False)
FRAME_TIME_EPOCH = FieldRef[datetime]("frame.time_epoch", "FT_ABSOLUTE_TIME", False)
FRAME_TIMES = (FRAME_TIME, FRAME_TIME_UTC, FRAME_TIME_EPOCH)

FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)


def _utc(seconds: int, micros: int = 0) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=micros)


#: sample.pcap's three frames arrive one second apart from epoch 1700000000.
SAMPLE_TIMES = [_utc(1700000000), _utc(1700000001), _utc(1700000002)]
FRAME_2_TIME, FRAME_3_TIME = SAMPLE_TIMES[1], SAMPLE_TIMES[2]

#: ntp_times.pcap, from tests/fixtures/make_fixtures.py: frame arrival times,
#: then each NTP timestamp per frame. ``None`` there is the all-zero "not set"
#: NTP time, which ``-T fields`` prints as ``NULL`` and ``-T ek`` as the epoch.
NTP_BASE = 1699142405
EPOCH = _utc(0)
NTP_FRAME_TIMES = [_utc(NTP_BASE), _utc(NTP_BASE + 1, 1000)]
NTP_EXPECTED = {
    NTP.reftime.name: [EPOCH, _utc(NTP_BASE - 60)],
    NTP.org.name: [EPOCH, _utc(NTP_BASE, 500000)],
    NTP.rec.name: [EPOCH, _utc(NTP_BASE + 1, 250000)],
    NTP.xmt.name: [_utc(NTP_BASE, 500000), _utc(NTP_BASE + 1, 750000)],
}
NTP_TIMES_REFS = (NTP.reftime, NTP.org, NTP.rec, NTP.xmt)

#: Pre-epoch frames: nanosecond pcapng stamps relative to an interface
#: if_tsoffset of -1 s, so tshark's nstime_t has negative whole seconds and a
#: non-negative fraction. 4.6.9 prints frame 1 as "-1.500000000" in -T fields
#: and "1969-12-31T23:59:59.500000000Z" in -T ek.
PRE_EPOCH_OFFSET = -1
PRE_EPOCH_STAMPS_NS = (500_000_000, 0, 999_999_999, 1_250_000_000)
PRE_EPOCH_TIMES = [
    EPOCH - timedelta(microseconds=500000),
    EPOCH - timedelta(seconds=1),
    # 1 ns before the epoch, truncated to the microsecond at or before it.
    EPOCH - timedelta(microseconds=1),
    EPOCH + timedelta(microseconds=250000),
]


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _pcapng_option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def _pre_epoch_pcapng() -> bytes:
    """One Ethernet interface (if_tsresol 9, if_tsoffset -1 s) and four frames."""
    opt_end = struct.pack("<HH", 0, 0)
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opt_end)
    idb = _pcapng_block(
        0x00000001,
        struct.pack("<HHI", 1, 0, 65535)
        + _pcapng_option(9, bytes([9]))  # if_tsresol: nanoseconds
        + _pcapng_option(14, struct.pack("<q", PRE_EPOCH_OFFSET))  # if_tsoffset
        + opt_end,
    )
    # A 60-byte broadcast frame with the local-experimental EtherType, so
    # nothing above Ethernet dissects.
    frame = b"\xff" * 6 + bytes(range(6)) + b"\x88\xb5" + b"\x00" * 46
    blocks = [shb, idb]
    for stamp in PRE_EPOCH_STAMPS_NS:
        header = struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame))
        blocks.append(_pcapng_block(0x00000006, header + frame))
    return b"".join(blocks)


@pytest.fixture
def pre_epoch(tmp_path: Path) -> Path:
    path = tmp_path / "pre_epoch.pcapng"
    path.write_bytes(_pre_epoch_pcapng())
    return path


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


def _times(packets: Sequence[RawPacket], ref: FieldRef[datetime]) -> list[datetime]:
    """Every occurrence of *ref* across *packets*, converted, in order."""
    return [
        value
        for pkt in packets
        for raw in pkt.get_raw(ref.name)
        if isinstance(value := convert(ref.ftype, raw), datetime)
    ]


def _ek(pcap: Path) -> list[Packet]:
    cap = Capture(pcap)
    assert cap.plan().mode == "ek"
    return list(cap)


def _fields(pcap: Path, *refs: FieldRef[datetime]) -> list[Packet]:
    cap = Capture(pcap).select(*refs)
    assert cap.plan().mode == "fields"
    return list(cap)


class TestLiveEkPacket:
    def test_every_frame_time_reads_as_a_datetime(self) -> None:
        # The issue's reproduction, verbatim in shape: a bare Capture is ek,
        # and its first packet's absolute times used to raise ValueError.
        pkt = _ek(SAMPLE)[0]
        for ref in FRAME_TIMES:
            (raw,) = pkt.get_raw(ref.name)
            # The precondition the bug needed, pinned so this test cannot
            # pass by reading some other form: ek prints ISO 8601 UTC even
            # for frame.time_epoch.
            assert raw.endswith("Z"), (ref.name, raw)
            assert convert(ref.ftype, raw) == SAMPLE_TIMES[0], ref.name

    def test_a_generated_field_reads_through_its_descriptor(self) -> None:
        # The public typed path, not only values.convert: pkt[NTP].xmt.
        pkt = _ek(NTP_TIMES)[0]
        xmt = pkt[NTP].xmt
        assert_type(xmt, datetime | None)
        assert xmt == _utc(NTP_BASE, 500000)


class TestEkAndFieldsAgree:
    @pytest.mark.parametrize("ref", FRAME_TIMES, ids=lambda ref: ref.name)
    def test_frame_times(self, ref: FieldRef[datetime]) -> None:
        assert _times(_ek(SAMPLE), ref) == SAMPLE_TIMES
        assert _times(_fields(SAMPLE, ref), ref) == SAMPLE_TIMES

    @pytest.mark.parametrize("ref", NTP_TIMES_REFS, ids=lambda ref: ref.name)
    def test_ntp_times_including_the_zero_time(self, ref: FieldRef[datetime]) -> None:
        # The zero NTP time prints NULL in -T fields and the epoch in -T ek;
        # both must read as the epoch.
        expected = NTP_EXPECTED[ref.name]
        assert _times(_ek(NTP_TIMES), ref) == expected
        assert _times(_fields(NTP_TIMES, ref), ref) == expected

    def test_ntp_frame_times_with_a_space_padded_day(self) -> None:
        # ntp_times.pcap is dated the 5th, so before 4.6 -T fields prints
        # "Nov  5, 2023 ..." with two spaces.
        for ref in FRAME_TIMES:
            assert _times(_ek(NTP_TIMES), ref) == NTP_FRAME_TIMES, ref.name
            assert _times(_fields(NTP_TIMES, ref), ref) == NTP_FRAME_TIMES, ref.name

    @pytest.mark.parametrize("ref", FRAME_TIMES, ids=lambda ref: ref.name)
    def test_a_residual_predicate_selects_the_same_frames(self, ref: FieldRef[datetime]) -> None:
        # dfilter.py never pushes a time literal, so this is a residual in both
        # modes; in fields mode the planner auto-projects the field for it.
        term = ref >= FRAME_3_TIME
        ek = Capture(SAMPLE).filter(term)
        fields = Capture(SAMPLE).select(FRAME_NUMBER).filter(term)
        assert ek.plan().mode == "ek"
        assert fields.plan().mode == "fields"
        assert fields.plan().residual is not None
        assert [pkt.get_raw("frame.number") for pkt in ek] == [("3",)]
        assert [pkt.get_raw("frame.number") for pkt in fields] == [("3",)]


class TestPreEpoch:
    """Times before the epoch, which -T fields prints as signed whole seconds
    plus a non-negative fraction ("-1.500000000" is -0.5 s)."""

    @pytest.mark.parametrize("ref", FRAME_TIMES, ids=lambda ref: ref.name)
    def test_ek_and_fields_agree(self, ref: FieldRef[datetime], pre_epoch: Path) -> None:
        assert _times(_ek(pre_epoch), ref) == PRE_EPOCH_TIMES
        assert _times(_fields(pre_epoch, ref), ref) == PRE_EPOCH_TIMES

    def test_fields_prints_the_signed_whole_seconds_form(self, pre_epoch: Path) -> None:
        # The precondition, pinned so the parity above cannot pass by tshark
        # having changed its rendering: the fraction is not the sign's.
        packets = _fields(pre_epoch, FRAME_TIME_EPOCH)
        assert packets[0].get_raw(FRAME_TIME_EPOCH.name) == ("-1.500000000",)

    @pytest.mark.parametrize("ref", FRAME_TIMES, ids=lambda ref: ref.name)
    @pytest.mark.parametrize(
        ("term_of", "frames"),
        [
            (lambda ref: ref < EPOCH, [("1",), ("2",), ("3",)]),
            (lambda ref: ref >= PRE_EPOCH_TIMES[0], [("1",), ("3",), ("4",)]),
            (lambda ref: ref == PRE_EPOCH_TIMES[0], [("1",)]),
            # A string literal is a signed decimal: "-1.5" is 1.5 s before
            # the epoch, earlier than every frame.
            (lambda ref: ref > "-1.5", [("1",), ("2",), ("3",), ("4",)]),
            (lambda ref: ref > "-0.5", [("3",), ("4",)]),
        ],
        ids=["before-epoch", "from-frame-1", "frame-1", "after-str-1.5", "after-str-0.5"],
    )
    def test_a_residual_predicate_selects_the_same_frames(
        self,
        ref: FieldRef[datetime],
        term_of: Callable[[FieldRef[datetime]], Expr],
        frames: list[tuple[str]],
        pre_epoch: Path,
    ) -> None:
        term = term_of(ref)
        ek = Capture(pre_epoch).filter(term)
        fields = Capture(pre_epoch).select(FRAME_NUMBER).filter(term)
        assert ek.plan().mode == "ek"
        assert fields.plan().mode == "fields"
        assert fields.plan().residual is not None
        assert [pkt.get_raw("frame.number") for pkt in ek] == frames
        assert [pkt.get_raw("frame.number") for pkt in fields] == frames


class TestCallerZoneDoesNotLeak:
    def test_frame_time_reads_the_same_in_a_non_utc_zone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Before 4.6, tshark prints frame.time in its own zone by abbreviation
        # ("MST"), which no parser can resolve; the spawned tshark is pinned
        # to UTC so the caller's zone never reaches the rendering.
        monkeypatch.setenv("TZ", "America/Denver")
        packets = _fields(SAMPLE, FRAME_TIME)
        (raw,) = packets[0].get_raw(FRAME_TIME.name)
        assert raw.endswith(("+0000", " UTC")), raw
        assert _times(packets, FRAME_TIME) == SAMPLE_TIMES

    def test_the_select_and_filter_from_the_issue(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Symptom B: both of these used to plan fine and raise per packet.
        monkeypatch.setenv("TZ", "Asia/Kolkata")
        selected = list(Capture(SAMPLE).select(IP.src, FRAME_TIME))
        assert _times(selected, FRAME_TIME) == SAMPLE_TIMES
        filtered = list(Capture(SAMPLE).select(IP.src).filter(FRAME_TIME >= FRAME_2_TIME))
        # Frame 2 is ARP (no ip.src) but still passes the time residual.
        assert [pkt.get_raw("ip.src") for pkt in filtered] == [(), ("10.0.0.3",)]
