"""Tests for the ``-T fields`` projection reader.

The golden test parses ``tests/data/fields_sample.txt`` — real tshark 4.6
output checked in by ``tests/data/make_fields_sample.py`` — without spawning
tshark. The integration test (``-m integration``) regenerates the same rows
by spawning tshark over the checked-in ``sample.pcap``.

NB: sample files are split on ``"\\n"`` only, never ``str.splitlines()`` —
splitlines() also treats ``\\x1e`` (the occurrence aggregator byte) as a
line boundary and would shred multi-occurrence columns.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import assert_type

from remora.fields import FieldNotProjectedError, FieldRef, RawPacket
from remora.reader.fields_reader import (
    OCC_SEP,
    UNIT_SEP,
    FieldsReader,
    FieldsRow,
    fields_argv,
)

DATA_DIR = Path(__file__).resolve().parent / "data"

FRAME_REF = FieldRef[int]("frame.number", "FT_FRAMENUM", False)
SRC_REF = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
PORT_REF = FieldRef[int]("tcp.port", "FT_UINT16", True)
QNAME_REF = FieldRef[str]("dns.qry.name", "FT_STRING", False)

#: Projection used by make_fields_sample.py; order matters.
SAMPLE_PROJECTION: list[FieldRef[Any]] = [FRAME_REF, SRC_REF, PORT_REF, QNAME_REF]

#: Expected parse of fields_sample.txt, column name -> raw occurrences.
SAMPLE_ROWS = [
    {
        "frame.number": ("1",),
        "ip.src": ("10.0.0.1",),
        "tcp.port": ("51234", "443"),  # two occurrences: srcport, dstport
        "dns.qry.name": (),
    },
    {
        # ARP request: no IP/TCP/DNS layers at all.
        "frame.number": ("2",),
        "ip.src": (),
        "tcp.port": (),
        "dns.qry.name": (),
    },
    {
        "frame.number": ("3",),
        "ip.src": ("10.0.0.3",),
        "tcp.port": (),
        "dns.qry.name": ("foo,bar.example",),  # comma survives verbatim
    },
]


def sample_lines(text: str) -> list[str]:
    """Split raw tshark stdout into lines on \\n only (see module docstring)."""
    return text.rstrip("\n").split("\n")


def parse(lines: list[str], projection: Sequence[FieldRef[Any]] | None = None) -> list[FieldsRow]:
    return list(FieldsReader(lines, SAMPLE_PROJECTION if projection is None else projection))


def row_dict(row: FieldsRow) -> dict[str, tuple[str, ...]]:
    return {ref.name: row.get_raw(ref.name) for ref in SAMPLE_PROJECTION}


class TestFieldsArgv:
    def test_golden_argv(self) -> None:
        assert fields_argv(SAMPLE_PROJECTION) == [
            "-T",
            "fields",
            "-E",
            "separator=\x1f",
            "-E",
            "aggregator=\x1e",
            "-E",
            "occurrence=a",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "tcp.port",
            "-e",
            "dns.qry.name",
        ]

    def test_always_has_occurrence_and_separators(self) -> None:
        argv = fields_argv([])
        assert "occurrence=a" in argv
        assert f"separator={UNIT_SEP}" in argv
        assert f"aggregator={OCC_SEP}" in argv

    def test_separators_are_raw_control_bytes(self) -> None:
        """tshark 4.6 has no /xNN escape; the literal byte must be in argv."""
        assert UNIT_SEP == "\x1f"
        assert OCC_SEP == "\x1e"
        assert not any("/x1f" in arg or "/x1e" in arg for arg in fields_argv(SAMPLE_PROJECTION))


class TestParseRules:
    def test_multi_occurrence_column_becomes_tuple(self) -> None:
        (row,) = parse([f"1{UNIT_SEP}10.0.0.1{UNIT_SEP}51234{OCC_SEP}443{UNIT_SEP}"])
        assert row.get_raw("tcp.port") == ("51234", "443")

    def test_absent_is_empty_tuple(self) -> None:
        (row,) = parse([f"2{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}"])
        assert row.get_raw("ip.src") == ()
        assert row.get_raw("tcp.port") == ()

    def test_empty_occurrences_among_multiple_are_preserved(self) -> None:
        """A column of just OCC_SEP is ("", "") — distinguishable from absent ()."""
        (row,) = parse([f"1{UNIT_SEP}{UNIT_SEP}{OCC_SEP}{UNIT_SEP}"])
        assert row.get_raw("tcp.port") == ("", "")
        assert row.get_raw("ip.src") == ()

    def test_values_kept_verbatim_no_conversion(self) -> None:
        line = f'7{UNIT_SEP}not an ip{UNIT_SEP}0x1f{UNIT_SEP}tab\tcomma,quote"'
        (row,) = parse([line])
        assert row.get_raw("ip.src") == ("not an ip",)
        assert row.get_raw("tcp.port") == ("0x1f",)
        assert row.get_raw("dns.qry.name") == ('tab\tcomma,quote"',)

    def test_column_count_mismatch_names_line_number(self) -> None:
        good = f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}"
        bad = f"2{UNIT_SEP}"
        with pytest.raises(ValueError, match=r"line 2.*expected 4 column\(s\).*got 2"):
            parse([good, bad])

    def test_unprojected_field_raises(self) -> None:
        (row,) = parse([f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}"])
        with pytest.raises(FieldNotProjectedError, match=r"udp\.port"):
            row.get_raw("udp.port")


class TestFieldsRowPacketContract:
    def test_satisfies_raw_packet(self) -> None:
        (row,) = parse([f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}"])
        assert isinstance(row, RawPacket)

    def test_getitem_builds_protocol_view_that_reads_through(self) -> None:
        from remora.fields import Field, MultiField

        class FakeProto:
            _remora_packet: RawPacket

            src = Field(SRC_REF)
            port = MultiField(PORT_REF)

            def __init__(self, packet: RawPacket) -> None:
                self._remora_packet = packet

        (row,) = parse([f"1{UNIT_SEP}10.0.0.1{UNIT_SEP}51234{OCC_SEP}443{UNIT_SEP}"])
        # Static half of the contract: raw access and protocol-view typing.
        assert_type(row.get_raw("ip.src"), tuple[str, ...])
        view = row[FakeProto]
        assert_type(view, FakeProto)
        assert isinstance(view, FakeProto)
        assert view.src == IPv4Address("10.0.0.1")
        assert view.port == (51234, 443)


class TestGoldenSample:
    """Parse real checked-in tshark 4.6 output without spawning tshark."""

    def test_sample_parses_to_expected_rows(self) -> None:
        text = (DATA_DIR / "fields_sample.txt").read_text()
        rows = parse(sample_lines(text))
        assert [row_dict(row) for row in rows] == SAMPLE_ROWS


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
class TestIntegration:
    def test_live_tshark_matches_golden_parse(self) -> None:
        from remora.reader.process import TsharkProcess

        tshark = shutil.which("tshark")
        assert tshark is not None
        argv = [tshark, "-r", str(DATA_DIR / "sample.pcap"), *fields_argv(SAMPLE_PROJECTION)]
        with TsharkProcess(argv) as proc:
            raw_lines = list(proc)
        # Self-verify the raw-byte separator claim (module docstring of
        # fields_reader): the control bytes really are in tshark's stdout.
        assert any(UNIT_SEP in line for line in raw_lines)
        assert any(OCC_SEP in line for line in raw_lines)
        rows = list(FieldsReader(raw_lines, SAMPLE_PROJECTION))
        assert [row_dict(row) for row in rows] == SAMPLE_ROWS
