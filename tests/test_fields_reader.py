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
    ESCAPED_CHARS,
    OCC_SEP,
    UNIT_SEP,
    FieldsReader,
    FieldsRow,
    fields_argv,
    unescape,
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
            "separator=\x0b",
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
        assert UNIT_SEP == "\x0b"
        assert OCC_SEP == "\x1e"
        assert not any("/x0b" in arg or "/x1e" in arg for arg in fields_argv(SAMPLE_PROJECTION))


class TestSeparatorInvariants:
    """The two separators sit on OPPOSITE sides of tshark's escaping.

    tshark writes the column separator to the stream RAW, after each column's
    text has been escaped, but splices the occurrence aggregator INTO the
    value text before escaping it (measured: ``aggregator=\\x0c`` comes back
    as the two characters ``\\f``). The two constants therefore have opposite
    requirements, and getting either backwards is a silent corruption.
    """

    def test_column_separator_is_a_byte_tshark_escapes_in_values(self) -> None:
        # Escaped-in-values means no field value can ever forge it: column
        # framing is unambiguous. This is the load-bearing invariant of #74.
        assert UNIT_SEP in ESCAPED_CHARS

    def test_occurrence_aggregator_is_a_byte_tshark_leaves_raw(self) -> None:
        # The aggregator is escaped along with the value, so an escaped byte
        # would arrive as its two-character escape and NEVER split.
        assert OCC_SEP not in ESCAPED_CHARS

    def test_escape_table_is_exactly_the_eight_c_escapes(self) -> None:
        assert ESCAPED_CHARS == {
            "\a": "a",
            "\b": "b",
            "\t": "t",
            "\n": "n",
            "\v": "v",
            "\f": "f",
            "\r": "r",
            "\\": "\\",
        }


class TestUnescape:
    @pytest.mark.parametrize(
        ("escaped", "expected"),
        [
            (r"a\ab", "a\ab"),
            (r"a\bb", "a\bb"),
            (r"a\tb", "a\tb"),
            (r"a\nb", "a\nb"),
            (r"a\vb", "a\vb"),
            (r"a\fb", "a\fb"),
            (r"a\rb", "a\rb"),
            (r"a\\b", "a\\b"),
        ],
    )
    def test_every_escape_in_the_table_round_trips(self, escaped: str, expected: str) -> None:
        assert unescape(escaped) == expected

    def test_text_without_a_backslash_is_returned_unchanged(self) -> None:
        assert unescape("10.0.0.1") == "10.0.0.1"

    def test_doubled_backslash_is_consumed_before_the_following_letter(self) -> None:
        """``\\\\t`` is a literal backslash then ``t`` — not a tab."""
        assert unescape(r"a\\tb") == "a\\tb"
        assert unescape("a" + "\\" * 4 + "b") == "a\\\\b"

    def test_unknown_escape_passes_through_verbatim(self) -> None:
        """tshark never emits one; refusing would be a crash on valid data."""
        assert unescape(r"a\qb") == r"a\qb"

    def test_trailing_lone_backslash_is_kept(self) -> None:
        assert unescape("path\\") == "path\\"

    def test_raw_control_bytes_tshark_does_not_escape_pass_through(self) -> None:
        # 0x01-0x06, 0x0e-0x1f and 0x7f reach us as themselves (measured).
        for raw in ("\x01", "\x1b", "\x1f", "\x7f"):
            assert unescape(f"a{raw}b") == f"a{raw}b"


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

    def test_values_get_no_type_conversion(self) -> None:
        line = f'7{UNIT_SEP}not an ip{UNIT_SEP}0x1f{UNIT_SEP}comma,quote"'
        (row,) = parse([line])
        assert row.get_raw("ip.src") == ("not an ip",)
        assert row.get_raw("tcp.port") == ("0x1f",)
        assert row.get_raw("dns.qry.name") == ('comma,quote"',)

    def test_each_occurrence_is_unescaped_after_the_split(self) -> None:
        line = f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}" + r"a\tb" + OCC_SEP + r"c\\d"
        (row,) = parse([line])
        assert row.get_raw("dns.qry.name") == ("a\tb", "c\\d")

    def test_a_value_containing_the_column_separator_cannot_split_a_column(self) -> None:
        """tshark escapes a VT inside a value, so only the raw byte frames."""
        line = f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}" + r"a\vb"
        (row,) = parse([line])
        assert row.get_raw("dns.qry.name") == ("a\vb",)

    def test_bytes_tshark_leaves_raw_are_carried_as_data(self) -> None:
        """0x1f and 0x0c used to frame columns/occurrences; now they are data."""
        line = f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}a\x1fb\x0cc"
        (row,) = parse([line])
        assert row.get_raw("dns.qry.name") == ("a\x1fb\x0cc",)

    def test_residual_a_raw_aggregator_byte_in_a_value_forks_occurrences(self) -> None:
        """Pinned trade-off, not a wish: tshark splices the aggregator into the
        value text *before* escaping it, so no byte choice can tell an
        aggregator apart from the same byte occurring inside a value."""
        line = f"1{UNIT_SEP}{UNIT_SEP}{UNIT_SEP}a{OCC_SEP}b"
        (row,) = parse([line])
        assert row.get_raw("dns.qry.name") == ("a", "b")  # truth is one value "a\x1eb"

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
