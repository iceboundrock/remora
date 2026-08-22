r"""Control characters in string values: the three paths must agree (issue #74).

``tshark -T fields`` C-escapes control bytes in value text while the
display-filter engine and ``-T ek`` operate on the true value, so the same
expression used to select different packets depending on which path evaluated
it. This suite pins the three row sets equal over
``tests/fixtures/ctrl_comments.pcapng``, whose frame comments carry real
control bytes (a dissector-built string field cannot: every one of those is
already ``format_text``-ed by its dissector):

* **pushdown** — the expression compiled to ``-Y`` and evaluated by Wireshark;
* **fields residual** — no ``-Y``, a ``-T fields`` projection, the compiled
  Python predicate over :class:`FieldsRow` (this is the path that was wrong);
* **ek residual** — no ``-Y``, ``-T ek``, the same predicate over
  :class:`EkPacket` (this path was already right).

It also discharges the issue's item 4 — "confirm behavior on CI's Linux/PPA
tshark" — the only way a macOS developer can: rather than trusting the escape
table measured on Homebrew 4.6.8, :class:`TestEscapeTableIsWhatTsharkDoes`
re-measures it against whatever tshark is on PATH and asserts it equals the
table :mod:`remora.reader.fields_reader` implements. A build that escapes
differently fails loudly here instead of silently forking row sets.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from remora.compile.dfilter import compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr
from remora.fields import FieldRef, RawPacket
from remora.reader.ek_reader import EkReader, ek_argv
from remora.reader.fields_reader import ESCAPED_CHARS, OCC_SEP, UNIT_SEP, FieldsReader, fields_argv
from remora.reader.process import TsharkProcess

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
CTRL_COMMENTS = FIXTURES_DIR / "ctrl_comments.pcapng"

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

FRAME_NUMBER = FieldRef[int]("frame.number", "FT_FRAMENUM", False)
#: pcapng allows several comments per frame, so the field is multi-valued.
COMMENT = FieldRef[str]("frame.comment", "FT_STRING", True)

PROJECTION: list[FieldRef[Any]] = [FRAME_NUMBER, COMMENT]

#: The comment carried by each frame of the fixture, by frame number. Kept
#: here rather than imported from make_fixtures.py so a fixture regenerated
#: with different bytes fails a test instead of quietly redefining the
#: expectation.
COMMENTS = {
    1: "tab\there",
    2: "vt\vhere",
    3: "back\\slash",
    4: "us\x1fhere",
}


def tshark() -> str:
    resolved = shutil.which(os.environ.get("TSHARK") or "tshark")
    assert resolved is not None, "REMORA_REQUIRE_TSHARK is set but tshark is missing"
    return resolved


def run(*args: str) -> list[str]:
    with TsharkProcess([tshark(), "-n", "-r", str(CTRL_COMMENTS), *args]) as proc:
        return list(proc)


def pushdown_rows(expr: Expr) -> set[int]:
    """Frame numbers Wireshark itself selects for *expr*."""
    lines = run("-Y", compile_dfilter(expr), *fields_argv([FRAME_NUMBER]))
    return {int(line) for line in lines if line}


def fields_rows(expr: Expr) -> set[int]:
    """Frame numbers the compiled predicate selects over ``-T fields`` rows."""
    predicate = compile_predicate(expr)
    rows = FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION)
    return {int(row.get_raw("frame.number")[0]) for row in rows if predicate(row)}


def ek_rows(expr: Expr) -> set[int]:
    """Frame numbers the compiled predicate selects over ``-T ek`` packets."""
    predicate = compile_predicate(expr)
    packets = EkReader(run(*ek_argv()))
    return {int(pkt.get_raw("frame.number")[0]) for pkt in packets if predicate(pkt)}


class TestFixtureCarriesRealControlBytes:
    """Guard the guard: if the fixture lost its control bytes the suite below
    would pass vacuously."""

    def test_ek_reports_the_true_comment_of_every_frame(self) -> None:
        packets = list(EkReader(run(*ek_argv())))
        comments = {
            index: pkt.get_raw("frame.comment") for index, pkt in enumerate(packets, start=1)
        }
        assert comments == {n: (text,) for n, text in COMMENTS.items()} | {5: ()}


class TestRowSetsAgreeAcrossThePaths:
    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_equality_on_a_control_bearing_value(self, frame: int) -> None:
        expr = COMMENT == COMMENTS[frame]  # noqa: SIM300
        pushed = pushdown_rows(expr)
        assert pushed == {frame}
        assert fields_rows(expr) == pushed
        assert ek_rows(expr) == pushed

    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_contains_on_a_control_bearing_value(self, frame: int) -> None:
        # The needle is the two characters straddling the control byte, so it
        # exists only in the escaped-vs-true representation that is correct.
        text = COMMENTS[frame]
        needle = text[2:5]
        expr = COMMENT.contains(needle)
        pushed = pushdown_rows(expr)
        assert pushed == {frame}
        assert fields_rows(expr) == pushed
        assert ek_rows(expr) == pushed


class TestColumnFramingSurvivesTheSeparatorBytes:
    def test_a_value_holding_the_old_separator_no_longer_aborts_the_parse(self) -> None:
        # Frame 4's comment carries a raw 0x1f, the pre-#74 column separator.
        # Parsing used to raise "expected 2 column(s) ... got 3".
        rows = list(FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION))
        assert len(rows) == 5
        assert rows[3].get_raw("frame.comment") == ("us\x1fhere",)

    def test_a_value_holding_the_current_separator_is_escaped_by_tshark(self) -> None:
        # Frame 2's comment carries a raw 0x0b, the column separator itself.
        # tshark prints it as "\v", so it cannot frame a column.
        line = run(*fields_argv(PROJECTION))[1]
        assert UNIT_SEP not in line.split(UNIT_SEP, 1)[1]
        rows = list(FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION))
        assert rows[1].get_raw("frame.comment") == ("vt\vhere",)


class TestEscapeTableIsWhatTsharkDoes:
    """Item 4 of the issue: re-measure the table against the local tshark."""

    def test_the_escaped_bytes_arrive_as_their_two_character_escape(self) -> None:
        # Every key of ESCAPED_CHARS that the fixture carries. The fixture
        # cannot carry all eight (0x0a would need a comment spanning lines,
        # which editcap-shaped tooling mangles), so this checks the three it
        # does carry plus the raw-passthrough byte, which is the load-bearing
        # half: an escape we DON'T undo corrupts the value.
        by_frame = dict(enumerate(run(*fields_argv(PROJECTION)), start=1))
        assert by_frame[1].split(UNIT_SEP)[1] == "tab" + "\\" + ESCAPED_CHARS["\t"] + "here"
        assert by_frame[2].split(UNIT_SEP)[1] == "vt" + "\\" + ESCAPED_CHARS["\v"] + "here"
        assert by_frame[3].split(UNIT_SEP)[1] == "back" + "\\" + ESCAPED_CHARS["\\"] + "slash"
        assert by_frame[4].split(UNIT_SEP)[1] == "us\x1fhere"  # 0x1f is NOT escaped

    def test_the_separator_is_written_raw_and_the_aggregator_is_escaped(self) -> None:
        """The invariant the two constants are chosen for (see the reader's
        module docstring): tshark writes the column separator outside the
        escaper and splices the aggregator inside it."""
        assert UNIT_SEP in ESCAPED_CHARS
        assert OCC_SEP not in ESCAPED_CHARS
        # A raw separator really does appear between the columns...
        assert UNIT_SEP in run(*fields_argv(PROJECTION))[0]
        # ...while an aggregator drawn from the escaped set would come back as
        # its escape and never split. Measured here, not assumed.
        probe_argv = [
            tshark(),
            "-n",
            "-r",
            str(FIXTURES_DIR / "dns_multi.pcap"),
            "-T",
            "fields",
            "-E",
            f"separator={UNIT_SEP}",
            "-E",
            "aggregator=\f",  # 0x0c, a member of ESCAPED_CHARS
            "-E",
            "occurrence=a",
            "-e",
            "dns.qry.name",
        ]
        with TsharkProcess(probe_argv) as proc:
            first = next(iter(proc))
        assert "\f" not in first
        assert "\\f" in first


class TestPredicateContractIsUnchanged:
    def test_a_frame_without_a_comment_never_matches(self) -> None:
        # SIM300 ("Yoda condition") suppressed throughout: swapping the
        # operands would build a different Expr, not the same one read
        # backwards.
        for text in COMMENTS.values():
            assert 5 not in fields_rows(COMMENT == text)  # noqa: SIM300
        assert fields_rows(COMMENT.present()) == {1, 2, 3, 4}

    def test_row_and_packet_read_the_same_value(self) -> None:
        rows = list(FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION))
        packets = list(EkReader(run(*ek_argv())))
        assert [row.get_raw("frame.comment") for row in rows] == [
            pkt.get_raw("frame.comment") for pkt in packets
        ]

    def test_rows_satisfy_the_raw_packet_contract(self) -> None:
        rows = list(FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION))
        assert all(isinstance(row, RawPacket) for row in rows)
