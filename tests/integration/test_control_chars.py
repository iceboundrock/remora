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
tshark" — the only way a macOS developer can: rather than trusting a table
measured on one build, :class:`TestEscapeTableIsWhatTsharkDoes` re-measures
against whatever tshark is on PATH. A build that escapes differently fails
loudly here instead of silently forking row sets.

**The escaping is version-dependent, so this suite is too.** tshark only
doubles a literal backslash from 4.4; on 4.2.2 (Ubuntu noble's stock build,
and what CI's ``checks`` job installs) it does not, which makes the escaping
non-invertible there — see :mod:`remora.reader.fields_reader`. The reader
gates unescaping on that, so the three row sets agree only on >= 4.4. Below
it the fields path still diverges for any value tshark escaped, and this
suite asserts *that* rather than skipping: the pre-4.4 behavior is a
documented contract too, and a silent skip would let a regression through.
Framing, by contrast, is fixed on every version and is asserted
unconditionally.
"""

from __future__ import annotations

import os
import shutil
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from remora.compile.dfilter import compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr
from remora.fields import FieldRef, RawPacket
from remora.reader.ek_reader import EkReader, ek_argv
from remora.reader.fields_reader import (
    ESCAPED_CHARS,
    OCC_SEP,
    UNIT_SEP,
    FieldsReader,
    escaping_is_reversible,
    fields_argv,
    unescape,
)
from remora.reader.process import TsharkProcess, probe_tshark_version

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


@cache
def tshark_version() -> str | None:
    """The version of the tshark on PATH, probed once per session.

    Cached rather than computed at module scope: a module-level probe spawns
    a process during *collection*, so ``--collect-only`` and a run that skips
    this whole suite would both pay for it.
    """
    return probe_tshark_version(os.environ.get("TSHARK") or "tshark")


@cache
def reversible() -> bool:
    """Whether the tshark on PATH escapes invertibly (>= 4.4).

    Everything below branches on this rather than assuming the developer's
    build.
    """
    return escaping_is_reversible(tshark_version())


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
    # The collision that forces the version gate: a literal backslash
    # immediately followed by "t" (see make_fixtures.py).
    5: "C:\\temp",
}

#: Frame 7 and its true comment, kept OUT of :data:`COMMENTS` on purpose.
#: Every test parametrized over ``COMMENTS`` asserts the fields path recovers
#: the value, and frame 7 is the one frame where it provably cannot: its
#: comment carries :data:`OCC_SEP` itself, which tshark escapes on no version,
#: so the column forks into two occurrences. Folding it into ``COMMENTS``
#: would turn an accepted residual into a stream of failures; it gets
#: :class:`TestTheOccurrenceForkIsTheAcceptedResidual` instead.
RS_FRAME = 7
RS_COMMENT = "rs\x1ehere"

#: What the fields path yields for :data:`RS_FRAME` instead of the true value:
#: the join positions are unrecoverable, so the one value arrives as two.
RS_FORKED = ("rs", "here")

#: A ``matches`` pattern per frame, each written so it can only match that
#: frame's TRUE comment. Issue #74 names ``matches`` alongside ``==`` and
#: ``contains``, and it is the operator where the two regex engines could fork
#: as well as the two representations, so it gets its own row set.
#:
#: The patterns are constrained twice over. :class:`remora.expr.Matches`
#: accepts only the Python-re/PCRE2 common subset, which is why frame 2's
#: VERTICAL TAB is written ``\x0b`` rather than ``\v`` — ``\v`` is
#: dialect-specific and rejected at construction. And a backslash in the
#: subject has to be written ``\\``, so frames 3 and 5 exercise exactly the
#: doubling that decides the version gate.
MATCHES_PATTERNS = {
    1: r"tab\there",
    2: r"vt\x0bhere",
    3: r"back\\slash",
    4: r"us\x1fhere",
    5: r"C:\\temp",
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
    rows = FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
    return {int(row.get_raw("frame.number")[0]) for row in rows if predicate(row)}


def emitted_comment(frame: int) -> str:
    """The raw column text tshark printed for *frame*'s comment."""
    return run(*fields_argv(PROJECTION))[frame - 1].split(UNIT_SEP)[1]


def survives_the_round_trip(frame: int) -> bool:
    """Whether the fields path can recover frame *frame*'s true comment.

    True when the running tshark escapes invertibly, and also when it escaped
    nothing at all in this particular value — a raw ``0x1f`` reaches us intact
    on every build, so those frames agree even on 4.2.2.
    """
    return reversible() or emitted_comment(frame) == COMMENTS[frame]


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
        assert comments == {n: (text,) for n, text in COMMENTS.items()} | {
            6: (),
            RS_FRAME: (RS_COMMENT,),
        }


class TestRowSetsAgreeAcrossThePaths:
    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_equality_on_a_control_bearing_value(self, frame: int) -> None:
        expr = COMMENT == COMMENTS[frame]  # noqa: SIM300
        pushed = pushdown_rows(expr)
        assert pushed == {frame}
        # ek decodes JSON and is right on every version — the reference.
        assert ek_rows(expr) == pushed
        if survives_the_round_trip(frame):
            assert fields_rows(expr) == pushed
        else:
            # Pre-4.4: tshark escaped the value and the escaping cannot be
            # inverted, so the reader honestly reports the escaped text and
            # the predicate does not match. Pinned, not skipped.
            assert fields_rows(expr) == set()

    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_contains_on_a_control_bearing_value(self, frame: int) -> None:
        # The needle is the two characters straddling the control byte, so it
        # exists only in the escaped-vs-true representation that is correct.
        text = COMMENTS[frame]
        needle = text[2:5]
        expr = COMMENT.contains(needle)
        pushed = pushdown_rows(expr)
        assert pushed == {frame}
        assert ek_rows(expr) == pushed
        if survives_the_round_trip(frame):
            assert fields_rows(expr) == pushed
        else:
            assert fields_rows(expr) == set()

    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_matches_on_a_control_bearing_value(self, frame: int) -> None:
        r"""The third operator #74 names, pinned like the other two.

        Every pattern is anchored on the control byte itself (a regex ``\t``
        or ``\xHH``, never the two characters tshark prints for it), so a
        match proves the path recovered the true value rather than the
        escaped text. Frames 3 and 5 carry a literal backslash instead, which
        is the subject the version gate turns on.
        """
        expr = COMMENT.matches(MATCHES_PATTERNS[frame])
        pushed = pushdown_rows(expr)
        assert pushed == {frame}
        # PCRE2 (pushdown) and Python re (residual) agree on this subset, so
        # any disagreement below is the representation, not the dialect.
        assert ek_rows(expr) == pushed
        if survives_the_round_trip(frame):
            assert fields_rows(expr) == pushed
        else:
            assert fields_rows(expr) == set()


class TestColumnFramingSurvivesTheSeparatorBytes:
    def test_a_value_holding_the_old_separator_no_longer_aborts_the_parse(self) -> None:
        # Frame 4's comment carries a raw 0x1f, the pre-#74 column separator.
        # Parsing used to raise "expected 2 column(s) ... got 3".
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        assert len(rows) == 7
        # 0x1f is escaped by no measured version and carries no backslash, so
        # this value is identical on both sides of the gate.
        assert rows[3].get_raw("frame.comment") == ("us\x1fhere",)

    def test_a_value_holding_the_current_separator_is_escaped_by_tshark(self) -> None:
        # Frame 2's comment carries a raw 0x0b, the column separator itself.
        # tshark prints it as "\v" on EVERY measured version, so it cannot
        # frame a column — this half is unconditional, which is the whole
        # point of choosing an escaped byte for the separator.
        line = run(*fields_argv(PROJECTION))[1]
        assert UNIT_SEP not in line.split(UNIT_SEP, 1)[1]
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        # Recovering the true 0x0b from that "\v" is the gated half.
        expected = "vt\vhere" if reversible() else "vt" + "\\" + ESCAPED_CHARS["\v"] + "here"
        assert rows[1].get_raw("frame.comment") == (expected,)


class TestEscapeTableIsWhatTsharkDoes:
    """Item 4 of the issue: re-measure against the tshark actually installed.

    These assert *properties* rather than one build's byte table, because the
    table is not stable across releases (module docstring). What must hold is
    the property the reader relies on: on a version we unescape for, undoing
    the escaping recovers the value ``-T ek`` reports.
    """

    def test_the_version_gate_matches_the_binary_on_path(self) -> None:
        version = tshark_version()
        assert version is not None, "tshark is installed but reported no version"
        assert escaping_is_reversible(version) == reversible()

    @pytest.mark.parametrize("frame", sorted(COMMENTS))
    def test_unescaping_recovers_the_true_value_when_the_gate_is_open(self, frame: int) -> None:
        """The contract in one line: on >= 4.4, unescape inverts what tshark did."""
        if not reversible():
            pytest.skip(f"tshark {tshark_version()} does not escape invertibly")
        assert unescape(emitted_comment(frame)) == COMMENTS[frame]

    def test_a_pre_44_build_really_is_non_invertible(self) -> None:
        r"""Why the gate exists, measured rather than taken from a changelog.

        Frame 5's comment is ``C:\temp`` — a literal backslash immediately
        followed by ``t``. A build that does not double the backslash prints
        it unchanged as ``C:\temp``, which is byte-for-byte what it prints
        for a value holding a real TAB. Unescaping there does not merely fail
        to help: it rewrites this value into ``C:<TAB>emp``.
        """
        if reversible():
            pytest.skip(f"tshark {tshark_version()} doubles backslashes")
        assert emitted_comment(5) == COMMENTS[5]  # NOT doubled
        corrupted = unescape(emitted_comment(5))
        assert corrupted != COMMENTS[5]
        assert corrupted == "C:\temp"  # a TAB where the backslash was

    def test_the_backslash_row_is_what_decides_the_gate(self) -> None:
        """Doubling and invertibility are the same fact, whichever build this is."""
        doubled = emitted_comment(3) == "back" + "\\" + ESCAPED_CHARS["\\"] + "slash"
        assert doubled is reversible()
        # ...and the collision frame agrees with it.
        assert (emitted_comment(5) != COMMENTS[5]) is reversible()

    def test_the_bytes_this_build_escapes_are_a_subset_of_the_table(self) -> None:
        """The reader may know escapes a build never emits (4.2.2 leaves 0x07
        raw); it must never MISS one, which is what would corrupt a value."""
        for frame, text in COMMENTS.items():
            emitted = emitted_comment(frame)
            for char in text:
                if char in emitted:  # arrived raw
                    continue
                assert char in ESCAPED_CHARS, (
                    f"frame {frame}: tshark {tshark_version()} escaped {char!r}, "
                    f"which ESCAPED_CHARS does not name"
                )
                assert "\\" + ESCAPED_CHARS[char] in emitted

    def test_the_separator_is_raw_and_the_aggregator_is_never_forgeable(self) -> None:
        """The invariant the two constants are chosen for (reader docstring).

        The column separator must be a byte the escaper replaces; the
        aggregator must be one it leaves alone. Which side of the escaper the
        aggregator is spliced on CHANGED in 4.4 — 4.2.2 splices it after
        escaping, 4.4+ before — so an escaped byte works as an aggregator on
        one and silently stops splitting on the other. 0x1e, escaped by
        neither, is the only choice that works on both, and that is what is
        asserted here.
        """
        assert UNIT_SEP in ESCAPED_CHARS
        assert OCC_SEP not in ESCAPED_CHARS
        # A raw separator really does appear between the columns...
        assert UNIT_SEP in run(*fields_argv(PROJECTION))[0]
        # ...and the chosen aggregator really does split a multi-occurrence
        # column, on whichever side of the escaper this build splices it.
        multi = FieldRef[str]("dns.qry.name", "FT_STRING", True)
        proj: list[FieldRef[Any]] = [FRAME_NUMBER, multi]
        argv = [
            tshark(),
            "-n",
            "-r",
            str(FIXTURES_DIR / "dns_multi.pcap"),
            *fields_argv(proj),
        ]
        with TsharkProcess(argv) as proc:
            lines = [line for line in proc if line]
        assert lines, "dns_multi.pcap must yield rows"
        assert any(OCC_SEP in line for line in lines), (
            f"tshark {tshark_version()} did not split occurrences on OCC_SEP"
        )


class TestTheOccurrenceForkIsTheAcceptedResidual:
    r"""Frame 7 witnesses, end to end, the one thing #74 does NOT fix.

    ``OCC_SEP`` (0x1e) is escaped by no measured tshark, so a value that
    genuinely holds one is indistinguishable from two occurrences joined by
    it. That is not a choice of separator that could be made better: tshark
    returns ``escape(occ1 + SEP + occ2)``, a function of the joined string
    alone, so the join positions are gone before the reader sees anything.
    Any *escaped* byte never arrives raw and so would never split at all
    (measured: on 4.4+ the aggregator is spliced in before the escaper, so
    ``aggregator=0x0c`` comes back as the two characters ``\f``); any
    *unescaped* byte is forgeable by the value, which is this frame.

    These tests pin the fork as expected behaviour. If a future tshark starts
    escaping 0x1e they will fail, which is the correct alarm: the residual
    would then be closable and the docs would be wrong.

    The premise this rests on — ``OCC_SEP not in ESCAPED_CHARS`` — is
    asserted by
    :meth:`TestEscapeTableIsWhatTsharkDoes.test_the_separator_is_raw_and_the_aggregator_is_never_forgeable`
    and deliberately not repeated here.
    """

    def test_ek_reports_the_one_true_value(self) -> None:
        """The ek path is unaffected — JSON needs no in-band separator."""
        packets = list(EkReader(run(*ek_argv())))
        assert packets[RS_FRAME - 1].get_raw("frame.comment") == (RS_COMMENT,)

    def test_the_fields_path_forks_it_into_two_occurrences(self) -> None:
        """...where the fields path reports two, on every version.

        Unconditional: 0x1e carries no backslash and is escaped nowhere, so
        the gate does not enter into it.
        """
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        assert rows[RS_FRAME - 1].get_raw("frame.comment") == RS_FORKED

    def test_the_two_paths_disagree_and_that_is_the_documented_residual(self) -> None:
        """State the divergence directly rather than leaving it implied."""
        packets = list(EkReader(run(*ek_argv())))
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        from_ek = packets[RS_FRAME - 1].get_raw("frame.comment")
        from_fields = rows[RS_FRAME - 1].get_raw("frame.comment")
        assert from_ek != from_fields
        assert len(from_ek) == 1 and len(from_fields) == 2
        # The bytes are all still there; only the join position is lost.
        assert OCC_SEP.join(from_fields) == from_ek[0]

    def test_a_predicate_therefore_disagrees_across_the_two_paths(self) -> None:
        """The consequence a user would actually hit.

        Equality against the true value selects frame 7 over ek and misses it
        over a -T fields projection. Pinned so the blast radius of the
        residual is recorded, not just its mechanism.
        """
        expr = COMMENT == RS_COMMENT
        assert RS_FRAME in ek_rows(expr)
        assert RS_FRAME not in fields_rows(expr)


class TestPredicateContractIsUnchanged:
    def test_a_frame_without_a_comment_never_matches(self) -> None:
        # SIM300 ("Yoda condition") suppressed throughout: swapping the
        # operands would build a different Expr, not the same one read
        # backwards. Version-independent: absence is absence on any build.
        for text in COMMENTS.values():
            assert 6 not in fields_rows(COMMENT == text)  # noqa: SIM300
        # Frame 7 IS present — the fork loses the join position, not the
        # field — so presence covers every frame but the commentless one.
        assert fields_rows(COMMENT.present()) == {1, 2, 3, 4, 5, RS_FRAME}

    def test_row_and_packet_read_the_same_value(self) -> None:
        """The two readers agree only where the escaping is invertible; ek is
        the reference, so below 4.4 this is a known, pinned divergence."""
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        packets = list(EkReader(run(*ek_argv())))
        from_rows = [row.get_raw("frame.comment") for row in rows]
        from_packets = [pkt.get_raw("frame.comment") for pkt in packets]
        # Frame 7 is excluded by name, not by loosening the comparison: it
        # diverges for a different reason (the occurrence fork, which no
        # version fixes) and TestTheOccurrenceForkIsTheAcceptedResidual owns
        # it. Dropping it here keeps this test about the ESCAPING only.
        del from_rows[RS_FRAME - 1], from_packets[RS_FRAME - 1]
        if reversible():
            assert from_rows == from_packets
        else:
            assert from_rows != from_packets
            # ...and only for the frames tshark actually escaped.
            for index, frame in enumerate(sorted(COMMENTS)):
                if survives_the_round_trip(frame):
                    assert from_rows[index] == from_packets[index]

    def test_rows_are_never_silently_wrong_about_framing(self) -> None:
        """Column framing is fixed on every version: seven rows, one per frame.

        The occurrence counts are the honest census: five frames carry one
        comment, frame 6 carries none, and frame 7 reports **two** because its
        value holds :data:`OCC_SEP`. That last count is the accepted residual,
        not a framing failure — the row itself is intact and in the right
        place, which is what this test is about.
        """
        rows = list(
            FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION, unescape_values=reversible())
        )
        assert len(rows) == 7
        assert [len(row.get_raw("frame.comment")) for row in rows] == [1, 1, 1, 1, 1, 0, 2]

    def test_rows_satisfy_the_raw_packet_contract(self) -> None:
        rows = list(FieldsReader(run(*fields_argv(PROJECTION)), PROJECTION))
        assert all(isinstance(row, RawPacket) for row in rows)
