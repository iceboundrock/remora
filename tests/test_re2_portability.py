"""RE2 portability rules for matches patterns (issue #36).

The pattern subset `Expr` accepts is the Python-re/PCRE2 intersection; DuckDB's
RE2 is a third engine that cannot compile some of it. This module's rules are
what `remora.compile.sql` refuses on, so they are pinned here twice: as pure
unit expectations, and (where duckdb is installed) against RE2 itself.

It also carries the drift guard for the brace-quantifier grammar the two layers
each spell out for themselves (see `TestBraceGrammarAgreement`).
"""

from __future__ import annotations

import re

import pytest

from remora.compile.re2 import _BRACE as RE2_BRACE
from remora.compile.re2 import MAX_REPEAT, unportable_reason
from remora.expr import _QUANTIFIER_BRACE as EXPR_BRACE

PORTABLE = (
    "^ex.*com$",
    "foo\\.bar",
    "(?:abc)+",
    "(abc)+",
    "a|b",
    "[a-z]+",
    "[^0-9]+",
    "\\d{1,3}\\.\\d{1,3}",
    "\\bword\\b",
    "\\Bx",
    "\\w\\W\\s\\S\\D",
    "a{2,}",
    "a{1,3}?",
    "a+?",
    "\\x41",
    "a{1000}",
    "a{0,1000}",
    "(?:a{31}){31}",
    "(?:a{500}){2}",
    "(?:(?:a{10}){10}){10}",
    "(?:(?:a{10,}){10}){10}",
    "(?:a{2,}){10}",
    "(?:a+){1000}",
    "[{]a",
    "\\{2\\}",
    "[a\\]b]+",
    "(?:(?:a{7}){32}){0}",
)

UNPORTABLE = (
    ("a(?=b)", "lookaround"),
    ("a(?!b)", "lookaround"),
    ("(?<=a)b", "lookaround"),
    ("(?<!a)b", "lookaround"),
    ("a{1001}", "1001"),
    ("a{1,1001}", "1001"),
    ("a{1001,}", "1001"),
    ("(?:a{32}){32}", "1024"),
    ("(?:a{500}){3}", "1500"),
    ("(?:a{500,}){3}", "1500"),
    ("(?:a{100,}){11}", "1100"),
    ("(?:(?:a{500}){3}){0}", "1500"),
)

#: Patterns RE2 compiles perfectly well and remora refuses anyway, because the
#: *meaning* forks: RE2 folds case by Unicode in both directions, so a non-ASCII
#: pattern character can match ASCII text PCRE2 and Python `re` would not
#: (U+212A KELVIN SIGN -> "k", U+017F LATIN SMALL LETTER LONG S -> "s"). The
#: portable-text guard in sql.py covers the value side and cannot see this one,
#: because the value is ASCII. Kept apart from UNPORTABLE because the
#: real-engine cross-check below asserts the opposite thing about each table.
UNPORTABLE_BUT_RE2_COMPILES = (
    # Written as escapes rather than literal characters: an editor or tool that
    # NFKC-normalizes the source would turn U+212A into a plain "k" and quietly
    # neuter the test (it happened once while writing this file).
    ("\u212a", "U+212A"),  # KELVIN SIGN -> "k"
    ("\u017f", "U+017F"),  # LATIN SMALL LETTER LONG S -> "s"
    ("caf\u00e9", "U+00E9"),
    ("^\u00e9.*$", "U+00E9"),
)


@pytest.mark.parametrize("pattern", PORTABLE)
def test_portable_patterns_have_no_reason(pattern: str) -> None:
    assert unportable_reason(pattern) is None


@pytest.mark.parametrize(("pattern", "fragment"), UNPORTABLE)
def test_unportable_patterns_name_the_construct(pattern: str, fragment: str) -> None:
    reason = unportable_reason(pattern)
    assert reason is not None
    assert fragment in reason
    assert "RE2" in reason


@pytest.mark.parametrize(("pattern", "fragment"), UNPORTABLE_BUT_RE2_COMPILES)
def test_non_ascii_patterns_are_refused_naming_the_character(pattern: str, fragment: str) -> None:
    # A semantic refusal, not an engine one: RE2 would compile these (the class
    # below proves it), but a Unicode fold onto ASCII forks the row set.
    reason = unportable_reason(pattern)
    assert reason is not None
    assert fragment in reason
    assert "RE2" in reason


def test_the_limit_is_re2s_documented_one() -> None:
    assert MAX_REPEAT == 1000


def test_reason_names_a_position() -> None:
    reason = unportable_reason("ab(?=c)")
    assert reason is not None
    assert "position 2" in reason


#: Brace-ish strings both layers must classify identically. Each is fed to both
#: regexes at position 0, the position their callers scan from when they see a
#: "{". The forms each layer actually cares about are all here: the three shared
#: quantifiers ({m}, {m,}, {m,n}), the zero counts re2._brace_bound floors to a
#: factor of 1, the large count expr's PCRE2 ceiling is expressed in, and the
#: near-misses both must treat as a literal "{" rather than a quantifier.
BRACE_CORPUS = (
    "{2}",
    "{2,}",
    "{2,5}",
    "{0}",
    "{0,}",
    "{0,0}",
    "{}",
    "{,5}",
    "{a}",
    "{2,5,7}",
    "\\{2\\}",
    "{ 2 }",
    "{2",
    "{2,",
    "{65535}",
    "{65536}",
    "{1000}",
    "{1001}",
    "{2}{3}",
    "{2,}?",
    "{007}",
    "{12345678901234567890}",
    "",
    "a{2}",
)


class TestBraceGrammarAgreement:
    r"""`re2._BRACE` and `expr._QUANTIFIER_BRACE` must accept the same language.

    The two patterns are written out twice on purpose and **must stay
    duplicated**: `expr.py` is a leaf module that imports nothing from remora,
    and `re2.py` is a leaf that imports nothing but the stdlib, so neither can
    import the other and neither can be the single source for the other. A
    shared constant would need a third module both depend on, which is the
    import edge both leaf invariants exist to forbid — so the coupling is this
    test, and a future reader tempted to "fix" the duplication by adding an
    import should stop here.

    The assertion is behavioural, not textual: comparing the two `.pattern`
    strings would be a tautology today and a false alarm the moment one side is
    rewritten into an equivalent form. Instead both regexes are driven over one
    corpus and their verdicts, spans and captured groups are compared.
    """

    @pytest.mark.parametrize("text", BRACE_CORPUS)
    def test_both_grammars_agree(self, text: str) -> None:
        re2_match = RE2_BRACE.match(text)
        expr_match = EXPR_BRACE.match(text)
        assert (re2_match is None) == (expr_match is None), (
            f"one layer matched {text!r} and the other did not: "
            f"re2={re2_match!r} expr={expr_match!r}"
        )
        if re2_match is None or expr_match is None:
            return
        assert re2_match.group(0) == expr_match.group(0)
        assert re2_match.groups() == expr_match.groups()
        assert re2_match.span() == expr_match.span()

    def test_both_grammars_anchor_at_the_scan_position(self) -> None:
        # Both callers pass the index of a "{" as `pos`, so the anchoring the
        # two layers rely on has to agree as well as the language does.
        assert RE2_BRACE.match("a{2,5}", 1) is not None
        assert EXPR_BRACE.match("a{2,5}", 1) is not None
        assert RE2_BRACE.match("a{2,5}", 0) is None
        assert EXPR_BRACE.match("a{2,5}", 0) is None


class TestAgainstRealRE2:
    """The verdicts, checked against DuckDB's own RE2."""

    @pytest.fixture(scope="class")
    @classmethod
    def con(cls) -> object:
        duckdb = pytest.importorskip("duckdb")
        return duckdb.connect(":memory:")

    @pytest.mark.parametrize("pattern", PORTABLE)
    def test_portable_patterns_really_compile(self, con: object, pattern: str) -> None:
        # No exception is the assertion: RE2 compiles it.
        con.execute("SELECT regexp_matches('a', ?)", [pattern]).fetchall()  # type: ignore[attr-defined]

    @pytest.mark.parametrize(("pattern", "_fragment"), UNPORTABLE)
    def test_unportable_patterns_really_fail(
        self, con: object, pattern: str, _fragment: str
    ) -> None:
        duckdb = pytest.importorskip("duckdb")
        with pytest.raises(duckdb.Error):
            con.execute("SELECT regexp_matches('a', ?)", [pattern]).fetchall()  # type: ignore[attr-defined]

    @pytest.mark.parametrize(("pattern", "_fragment"), UNPORTABLE_BUT_RE2_COMPILES)
    def test_non_ascii_patterns_really_compile(
        self, con: object, pattern: str, _fragment: str
    ) -> None:
        # The engine accepts them — which is why this table is separate from
        # UNPORTABLE, whose entries RE2 itself rejects.
        con.execute("SELECT regexp_matches('a', ?)", [pattern]).fetchall()  # type: ignore[attr-defined]

    def test_the_unicode_fold_onto_ascii_is_real(self, con: object) -> None:
        # The defect this rule closes, reproduced on the engine: RE2 says the
        # Kelvin sign matches an ASCII "k"; Python re over UTF-8 bytes does not,
        # and neither does Wireshark's PCRE2.
        row = con.execute("SELECT regexp_matches('kelvin', ?, 'i')", ["\u212a"]).fetchone()  # type: ignore[attr-defined]
        assert row is not None
        assert row[0] is True
        assert re.search("\u212a".encode(), b"kelvin", re.IGNORECASE) is None
