"""RE2 portability rules for matches patterns (issue #36).

The pattern subset `Expr` accepts is the Python-re/PCRE2 intersection; DuckDB's
RE2 is a third engine that cannot compile some of it. This module's rules are
what `remora.compile.sql` refuses on, so they are pinned here twice: as pure
unit expectations, and (where duckdb is installed) against RE2 itself.
"""

from __future__ import annotations

import re

import pytest

from remora.compile.re2 import MAX_REPEAT, unportable_reason

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
