"""RE2 portability rules for matches patterns (issue #36).

The pattern subset `Expr` accepts is the Python-re/PCRE2 intersection; DuckDB's
RE2 is a third engine that cannot compile some of it. This module's rules are
what `remora.compile.sql` refuses on, so they are pinned here twice: as pure
unit expectations, and (where duckdb is installed) against RE2 itself.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("pattern", PORTABLE)
def test_portable_patterns_have_no_reason(pattern: str) -> None:
    assert unportable_reason(pattern) is None


@pytest.mark.parametrize(("pattern", "fragment"), UNPORTABLE)
def test_unportable_patterns_name_the_construct(pattern: str, fragment: str) -> None:
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
