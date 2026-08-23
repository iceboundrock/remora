"""docs/semantics.md must describe the semantics the suite enforces (issue #36).

The truth table and the regex matrix are contracts, so they are parsed out of
the markdown and compared against the code and the test table rather than being
trusted to stay in sync by hand — the same treatment tests/test_readme.py gives
the quickstart.
"""

from __future__ import annotations

import re
from pathlib import Path

from remora.compile.re2 import LOOKAROUND_PREFIXES, MAX_REPEAT

# Deliberately a private helper: the point of this guard is that the SQL the doc
# quotes is the SQL the backend emits, so the expected fragment is built by the
# real builder rather than copied out of it.
from remora.compile.sql import _guarded_match
from remora.reader.fields_reader import ESCAPED_CHARS, OCC_SEP, UNIT_SEP
from test_semantics_table import TRUTH_OPERATORS

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "semantics.md"

TRUTH_START = "<!-- truth-table:start -->"
TRUTH_END = "<!-- truth-table:end -->"

ESCAPES_START = "<!-- fields-escapes:start -->"
ESCAPES_END = "<!-- fields-escapes:end -->"


def read_doc() -> str:
    return DOC.read_text(encoding="utf-8")


def truth_rows() -> dict[str, tuple[str, str, str, str]]:
    """Parse the marked truth table into operator -> the four cells."""
    text = read_doc()
    body = text.split(TRUTH_START, 1)[1].split(TRUTH_END, 1)[0]
    rows: dict[str, tuple[str, str, str, str]] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 5 or cells[0] in {"operator", "Operator"}:
            continue
        rows[cells[0].strip("`")] = (cells[1], cells[2], cells[3], cells[4])
    return rows


def test_the_doc_exists() -> None:
    assert DOC.is_file()


def test_truth_table_covers_exactly_the_enforced_operators() -> None:
    assert set(truth_rows()) == set(TRUTH_OPERATORS)


def test_every_positive_cell_is_false_and_every_negated_cell_is_true() -> None:
    for operator, cells in truth_rows().items():
        positive_scalar, positive_multi, negated_scalar, negated_multi = cells
        assert positive_scalar == "False", operator
        assert positive_multi == "False", operator
        assert negated_scalar == "True", operator
        assert negated_multi == "True", operator


def test_the_regex_matrix_names_the_real_re2_limit() -> None:
    text = read_doc()
    assert str(MAX_REPEAT) in text
    for prefix in LOOKAROUND_PREFIXES:
        assert f"({prefix}" in text


def test_the_portable_text_guard_section_states_both_halves() -> None:
    # The pattern side (re2.py refuses a non-ASCII pattern, because RE2 folds
    # U+212A/U+017F ONTO ASCII) and the value side (sql.py's runtime guard) are
    # each unsound alone; the doc has to carry both.
    text = read_doc()
    assert "U+212A" in text
    assert "U+017F" in text
    # The value-side test the doc quotes, taken from the compiler that emits it:
    # "strlen(v) <> length(v) OR contains(v, chr(10))".
    condition = _guarded_match("v", '"col"').split("CASE WHEN ", 1)[1].split(" THEN ", 1)[0]
    assert condition in text


def escape_rows() -> dict[str, str]:
    """Parse the marked `-T fields` escape table into byte -> escape letter."""
    body = read_doc().split(ESCAPES_START, 1)[1].split(ESCAPES_END, 1)[0]
    rows: dict[str, str] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) != 2 or cells[0] == "byte":
            continue
        rows[cells[0]] = cells[1]
    return rows


def test_the_fields_escape_table_is_the_one_the_reader_implements() -> None:
    # The reader inverts this table on every value it parses, so a doc that
    # drifts from it is a doc that mis-describes the row sets remora returns.
    assert escape_rows() == {
        f"0x{ord(char):02x}": "\\" + letter for char, letter in ESCAPED_CHARS.items()
    }


def test_the_doc_states_which_side_of_the_escaper_each_separator_is_on() -> None:
    # Getting either backwards is a silent corruption (#74), so the doc has to
    # name both bytes, and they have to still be on the sides it claims.
    text = read_doc()
    assert f"(`0x{ord(UNIT_SEP):02x}`)" in text
    assert f"(`0x{ord(OCC_SEP):02x}`)" in text
    assert UNIT_SEP in ESCAPED_CHARS
    assert OCC_SEP not in ESCAPED_CHARS


#: Suffixes that make a backticked token a repository path rather than prose.
_PATH_SUFFIXES = (".py", ".pyi", ".md", ".toml", ".pcap", ".pcapng", ".txt")

#: A floor under the derivation below. Listing every path is what this test
#: stopped doing (issue #102), but a regex that quietly matches nothing would
#: turn the existence check into a no-op, so these four — the doc cannot be
#: this document without citing them — have to keep coming out of it.
_ANCHOR_PATHS = frozenset(
    {
        "src/remora/compile/re2.py",
        "src/remora/compile/sql.py",
        "tests/test_semantics_table.py",
        "tests/test_sql_duckdb.py",
    }
)


def named_paths() -> frozenset[str]:
    """Every repository path the doc names inside a code span.

    Derived from the doc rather than restated here (issue #102): a hand-kept
    list covers only the paths somebody remembered to add, and this one had
    fallen three behind. A ``file.py::Class`` citation contributes the file.
    """
    paths: set[str] = set()
    for span in re.findall(r"`([^`\n]+)`", read_doc()):
        head = span.split("::", 1)[0].strip()
        # A glob is a pattern, not an enforcement site: docs/*.md names no file.
        if "/" in head and "*" not in head and head.endswith(_PATH_SUFFIXES):
            paths.add(head)
    return frozenset(paths)


def test_the_doc_names_where_each_rule_is_enforced() -> None:
    named = named_paths()
    assert named >= _ANCHOR_PATHS, "the path derivation stopped seeing the doc's own citations"
    for path in sorted(named):
        # Naming a path is not enough: a renamed file would leave the doc
        # pointing at nothing, and the citation is the enforcement claim.
        assert (REPO_ROOT / path).is_file(), path


def code_fences() -> tuple[tuple[str, str], ...]:
    """Every fenced block in the doc, as ``(info string, body)`` pairs."""
    return tuple(
        (match.group(1).strip(), match.group(2))
        for match in re.finditer(r"^```(.*)\n(.*?)^```", read_doc(), re.M | re.S)
    )


def test_the_fence_inventory_the_mistag_guard_runs_over() -> None:
    """Self-reporting vacuity (issue #102).

    The guard below iterates the fences this doc carries, and today it carries
    none — so it asserts nothing, and reads as coverage it is not providing.
    Asserting the inventory it depends on says so out loud: the first fence
    added to this document fails here, which is exactly when someone should
    check that the guard below is saying what that fence needs.
    """
    assert code_fences() == ()


def test_no_fenced_stub_example_is_tagged_for_the_python_formatter() -> None:
    # ruff format rewrites ```python fences in docs/*.md, so a .pyi example
    # tagged ```python is reformatted as a .py file and silently corrupted.
    # Checked over EVERY fence rather than only the ```python ones: an untagged
    # or ```py-tagged stub is the same mistake, and the tag is what has to move.
    for tag, body in code_fences():
        if "..." in body.split("\n", 1)[0]:
            assert tag == "pyi", f"stub example must use a ```pyi fence, not ```{tag}"
