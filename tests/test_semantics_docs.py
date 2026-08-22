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


def test_the_doc_names_where_each_rule_is_enforced() -> None:
    text = read_doc()
    for path in (
        "tests/test_semantics_table.py",
        "tests/test_sql_duckdb.py",
        "tests/test_re2_portability.py",
        "src/remora/compile/re2.py",
        "src/remora/reader/fields_reader.py",
        "tests/test_fields_reader.py",
        "tests/integration/test_control_chars.py",
        "tests/fixtures/ctrl_comments.pcapng",
    ):
        assert path in text
        # Substring-only would leave the doc pointing at a renamed file.
        assert (REPO_ROOT / path).is_file(), path


def test_no_python_fence_is_mistagged_as_pyi() -> None:
    # ruff format rewrites ```python fences in docs/*.md; a .pyi example tagged
    # ```python would be reformatted as a .py file and silently corrupted.
    text = read_doc()
    for fence in re.findall(r"```python\n(.*?)```", text, re.S):
        assert "..." not in fence.split("\n")[0], "stub example must use a ```pyi fence"
