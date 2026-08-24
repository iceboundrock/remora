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


def parse_code_fences(text: str) -> tuple[tuple[str, str], ...]:
    r"""Every fenced block in *text*, as ``(info string, body)`` pairs.

    Takes the text rather than reading the doc so the parser can be exercised
    on synthetic input: the doc carries no fences, so a parser tested only
    through it is tested on nothing (issue #102 review).

    The info string is matched with ``[^\n]*`` rather than ``.*``: under
    ``re.S`` a dot spans newlines, so a greedy tag group swallows the body and
    hands the mistag rule an empty one to inspect — which would make that rule
    vacuous for a reason nothing announces. That bug was real and shipped in
    this file's first draft, which is why the synthetic test below asserts the
    split itself and not only the rule's verdict.
    """
    return tuple(
        (match.group(1).strip(), match.group(2))
        for match in re.finditer(r"^```([^\n]*)\n(.*?)^```", text, re.M | re.S)
    )


def code_fences() -> tuple[tuple[str, str], ...]:
    """Every fenced block in ``docs/semantics.md``."""
    return parse_code_fences(read_doc())


def mistagged_stub_fences(
    fences: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """The fences that are stub examples tagged for the Python formatter.

    A *stub example* is a body whose first line carries ``...``. ``ruff
    format`` rewrites ```python fences in ``docs/*.md``, so such an example
    must be tagged ```pyi or it is reformatted as a ``.py`` file and silently
    corrupted. Every other tag — ```py, ```python3, untagged — is the same
    mistake: the tag is what has to move.
    """
    return tuple(
        (tag, body) for tag, body in fences if "..." in body.split("\n", 1)[0] and tag != "pyi"
    )


#: Synthetic input for the enforcement test below: two stub examples that
#: differ only in their tag, plus a ```python fence that is not a stub. Written
#: as a Python string constant on purpose — a fixture file under ``docs/`` would
#: be reformatted by the very ``ruff format`` pass this rule exists to survive,
#: and a docstring would be too if ``docstring-code-format`` were ever enabled.
SYNTHETIC_FENCES = (
    "prose before\n\n"
    "```python\n"
    "class IP:\n"
    "    src: Field[IPv4Address]\n"
    "```\n\n"
    "```python\n"
    "def src(self) -> Field[IPv4Address]: ...\n"
    "```\n\n"
    "```pyi\n"
    "def dst(self) -> Field[IPv4Address]: ...\n"
    "```\n\n"
    "prose after\n"
)


def test_the_mistag_rule_rejects_a_stub_tagged_for_the_python_formatter() -> None:
    """The guard's enforcement, proven on input the doc does not have to carry.

    The doc has no fences, so applying the rule to it proves detection, never
    rejection: a regression in the rule — or in the parser feeding it — leaves
    CI green because the loop runs zero times (issue #102 review). Synthetic
    text decouples the two, so the rule is tested on its own terms and the
    inventory test goes back to doing only its own job.

    The REAL parser runs over that text rather than the tuples being
    hand-built, because the one bug this file has actually had lived in the
    parser: a tag group that swallowed the body left the rule with an empty
    string to inspect, and a test that skipped the parser would have passed
    right through it.
    """
    fences = parse_code_fences(SYNTHETIC_FENCES)
    # The split itself, pinned: tag on one side, body on the other.
    assert [tag for tag, _ in fences] == ["python", "python", "pyi"]
    assert fences[1][1] == "def src(self) -> Field[IPv4Address]: ...\n"
    # ...and the verdict. The ```python stub is rejected; the ```pyi twin of
    # the same body is not, and neither is a ```python fence that is no stub.
    assert mistagged_stub_fences(fences) == (fences[1],)


def test_the_fence_inventory_the_mistag_guard_runs_over() -> None:
    """Self-reporting vacuity (issue #102).

    The guard below iterates the fences this doc carries, and today it carries
    none — so it asserts nothing, and reads as coverage it is not providing.
    Asserting the inventory it depends on says so out loud: the first fence
    added to this document fails here, which is exactly when someone should
    check that the guard below is saying what that fence needs.

    One of three deliberately separate tests, because they fail for three
    different reasons and want three different responses, and a merged node
    name would stop saying which happened: the rule is *enforced* on synthetic
    fences above, this one *announces* that the doc's fence set changed (a
    maintainer decision, not a defect), and the third applies the rule to the
    doc. Only this one needs the teaching message below.
    """
    fences = code_fences()
    assert fences == (), (
        "docs/semantics.md has gained its first fenced code block ("
        + ", ".join("```" + (tag or "untagged") for tag, _ in fences)
        + "), which is the event this test exists to announce.\n"
        "Until now test_no_fenced_stub_example_is_tagged_for_the_python_formatter "
        "looped over zero fences — the rule it applies is enforced on synthetic "
        "input by test_the_mistag_rule_rejects_a_stub_tagged_for_the_python_"
        "formatter, and this assertion is what says the real doc fed it nothing.\n"
        "Two things to do, in this order: (1) check the new fence against that "
        "rule — a stub example (a body whose first line carries '...') must be "
        "tagged ```pyi, because `ruff format` rewrites ```python fences in "
        "docs/*.md and would reformat a .pyi example as .py and silently "
        "corrupt it; (2) then update this inventory to the fences the doc now "
        "carries, so it keeps announcing the next change rather than this one."
    )


def test_no_fenced_stub_example_is_tagged_for_the_python_formatter() -> None:
    """The rule above, applied to the document this suite is about.

    Third of three jobs, each with its own node name: the rule is *enforced*
    by the synthetic test, the doc's fence set is *announced* by the inventory
    test, and this one applies the enforced rule to the real doc. It runs over
    zero fences today; that is a fact about the doc, not about the rule, and
    the synthetic test is what keeps the rule honest meanwhile.
    """
    offenders = mistagged_stub_fences(code_fences())
    assert offenders == (), (
        "docs/semantics.md carries a stub example tagged "
        + ", ".join("```" + (tag or "untagged") for tag, _ in offenders)
        + " — it must be tagged ```pyi, because `ruff format` rewrites "
        "```python fences in docs/*.md and would reformat a .pyi example as "
        ".py and silently corrupt it."
    )
