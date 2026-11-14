"""``FT_OID`` through a live tshark and a real workspace (issue #149).

``FT_OID`` is ``str``: the numeric dotted text tshark prints. #149 measured
that text, and this suite holds the result over ``tests/fixtures/oid.pcap``:

- both readers print the same text, which is the text ``docs/semantics.md``
  documents for each encoding, malformed ones included;
- tshark rejects the quoted literal the ``str`` rendering would push, and
  compares a bare one by its encoded bytes rather than its text or its arcs,
  which is why the dfilter backend pushes presence only;
- for every expression below, the plan pushes what it should, and the Python
  residual in ``-T fields`` and ``-T ek`` mode and the workspace's SQL select
  the same frames, which are also the frames the expression is declared to
  select.

Measured on 4.2.2, 4.4.19 and 4.6.9. They print the same text and agree on
everything asserted here. One difference is recorded, not asserted: a two-arc
literal (``snmp.name == 1.3``) is an OID on 4.2.2 and a rejected ``Double``
on 4.4.19 and 4.6.9.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from remora import Capture
from remora.compile.predicate import compile_predicate
from remora.expr import Expr
from remora.fields import FieldRef, RawPacket
from remora.proto import SNMP

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OID_PCAP = REPO_ROOT / "tests" / "fixtures" / "oid.pcap"
SEMANTICS_DOC = REPO_ROOT / "docs" / "semantics.md"

FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)
# snmp.name occurs once per varbind, but ships scalar; the workspace refuses a
# second occurrence in a scalar column, so this suite declares it multi.
NAME = FieldRef[str]("snmp.name", "FT_OID", True)
ALL_REFS: tuple[FieldRef[str], ...] = (NAME, SNMP.value_oid, SNMP.enterprise)
ALL_FRAMES = frozenset(range(1, 11))

#: Per field, frame number -> every occurrence as tshark prints it, from
#: tests/fixtures/make_fixtures.py.
EXPECTED: dict[str, dict[int, tuple[str, ...]]] = {
    NAME.name: {
        1: ("1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.1.0"),
        3: ("1.3.6.1.2.1.1.10", "1.3.6.1.2.1.1.9"),
        # The third arc of 2**32 prints empty, and dissection stops there.
        4: ("1.3", "2.999.1", ""),
        5: ("1.3.6",),
        6: ("1.3.1",),
        7: ("0",),
        8: ("1.3.6.16383",),
        9: ("1.3.6.16384",),
        # One occurrence on each side of the subtree 1.3.6.1.2.1.1.
        10: ("1.3.6.1.2.1.0", "1.3.6.1.2.1.3"),
    },
    SNMP.value_oid.name: {1: ("1.3.6.1.4.1.8072.3.2.10",)},
    SNMP.enterprise.name: {2: ("1.3.6.1.4.1.9",)},
}

_TSHARK = os.environ.get("TSHARK") or "tshark"
_TSHARK_TIMEOUT = 60

# REMORA_REQUIRE_TSHARK (set in CI) turns "tshark missing" from a skip into a
# hard failure, so a broken CI install can never silently skip the suite.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(_TSHARK) is None and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


def _ek() -> list[RawPacket]:
    cap = Capture(OID_PCAP)
    assert cap.plan().mode == "ek"
    return list(cap)


def _fields() -> list[RawPacket]:
    cap = Capture(OID_PCAP).select(FRAME_NUMBER, *ALL_REFS)
    assert cap.plan().mode == "fields"
    return list(cap)


def _frame(pkt: RawPacket) -> int:
    return int(pkt.get_raw("frame.number")[0])


def _occurrences(packets: Sequence[RawPacket], ref: FieldRef[Any]) -> dict[int, tuple[str, ...]]:
    """Frame number -> every raw occurrence of *ref*, for frames carrying it."""
    return {_frame(pkt): pkt.get_raw(ref.name) for pkt in packets if pkt.get_raw(ref.name)}


def _doc_rows() -> list[tuple[int, str, str]]:
    """``(frame, field, printed text)`` from the marked table in docs/semantics.md.

    The same parse as tests/test_semantics_docs.py, which checks the octets
    column against the fixture; this one checks the printed column against tshark.
    """
    text = SEMANTICS_DOC.read_text(encoding="utf-8")
    body = text.split("<!-- oid-forms:start -->", 1)[1].split("<!-- oid-forms:end -->", 1)[0]
    rows: list[tuple[int, str, str]] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "frame":
            continue
        printed = "" if cells[3] == "(empty)" else cells[3].strip("`")
        rows.append((int(cells[0]), cells[1].strip("`"), printed))
    return rows


class TestReadersAgree:
    @pytest.mark.parametrize("ref", ALL_REFS, ids=lambda ref: ref.name)
    def test_ek_and_fields_print_the_built_text(self, ref: FieldRef[str]) -> None:
        assert _occurrences(_ek(), ref) == EXPECTED[ref.name]
        assert _occurrences(_fields(), ref) == EXPECTED[ref.name]

    def test_the_documented_renderings_are_what_tshark_prints(self) -> None:
        rows = _doc_rows()
        assert rows, "the oid-forms table parsed to nothing"
        for packets in (_ek(), _fields()):
            by_frame = {_frame(pkt): pkt for pkt in packets}
            for frame, field, printed in rows:
                assert printed in by_frame[frame].get_raw(field), (frame, field, printed)

    def test_instance_access_is_the_printed_text(self) -> None:
        packets = {_frame(pkt): pkt for pkt in Capture(OID_PCAP)}
        assert packets[2][SNMP].enterprise == "1.3.6.1.4.1.9"
        assert packets[1][SNMP].value_oid == "1.3.6.1.4.1.8072.3.2.10"
        assert packets[1][SNMP].enterprise is None


def _tshark(dfilter: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_TSHARK, "-n", "-r", str(OID_PCAP), "-Y", dfilter, "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=_TSHARK_TIMEOUT,
        check=False,
    )


def _tshark_frames(dfilter: str) -> set[int]:
    result = _tshark(dfilter)
    assert result.returncode == 0, result.stderr
    return {int(line) for line in result.stdout.split()}


class TestTsharkEvidence:
    """What tshark does with an OID filter: the reasons nothing but presence is pushed."""

    @pytest.mark.parametrize(
        "dfilter",
        [
            'snmp.name == "1.3.6.1.2.1.1.2.0"',
            'snmp.name > "1.3.6.1.2.1.1.9"',
            'snmp.name in {"1.3.6.1.2.1.1.2.0"}',
            'snmp.name contains "1.3.6"',
        ],
    )
    def test_a_quoted_oid_is_rejected(self, dfilter: str) -> None:
        result = _tshark(dfilter)
        assert result.returncode != 0
        assert "cannot be converted from a string" in result.stderr

    def test_matches_is_rejected(self) -> None:
        result = _tshark('snmp.name matches "^1"')
        assert result.returncode != 0
        assert "cannot participate in matches comparison" in result.stderr

    def test_a_bare_oid_compares_the_encoding_not_the_text(self) -> None:
        assert _tshark_frames("snmp.name == 1.3.6.1.2.1.1.2.0") == {1}
        # Frame 5 prints 1.3.6, but its encoding (2b 06 81) is not 1.3.6's.
        assert _tshark_frames("snmp.name == 1.3.6") == set()
        # Byte order puts .10 above .9 (frame 3), and the encodings of frames 5
        # and 6 sort above it too; the text puts .10 below .9.
        assert _tshark_frames("snmp.name > 1.3.6.1.2.1.1.9") == {3, 4, 5, 6, 8, 9, 10}

    def test_a_bare_oid_orders_the_encoding_not_the_arcs(self) -> None:
        # Well formed, and still not arc order: 16383 is ff 7f and 16384 is
        # 81 80 00, so tshark puts 1.3.6.16383 (frame 8) above 1.3.6.16384
        # (frame 9). Numeric arc order is the API's proposal, not tshark parity.
        assert _tshark_frames("frame.number in {8, 9} && snmp.name > 1.3.6.16384") == {8}
        assert _tshark_frames("frame.number in {8, 9} && snmp.name < 1.3.6.16383") == {9}

    def test_bounds_quantify_per_comparison_and_a_range_per_occurrence(self) -> None:
        # Frame 10 holds 1.3.6.1.2.1.0 and 1.3.6.1.2.1.3, neither in the
        # subtree 1.3.6.1.2.1.1, but each satisfies one bound. The same is true
        # of the Python and SQL backends (the straddle rows of MATRIX).
        assert _tshark_frames("snmp.name >= 1.3.6.1.2.1.1 && snmp.name < 1.3.6.1.2.1.2") == {
            1,
            3,
            4,
            10,
        }
        assert _tshark_frames("snmp.name in {1.3.6.1.2.1.1 .. 1.3.6.1.2.1.2}") == {1, 3}


@dataclass(frozen=True)
class Row:
    """One expression, the frames it selects, and the ``-Y`` the plan carries."""

    label: str
    expr: Expr
    expected: frozenset[int]
    dfilter: str | None
    residual: bool


def row(label: str, expr: Expr, expected: set[int], *, dfilter: str | None = None) -> Row:
    """A row whose OID value tests are residual; *dfilter* is the pushed remainder."""
    return Row(label, expr, frozenset(expected), dfilter, residual=True)


SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SUBTREE = r"^1\.3\.6\.1\.2\.1\.1(\.|$)"

MATRIX: list[Row] = [
    Row("present", NAME.present(), ALL_FRAMES - {2}, "(snmp.name)", residual=False),
    row("==", NAME == SYS_OBJECT_ID, {1}),
    row("!= (absent included)", NAME != SYS_OBJECT_ID, set(ALL_FRAMES - {1})),
    row("value oid ==", SNMP.value_oid == "1.3.6.1.4.1.8072.3.2.10", {1}),
    row("enterprise ==", SNMP.enterprise == "1.3.6.1.4.1.9", {2}),
    row("malformed encodings by their text", NAME.in_(["1.3.6", "1.3.1", "0"]), {5, 6, 7}),
    row("the empty rendering", NAME == "", {4}),
    row("> is text order", NAME > "1.3.6.1.2.1.1.9", {4, 8, 9, 10}),
    # tshark adds frame 8 (1.3.6.16383) by its encoding; text and arcs do not.
    row("> is not byte order", NAME > "1.3.6.16384", {4}),
    row("text range", NAME.in_([("1.3.6.1.2.1.1", "1.3.6.1.2.1.1.9")]), {1, 3}),
    row("contains", NAME.contains("1.3.6.1.2.1.1."), {1, 3}),
    row("subtree by matches", NAME.matches(SUBTREE), {1, 3}),
    # Frame 10 has no member of the subtree, but one occurrence per bound.
    row(
        "independent bounds straddle the subtree",
        (NAME >= "1.3.6.1.2.1.1") & (NAME < "1.3.6.1.2.1.2"),
        {1, 3, 4, 10},
    ),
    row("a range tests one occurrence", NAME.in_([("1.3.6.1.2.1.1", "1.3.6.1.2.1.2")]), {1, 3}),
    row(
        "refused term inside an or",
        (SNMP.enterprise == "1.3.6.1.4.1.9") | (NAME == "2.999.1"),
        {2, 4},
    ),
    row(
        "pushed presence and a residual",
        NAME.present() & (NAME > "1.3.6.1.2.1.1.9"),
        {4, 8, 9, 10},
        dfilter="(snmp.name)",
    ),
]

_IDS = [item.label for item in MATRIX]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    duckdb = pytest.importorskip("duckdb")
    del duckdb
    from remora.workspace import Workspace

    path = tmp_path_factory.mktemp("oid") / "ws.duckdb"
    with Workspace(path, mode="rw") as ws:
        result = ws.materialize(OID_PCAP, list(ALL_REFS))
        assert result.row_count == len(ALL_FRAMES)
    return path


class TestRowSetParity:
    @pytest.mark.parametrize("item", MATRIX, ids=_IDS)
    def test_pushdown_and_residual_as_planned(self, item: Row) -> None:
        cap = Capture(OID_PCAP).filter(item.expr)
        plan = cap.plan()
        assert plan.dfilter == item.dfilter, plan.explain()
        assert (plan.residual is not None) is item.residual, plan.explain()
        assert {_frame(pkt) for pkt in cap} == item.expected

    @pytest.mark.parametrize("item", MATRIX, ids=_IDS)
    def test_python_residual_in_both_reader_modes(self, item: Row) -> None:
        predicate = compile_predicate(item.expr)
        assert {_frame(pkt) for pkt in _ek() if predicate(pkt)} == item.expected
        assert {_frame(pkt) for pkt in _fields() if predicate(pkt)} == item.expected

    @pytest.mark.parametrize("item", MATRIX, ids=_IDS)
    def test_workspace_sql(self, workspace: Path, item: Row) -> None:
        from remora.workspace import Workspace

        with Workspace(workspace) as ws:
            frames = {r.frame_number for r in ws.query().filter(item.expr)}
        assert frames == item.expected


class TestWorkspaceRoundTrip:
    def test_rows_keep_the_printed_text(self, workspace: Path) -> None:
        from remora.workspace import Workspace

        with Workspace(workspace) as ws:
            rows = {r.frame_number: r for r in ws.query().select(*ALL_REFS)}
        stored = {n: r.get_all(NAME) for n, r in rows.items() if r.get_all(NAME)}
        assert stored == EXPECTED[NAME.name]
        assert rows[2].get(SNMP.enterprise) == "1.3.6.1.4.1.9"
        assert rows[1].get(SNMP.value_oid) == "1.3.6.1.4.1.8072.3.2.10"
