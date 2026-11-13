"""``FT_GUID`` and ``FT_EUI64`` through a live tshark and a real workspace (issue #69).

#69 typed GUIDs as :class:`uuid.UUID` and EUI-64s as 8 ``bytes``. This suite
holds the decision's end-to-end gate over ``tests/fixtures/guid_eui64.pcap``:

- both readers print the same text and it reads as the values the fixture was
  built with, through the generated descriptors;
- for every expression below, the display-filter pushdown, the Python residual
  in ``-T fields`` and ``-T ek`` mode, and the workspace's SQL select the same
  frames, which are also the frames the expression is declared to select;
- a workspace round trip (materialize, read, Parquet export) keeps the values.

Two shapes are refused on ``-Y`` because tshark answers them differently by
version: ordered GUID comparisons (4.2.2 orders the host-endian struct, 4.6.9
the text) and ``contains`` on an EUI-64 (4.2.2 rejects it). The matrix pins
that the planner does refuse them, so the row sets below cannot depend on
which build runs the suite. Nothing is version-gated.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from typing_extensions import assert_type

from remora import DNS, Capture
from remora.compile.predicate import compile_predicate
from remora.compile.sql import UnsupportedSqlExprError
from remora.expr import Expr
from remora.fields import FieldRef, RawPacket
from remora.proto import DHCP, ICMPV6, SIP
from remora.values import convert

GUID_EUI64 = Path(__file__).resolve().parent.parent / "fixtures" / "guid_eui64.pcap"

FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)
ALL_FRAMES = frozenset({1, 2, 3, 4, 5})

GUID_A = UUID("33221100-5544-7766-8899-aabbccddeeff")
GUID_LOW = UUID("00000034-0000-0000-0000-000000000000")
SIP_LOCAL = UUID("ab30317f-1a78-4dc4-8ff8-24d0d3715d86")
SIP_REMOTE = UUID("47755a9d-e779-4ba3-8765-3f2099600ef2")
EUI64_A = bytes.fromhex("0211223344556677")
EUI64_B = bytes.fromhex("fe0000000000a1b2")

GUID_REFS: tuple[FieldRef[UUID], ...] = (
    DHCP.client_id_uuid,
    SIP.Session_ID_local_uuid,
    SIP.Session_ID_remote_uuid,
)
EUI64_REFS: tuple[FieldRef[bytes], ...] = (
    DNS.eui64,
    ICMPV6.opt_src_linkaddr_eui64,
    ICMPV6.opt_aro_eui64,
)
ALL_REFS: tuple[FieldRef[Any], ...] = (*GUID_REFS, *EUI64_REFS)

#: Per field, frame number -> value, from tests/fixtures/make_fixtures.py.
EXPECTED: dict[str, dict[int, object]] = {
    DHCP.client_id_uuid.name: {1: GUID_A, 5: GUID_LOW},
    SIP.Session_ID_local_uuid.name: {2: SIP_LOCAL},
    SIP.Session_ID_remote_uuid.name: {2: SIP_REMOTE},
    DNS.eui64.name: {3: EUI64_A},
    ICMPV6.opt_src_linkaddr_eui64.name: {4: EUI64_B},
    ICMPV6.opt_aro_eui64.name: {4: EUI64_A},
}

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


def _ek() -> list[RawPacket]:
    cap = Capture(GUID_EUI64)
    assert cap.plan().mode == "ek"
    return list(cap)


def _fields() -> list[RawPacket]:
    cap = Capture(GUID_EUI64).select(FRAME_NUMBER, *ALL_REFS)
    assert cap.plan().mode == "fields"
    return list(cap)


def _frame(pkt: RawPacket) -> int:
    return int(pkt.get_raw("frame.number")[0])


def _values(packets: Sequence[RawPacket], ref: FieldRef[Any]) -> dict[int, object]:
    """Frame number -> the one converted occurrence of *ref*, for frames carrying it."""
    found: dict[int, object] = {}
    for pkt in packets:
        raw = pkt.get_raw(ref.name)
        if raw:
            (text,) = raw
            found[_frame(pkt)] = convert(ref.ftype, text)
    return found


class TestReadersAgree:
    @pytest.mark.parametrize("ref", ALL_REFS, ids=lambda ref: ref.name)
    def test_ek_and_fields_read_the_built_values(self, ref: FieldRef[Any]) -> None:
        assert _values(_ek(), ref) == EXPECTED[ref.name]
        assert _values(_fields(), ref) == EXPECTED[ref.name]

    def test_both_readers_print_the_same_text(self) -> None:
        # The precondition the parity rests on, pinned so a tshark that starts
        # printing braces or dashes is caught here rather than as a ValueError.
        ek = {_frame(pkt): pkt for pkt in _ek()}
        for pkt in _fields():
            for ref in ALL_REFS:
                assert pkt.get_raw(ref.name) == ek[_frame(pkt)].get_raw(ref.name), ref.name
        sip = ek[2].get_raw(SIP.Session_ID_local_uuid.name)
        # Upper-case on the wire, lower-case in the rendering.
        assert sip == (str(SIP_LOCAL),)
        assert ek[4].get_raw(ICMPV6.opt_aro_eui64.name) == ("02:11:22:33:44:55:66:77",)

    def test_the_little_endian_wire_guid_reads_as_printed(self) -> None:
        # dhcp.client_id.uuid is 00 11 22 .. ff on the wire, read little-endian
        # by the dissector; the UUID is what Wireshark shows, not the wire bytes.
        assert UUID(bytes=bytes.fromhex("00112233445566778899aabbccddeeff")) != GUID_A
        assert UUID(bytes_le=bytes.fromhex("00112233445566778899aabbccddeeff")) == GUID_A

    def test_typed_access_through_the_generated_classes(self) -> None:
        assert_type(DHCP.client_id_uuid, FieldRef[UUID])
        assert_type(DNS.eui64, FieldRef[bytes])
        packets = {_frame(pkt): pkt for pkt in Capture(GUID_EUI64)}
        guid = packets[1][DHCP].client_id_uuid
        eui = packets[3][DNS].eui64
        assert_type(guid, UUID | None)
        assert_type(eui, bytes | None)
        assert guid == GUID_A
        assert isinstance(guid, UUID)
        assert eui == EUI64_A
        assert packets[4][ICMPV6].opt_src_linkaddr_eui64 == EUI64_B
        assert packets[3][DHCP].client_id_uuid is None


@dataclass(frozen=True)
class Row:
    """One expression, the frames it selects, and whether ``-Y`` may carry it."""

    label: str
    expr: Expr
    expected: frozenset[int]
    pushed: bool
    sql_refused: bool = False


def row(label: str, expr: Expr, expected: set[int], *, pushed: bool, **kw: bool) -> Row:
    return Row(label, expr, frozenset(expected), pushed, **kw)


MATRIX: list[Row] = [
    row("guid ==", DHCP.client_id_uuid == str(GUID_A).upper(), {1}, pushed=True),
    row("guid != (absent included)", DHCP.client_id_uuid != GUID_A, {2, 3, 4, 5}, pushed=True),
    row("guid in set", DHCP.client_id_uuid.in_([GUID_LOW, SIP_LOCAL]), {5}, pushed=True),
    # 4.2.2 would select nothing here: frame 1 sorts below GUID_LOW by struct.
    row("guid >", DHCP.client_id_uuid > GUID_LOW, {1}, pushed=False),
    row("guid <=", DHCP.client_id_uuid <= GUID_LOW, {5}, pushed=False),
    row("guid range", DHCP.client_id_uuid.in_([(GUID_LOW, GUID_A)]), {1, 5}, pushed=False),
    row("second guid field >", SIP.Session_ID_remote_uuid > GUID_A, {2}, pushed=False),
    row("sip local ==", SIP.Session_ID_local_uuid == SIP_LOCAL, {2}, pushed=True),
    row("eui64 ==", DNS.eui64 == "02:11:22:33:44:55:66:77", {3}, pushed=True),
    row("eui64 != (absent included)", DNS.eui64 != EUI64_A, {1, 2, 4, 5}, pushed=True),
    row("eui64 >", ICMPV6.opt_src_linkaddr_eui64 > EUI64_A, {4}, pushed=True),
    row("eui64 <", ICMPV6.opt_src_linkaddr_eui64 < EUI64_A, set(), pushed=True),
    row(
        "eui64 range",
        ICMPV6.opt_aro_eui64.in_([("02:00:00:00:00:00:00:00", "02:ff:00:00:00:00:00:00")]),
        {4},
        pushed=True,
    ),
    row(
        "eui64 or", (DNS.eui64 == EUI64_A) | (ICMPV6.opt_aro_eui64 == EUI64_A), {3, 4}, pushed=True
    ),
    row(
        "refused term inside an or",
        (DHCP.client_id_uuid > GUID_LOW) | (DNS.eui64 == EUI64_A),
        {1, 3},
        pushed=False,
    ),
    row(
        "eui64 contains",
        DNS.eui64.contains(b"\x22\x33"),
        {3},
        pushed=False,
        sql_refused=True,
    ),
]

_IDS = [item.label for item in MATRIX]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    duckdb = pytest.importorskip("duckdb")
    del duckdb
    from remora.workspace import Workspace

    path = tmp_path_factory.mktemp("guid_eui64") / "ws.duckdb"
    with Workspace(path, mode="rw") as ws:
        result = ws.materialize(GUID_EUI64, list(ALL_REFS))
        assert result.row_count == len(ALL_FRAMES)
    return path


class TestRowSetParity:
    @pytest.mark.parametrize("item", MATRIX, ids=_IDS)
    def test_pushdown_or_residual_as_planned(self, item: Row) -> None:
        cap = Capture(GUID_EUI64).filter(item.expr)
        plan = cap.plan()
        assert (plan.dfilter is not None) is item.pushed, plan.explain()
        assert (plan.residual is None) is item.pushed, plan.explain()
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
            query = ws.query().filter(item.expr)
            if item.sql_refused:
                with pytest.raises(UnsupportedSqlExprError, match="BLOB"):
                    list(query)
                return
            frames = {r.frame_number for r in query}
        assert frames == item.expected


class TestWorkspaceRoundTrip:
    def test_rows_decode_to_the_built_values(self, workspace: Path) -> None:
        from remora.workspace import Workspace

        with Workspace(workspace) as ws:
            rows = {r.frame_number: r for r in ws.query().select(*ALL_REFS)}
        for ref in ALL_REFS:
            stored = {n: r.get(ref) for n, r in rows.items() if r.get(ref) is not None}
            assert stored == EXPECTED[ref.name], ref.name
        guid = rows[1].get(DHCP.client_id_uuid)
        assert_type(guid, UUID | None)
        assert isinstance(guid, UUID)

    def test_parquet_export_keeps_the_values(self, workspace: Path, tmp_path: Path) -> None:
        import duckdb

        from remora.workspace import Workspace

        target = tmp_path / "pkts.parquet"
        with Workspace(workspace) as ws:
            ws.export_parquet("pkts", target)
        con = duckdb.connect()
        try:
            types = dict(
                con.execute(
                    "SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM read_parquet(?))",
                    [str(target)],
                ).fetchall()
            )
            assert types["dhcp_client_id_uuid"] == "UUID"
            assert types["dns_eui64"] == "BLOB"
            exported = con.execute(
                "SELECT frame_number, dhcp_client_id_uuid, dns_eui64 FROM read_parquet(?) "
                "ORDER BY frame_number",
                [str(target)],
            ).fetchall()
        finally:
            con.close()
        assert exported[0] == (1, GUID_A, None)
        assert exported[2] == (3, None, EUI64_A)
        assert exported[4] == (5, GUID_LOW, None)

    def test_arrow_renders_a_guid_as_its_text(self, workspace: Path) -> None:
        pytest.importorskip("pyarrow")
        from remora.workspace import Workspace

        with Workspace(workspace) as ws:
            table = ws.query().select(DHCP.client_id_uuid, DNS.eui64).arrow()
        values = dict(
            zip(
                table.column("frame_number").to_pylist(),
                table.column("dhcp_client_id_uuid").to_pylist(),
                strict=True,
            )
        )
        assert values[1] == str(GUID_A)
        assert str(table.schema.field("dns_eui64").type) == "binary"
