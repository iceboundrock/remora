"""Unit tests for the two-level pushdown query planner (:mod:`remora.planner`).

Everything here runs without tshark: the planner only decides, so a Plan is
asserted on directly and its residual predicate is evaluated against
:class:`conftest.FakePacket` doubles.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from ipaddress import IPv4Address

import pytest

from conftest import FakePacket
from dfilter_corpus import (
    DF_DST,
    DF_NOT_SRC,
    DF_PORT_IN,
    DF_SRC,
    DF_SRC_AND_PORT,
    DF_SRC_OR_PORT,
)
from remora.fields import FieldRef, RawPacket
from remora.planner import Plan, make_plan

SRC = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
DST = FieldRef[IPv4Address]("ip.dst", "FT_IPv4", False)
PORT = FieldRef[int]("tcp.port", "FT_UINT16", True)
TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
# A FieldRef whose comparison against b"" the dfilter backend cannot render
# (empty bytes) — the simplest way to force a residual Expr that references
# an already-known field NAME; projection dedup only ever looks at .name.
PORT_BYTES = FieldRef[bytes]("tcp.port", "FT_BYTES", True)

JULY_2021 = datetime(2021, 7, 1, tzinfo=timezone.utc)  # epoch 1625097600

# The DF_* golden display-filter strings asserted below live in
# dfilter_corpus.py (with PLANNER_DFILTER_GOLDENS, which feeds them to a real
# tshark in tests/test_dfilter_validation.py); add new ones there.


class TestFullyPushed:
    def test_pure_expr_conjunction_is_fully_pushed(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", PORT == 443], select=[SRC, PORT])
        assert plan.dfilter == DF_SRC_AND_PORT
        assert plan.residual is None

    def test_select_given_yields_fields_mode_with_exactly_select(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", PORT == 443], select=[SRC, PORT])
        assert plan.mode == "fields"
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "tcp.port"]

    def test_select_none_yields_ek_mode_even_when_fully_pushed(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", PORT == 443])
        assert plan.dfilter == DF_SRC_AND_PORT
        assert plan.residual is None
        assert plan.mode == "ek"
        assert plan.projection is None

    def test_pushed_fields_are_not_projected_unless_selected(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", PORT == 443], select=[DST])
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.dst"]


class TestOpaqueLambdas:
    def test_expr_plus_lambda_splits_and_forces_ek_without_select(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", lambda pkt: True])
        assert plan.dfilter == DF_SRC
        assert plan.mode == "ek"
        assert plan.projection is None
        assert plan.residual is not None
        assert plan.residual(FakePacket({})) is True

    def test_lambda_forces_ek_even_with_select(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", lambda pkt: False], select=[SRC])
        assert plan.mode == "ek"
        assert plan.projection is None
        assert plan.residual is not None
        assert plan.residual(FakePacket({})) is False

    def test_lambda_only_query_pushes_nothing(self) -> None:
        plan = make_plan([lambda pkt: pkt.get_raw("ip.src") != ()])
        assert plan.dfilter is None
        assert plan.mode == "ek"
        assert plan.residual is not None
        assert plan.residual(FakePacket({"ip.src": ("10.0.0.1",)})) is True
        assert plan.residual(FakePacket({})) is False


class TestUnsupportedExprFallback:
    def test_time_conjunct_goes_residual_and_evaluates(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", TIME >= JULY_2021], select=[SRC])
        assert plan.dfilter == DF_SRC
        assert plan.residual is not None
        assert plan.residual(FakePacket({"frame.time": ("1625097600.000000000",)})) is True
        assert plan.residual(FakePacket({"frame.time": ("1625097599.999999000",)})) is False

    def test_residual_expr_fields_join_the_projection(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", TIME >= JULY_2021], select=[SRC])
        assert plan.mode == "fields"
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time"]

    def test_user_error_literal_raises_and_is_not_swallowed(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            make_plan([SRC == "not-an-ip"])


class TestExtendedOperatorPlanning:
    """Issue #17 nodes need no planner change: pushdown-or-residual routing and
    projection via field_refs must simply work. Pinned here end to end."""

    def test_membership_conjunct_is_pushed(self) -> None:
        plan = make_plan([PORT.in_([80, 443])], select=[PORT])
        assert plan.dfilter == DF_PORT_IN
        assert plan.residual is None
        assert plan.mode == "fields"

    def test_time_membership_is_residual_and_projected(self) -> None:
        plan = make_plan([TIME.in_([JULY_2021])], select=[SRC])
        assert plan.dfilter is None
        assert plan.residual is not None
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "frame.time"]
        assert plan.residual(FakePacket({"frame.time": ("1625097600",)})) is True
        assert plan.residual(FakePacket({"frame.time": ("1625097601",)})) is False


class TestProjection:
    def test_dedup_by_name_select_order_first_no_over_projection(self) -> None:
        # Residual Expr referencing PORT and SRC (the empty-bytes comparison
        # is unrenderable, so the whole Or goes residual); pushed conjunct on
        # DST must NOT appear in the projection.
        residual_expr = (PORT_BYTES == b"") | (SRC == "10.0.0.1")
        plan = make_plan([DST == "10.0.0.2", residual_expr], select=[SRC])
        assert plan.dfilter == DF_DST
        assert plan.mode == "fields"
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "tcp.port"]

    def test_empty_select_projects_nothing_when_no_residual(self) -> None:
        plan = make_plan([SRC == "10.0.0.1"], select=[])
        assert plan.mode == "fields"
        assert plan.projection == ()


class TestResidualComposition:
    def test_two_residual_terms_are_anded(self) -> None:
        plan = make_plan(
            [
                lambda pkt: pkt.get_raw("ip.src") != (),
                lambda pkt: pkt.get_raw("tcp.port") != (),
            ]
        )
        assert plan.residual is not None
        assert plan.residual(FakePacket({"ip.src": ("1.2.3.4",), "tcp.port": ("443",)})) is True
        assert plan.residual(FakePacket({"ip.src": ("1.2.3.4",)})) is False
        assert plan.residual(FakePacket({"tcp.port": ("443",)})) is False

    def test_evaluation_is_left_to_right_and_short_circuits(self) -> None:
        calls: list[str] = []

        def first(pkt: RawPacket) -> bool:
            calls.append("first")
            return True

        def second(pkt: RawPacket) -> bool:
            calls.append("second")
            return False

        def third(pkt: RawPacket) -> bool:
            calls.append("third")
            return True

        plan = make_plan([first, second, third])
        assert plan.residual is not None
        assert plan.residual(FakePacket({})) is False
        assert calls == ["first", "second"]

    def test_residual_exprs_run_before_opaque_callables(self) -> None:
        calls: list[str] = []

        def opaque(pkt: RawPacket) -> bool:
            calls.append("opaque")
            return True

        # The opaque term comes FIRST in the terms sequence, but residual
        # composition puts residual-Expr predicates before opaque callables.
        plan = make_plan([opaque, TIME >= JULY_2021])
        assert plan.residual is not None
        assert plan.residual(FakePacket({})) is False  # time Expr fails first
        assert calls == []


class TestTermFlattening:
    def test_nested_and_term_flattens_into_two_pushed_conjuncts(self) -> None:
        plan = make_plan([(SRC == "10.0.0.1") & (PORT == 443)])
        assert plan.dfilter == DF_SRC_AND_PORT
        assert plan.residual is None

    def test_or_term_pushes_as_a_single_conjunct(self) -> None:
        plan = make_plan([(SRC == "10.0.0.1") | (PORT == 443)])
        assert plan.dfilter == DF_SRC_OR_PORT

    def test_not_term_pushes_as_a_single_conjunct(self) -> None:
        plan = make_plan([~(SRC == "10.0.0.1")])
        assert plan.dfilter == DF_NOT_SRC


class TestEmptyTerms:
    def test_empty_terms_without_select(self) -> None:
        plan = make_plan([])
        assert plan.dfilter is None
        assert plan.residual is None
        assert plan.mode == "ek"
        assert plan.projection is None

    def test_empty_terms_with_select(self) -> None:
        plan = make_plan([], select=[SRC, PORT])
        assert plan.dfilter is None
        assert plan.residual is None
        assert plan.mode == "fields"
        assert plan.projection is not None
        assert [ref.name for ref in plan.projection] == ["ip.src", "tcp.port"]


class TestExplainAndRepr:
    def test_explain_fields_mode(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", TIME >= JULY_2021], select=[SRC])
        text = plan.explain()
        assert "mode: fields" in text
        assert f"dfilter (-Y): {DF_SRC}" in text
        assert "projection: ip.src, frame.time" in text
        assert "residual: 1 conjunct(s)" in text

    def test_explain_ek_mode_nothing_pushed(self) -> None:
        plan = make_plan([lambda pkt: True, lambda pkt: True])
        text = plan.explain()
        assert "mode: ek" in text
        assert "dfilter (-Y): (none)" in text
        assert "projection: (all fields — ek mode)" in text
        assert "residual: 2 conjunct(s)" in text

    def test_explain_no_residual(self) -> None:
        plan = make_plan([SRC == "10.0.0.1"], select=[SRC])
        assert "residual: none" in plan.explain()

    def test_repr_is_one_line_summary(self) -> None:
        plan = make_plan([SRC == "10.0.0.1", lambda pkt: True])
        text = repr(plan)
        assert "\n" not in text
        assert text.startswith("<Plan mode=ek ")
        assert f"'{DF_SRC}'" in text
        assert "1 conjunct(s)" in text

    def test_plan_is_a_plain_dataclass_usable_without_tshark(self) -> None:
        plan = make_plan([SRC == "10.0.0.1"], select=[SRC])
        assert isinstance(plan, Plan)
        # Frozen: decisions are immutable once planned.
        with pytest.raises(dataclasses.FrozenInstanceError):
            plan.mode = "ek"  # type: ignore[misc]
