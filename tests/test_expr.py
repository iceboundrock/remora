from __future__ import annotations

import dataclasses

import pytest

import remora.expr as ex
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Expr,
    FieldExprOps,
    FieldLike,
    Not,
    Or,
    Presence,
    conjuncts,
    field_refs,
)


class StubField(FieldExprOps):
    """Minimal FieldLike for tests; FieldRef (issue #8) will look like this."""

    __slots__ = ("_ftype", "_multi", "_name")

    def __init__(self, name: str, ftype: str = "FT_STRING", multi: bool = False) -> None:
        self._name = name
        self._ftype = ftype
        self._multi = multi

    @property
    def name(self) -> str:
        return self._name

    @property
    def ftype(self) -> str:
        return self._ftype

    @property
    def multi(self) -> bool:
        return self._multi


SRC = StubField("ip.src", "FT_IPv4")
DST = StubField("ip.dst", "FT_IPv4")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)


class TestOperatorConstruction:
    def test_eq_builds_comparison(self) -> None:
        e = SRC == "10.0.0.1"
        assert isinstance(e, Comparison)
        assert e.op is CompareOp.EQ
        assert e.field.name == "ip.src"
        assert e.value == "10.0.0.1"

    def test_ne_builds_not_eq_structurally(self) -> None:
        e = PORT != 443
        assert isinstance(e, Not)
        assert isinstance(e.operand, Comparison)
        assert e.operand.op is CompareOp.EQ
        assert e.operand.value == 443

    def test_there_is_no_ne_node_or_op(self) -> None:
        assert not hasattr(ex, "Ne")
        assert "NE" not in CompareOp.__members__

    @pytest.mark.parametrize(
        ("build", "op"),
        [
            (lambda: PORT < 1024, CompareOp.LT),
            (lambda: PORT <= 1024, CompareOp.LE),
            (lambda: PORT > 1024, CompareOp.GT),
            (lambda: PORT >= 1024, CompareOp.GE),
        ],
    )
    def test_ordering_operators(self, build: object, op: CompareOp) -> None:
        e = build()  # type: ignore[operator]
        assert isinstance(e, Comparison)
        assert e.op is op

    def test_logical_connectives(self) -> None:
        a, b = SRC == "10.0.0.1", PORT == 443
        both = a & b
        assert isinstance(both, And)
        assert both.left is a
        assert both.right is b
        either = a | b
        assert isinstance(either, Or)
        negated = ~a
        assert isinstance(negated, Not)
        assert negated.operand is a

    def test_present_builds_presence(self) -> None:
        e = SRC.present()
        assert isinstance(e, Presence)
        assert e.field.name == "ip.src"

    def test_field_hash_is_name_hash(self) -> None:
        assert hash(SRC) == hash("ip.src")


class TestBoolGuard:
    def test_bool_raises_pointing_to_operators(self) -> None:
        e = SRC == "10.0.0.1"
        with pytest.raises(TypeError, match=r"& \| ~"):
            bool(e)

    def test_python_and_raises(self) -> None:
        with pytest.raises(TypeError):
            (SRC == "10.0.0.1") and (PORT == 443)  # noqa: B018

    def test_chained_comparison_raises(self) -> None:
        with pytest.raises(TypeError):
            1 < PORT < 1024  # noqa: B015


class TestValidation:
    def test_list_literal_rejected(self) -> None:
        with pytest.raises(TypeError, match="unsupported literal"):
            SRC == [1, 2]  # noqa: B015

    def test_non_expr_logical_operand_rejected(self) -> None:
        with pytest.raises(TypeError, match="must be an Expr"):
            (SRC == "x") & "not an expr"  # type: ignore[operator]


class TestImmutabilityAndHashing:
    def test_nodes_are_frozen(self) -> None:
        e = SRC == "10.0.0.1"
        with pytest.raises(dataclasses.FrozenInstanceError):
            e.value = "changed"  # type: ignore[misc]

    def test_nodes_are_hashable_with_identity_semantics(self) -> None:
        a = SRC == "10.0.0.1"
        b = SRC == "10.0.0.1"
        s = {a, b}
        assert len(s) == 2  # identity hash: structurally equal but distinct objects
        assert a in s


class TestStructuralEquals:
    def test_nested_trees_equal(self) -> None:
        t1 = ((SRC == "10.0.0.1") & (PORT == 443)) | ~(DST == "10.0.0.2")
        t2 = ((SRC == "10.0.0.1") & (PORT == 443)) | ~(DST == "10.0.0.2")
        assert t1.equals(t2)
        assert t2.equals(t1)

    def test_differs_by_structure(self) -> None:
        assert not ((SRC == "a") & (PORT == 1)).equals((SRC == "a") | (PORT == 1))
        assert not (SRC == "a").equals(~(SRC == "a"))
        assert not (SRC == "a").equals("not an expr")

    def test_differs_by_field_op_or_value(self) -> None:
        assert not (SRC == "a").equals(DST == "a")
        assert not (PORT < 1).equals(PORT <= 1)
        assert not (SRC == "a").equals(SRC == "b")

    def test_literal_type_matters(self) -> None:
        assert not (PORT == 1).equals(PORT == True)  # noqa: E712
        assert not (PORT == 1).equals(PORT == 1.0)

    def test_presence_equals_by_name(self) -> None:
        assert SRC.present().equals(StubField("ip.src").present())
        assert not SRC.present().equals(DST.present())


class TestWalkers:
    def test_conjuncts_flattens_top_level_and_chain(self) -> None:
        a, b, c = SRC == "a", PORT == 1, DST == "b"
        assert list(conjuncts((a & b) & c)) == [a, b, c]
        assert list(conjuncts(a & (b & c))) == [a, b, c]

    def test_conjuncts_leaves_or_and_not_opaque(self) -> None:
        a, b, c = SRC == "a", PORT == 1, DST == "b"
        disjunction = a | b
        assert list(conjuncts(disjunction & c)) == [disjunction, c]
        negation = ~(a & b)
        assert list(conjuncts(negation)) == [negation]

    def test_conjuncts_of_single_term(self) -> None:
        a = SRC == "a"
        assert list(conjuncts(a)) == [a]

    def test_field_refs_walks_everything(self) -> None:
        tree = ((SRC == "a") & ~(PORT == 1)) | DST.present()
        names = [f.name for f in field_refs(tree)]
        assert names == ["ip.src", "tcp.port", "ip.dst"]


class TestTyping:
    def test_stub_satisfies_fieldlike(self) -> None:
        assert isinstance(SRC, FieldLike)

    def test_comparison_is_expr(self) -> None:
        e: Expr = SRC == "10.0.0.1"
        assert isinstance(e, Expr)
