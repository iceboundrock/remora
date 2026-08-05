"""Tests for the Expr IR: operator construction, guards, and structural comparison."""

from __future__ import annotations

import dataclasses

import pytest

import remora.expr as ex
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Contains,
    Expr,
    FieldExprOps,
    FieldLike,
    Matches,
    Membership,
    Not,
    Or,
    Presence,
    ValueRange,
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
HOST = StubField("http.host", "FT_STRING")


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

    def test_fields_are_unhashable(self) -> None:
        """Defining __eq__ (returning Expr) disables hashing; dedup by .name."""
        with pytest.raises(TypeError, match="unhashable"):
            hash(SRC)


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


class TestExtendedOperatorConstruction:
    def test_in_builds_membership(self) -> None:
        e = PORT.in_([80, 443])
        assert isinstance(e, Membership)
        assert e.field.name == "tcp.port"
        assert e.values == (80, 443)

    def test_in_converts_range_to_inclusive_value_range(self) -> None:
        e = PORT.in_([range(8000, 8081)])
        assert e.values == (ValueRange(8000, 8080),)

    def test_in_converts_pair_tuple_to_value_range(self) -> None:
        e = PORT.in_([(6000, 6002)])
        assert e.values == (ValueRange(6000, 6002),)

    def test_in_accepts_mixed_scalars_and_ranges(self) -> None:
        e = PORT.in_([443, (8000, 8080)])
        assert e.values == (443, ValueRange(8000, 8080))

    def test_in_rejects_empty_set(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            PORT.in_([])

    def test_in_rejects_stepped_range(self) -> None:
        with pytest.raises(ValueError, match="step"):
            PORT.in_([range(0, 10, 2)])

    def test_in_rejects_empty_range(self) -> None:
        with pytest.raises(ValueError, match="empty range"):
            PORT.in_([range(5, 5)])

    def test_in_rejects_non_literal_elements(self) -> None:
        with pytest.raises(TypeError, match="membership"):
            PORT.in_([[80, 443]])

    def test_in_rejects_bare_string(self) -> None:
        with pytest.raises(TypeError, match="per-character"):
            PORT.in_("80")

    def test_in_rejects_bare_bytes(self) -> None:
        with pytest.raises(TypeError, match="per-character"):
            PORT.in_(b"80")

    def test_contains_builds_node(self) -> None:
        e = HOST.contains("example")
        assert isinstance(e, Contains)
        assert e.field.name == "http.host"
        assert e.needle == "example"

    def test_contains_rejects_empty_needle(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            HOST.contains("")
        with pytest.raises(ValueError, match="empty"):
            HOST.contains(b"")

    def test_contains_rejects_non_str_bytes_needle(self) -> None:
        with pytest.raises(TypeError, match="needle"):
            Contains(HOST, 443)  # type: ignore[arg-type]

    def test_matches_builds_node(self) -> None:
        e = HOST.matches("^ex.*com$")
        assert isinstance(e, Matches)
        assert e.pattern == "^ex.*com$"

    def test_matches_rejects_invalid_regex_at_construction(self) -> None:
        with pytest.raises(ValueError, match="invalid regular expression"):
            HOST.matches("[unclosed")


class TestInOperatorGuard:
    """Python's `in` operator is NOT the membership API (issue #17 contract):
    `in` coerces `__contains__`'s result to bool, so it can never build an
    Expr — it must fail loudly, pointing the user at .in_()/.contains()."""

    def test_python_in_raises_pointing_to_in_(self) -> None:
        with pytest.raises(TypeError, match=r"in_"):
            443 in PORT  # noqa: B015

    def test_python_in_mentions_contains_alternative(self) -> None:
        with pytest.raises(TypeError, match="contains"):
            "example" in HOST  # noqa: B015


class TestExtendedStructuralEquals:
    def test_membership_equal_and_order_sensitive(self) -> None:
        assert PORT.in_([80, 443]).equals(PORT.in_([80, 443]))
        assert not PORT.in_([80, 443]).equals(PORT.in_([443, 80]))
        assert not PORT.in_([80]).equals(PORT.in_([80, 443]))
        assert not PORT.in_([80]).equals(StubField("udp.port", "FT_UINT16").in_([80]))

    def test_membership_range_vs_scalar_not_equal(self) -> None:
        assert not PORT.in_([(80, 80)]).equals(PORT.in_([80]))

    def test_membership_literal_type_matters(self) -> None:
        assert not PORT.in_([1]).equals(PORT.in_([True]))

    def test_contains_equal_and_needle_type_matters(self) -> None:
        assert HOST.contains("ab").equals(HOST.contains("ab"))
        assert not HOST.contains("ab").equals(HOST.contains("cd"))
        assert not HOST.contains("ab").equals(HOST.contains(b"ab"))

    def test_matches_equal_by_field_and_pattern(self) -> None:
        assert HOST.matches("x").equals(HOST.matches("x"))
        assert not HOST.matches("x").equals(HOST.matches("y"))
        assert not HOST.matches("x").equals(SRC.matches("x"))

    def test_extended_nodes_differ_from_other_node_types(self) -> None:
        assert not PORT.in_([80]).equals(PORT == 80)
        assert not HOST.contains("a").equals(HOST.matches("a"))


class TestExtendedWalkers:
    def test_field_refs_walks_extended_nodes(self) -> None:
        tree = (PORT.in_([80]) & HOST.contains("a")) | ~HOST.matches("b")
        names = [f.name for f in field_refs(tree)]
        assert names == ["tcp.port", "http.host", "http.host"]


class TestMatchesCommonSubset:
    """matches() accepts only the Python-re/PCRE2 common subset (PR #73):
    a pattern must mean the same thing whether it is pushed to tshark (PCRE2)
    or evaluated as a residual predicate (Python re), so dialect-specific
    constructs are rejected at construction — on every Python version."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "",
            "example",
            "^ex.*com$",
            "a.c",
            "foo|bar",
            "[a-z0-9]+",
            "[^/]{1,8}",
            "ab{2,3}c",
            "ab{2,}?c",
            r"foo\.bar",
            r"\d+\.\d+",
            r"\bword\b",
            r"(?:ab)+?",
            r"(?=look)a",
            r"(?!no)a",
            r"(?<=pre)a",
            r"(?<!pre)a",
            r"(a|b)c",
            r"\x2f",
            r"[\d\s-]",
            "café",
            # A ']' first in a class is a literal in both dialects, not the
            # terminator — the scanner must skip it (PR #73 review round 2).
            "[]a]",
        ],
    )
    def test_common_subset_patterns_accepted(self, pattern: str) -> None:
        assert HOST.matches(pattern).pattern == pattern

    @pytest.mark.parametrize(
        ("pattern", "construct"),
        [
            ("(?|alpha|gamma)", "group"),  # PCRE2 branch reset (the review's repro)
            ("(?>a+)b", "group"),  # atomic group
            ("a*+", "possessive"),
            ("a++", "possessive"),
            ("ab{2,3}+c", "possessive"),
            ("(?i)a", "group"),  # inline flags
            ("(?P<name>a)", "group"),  # named group, Python spelling
            ("(?<name>a)", "group"),  # named group, PCRE2 spelling
            ("(?#comment)a", "group"),
            ("(?(1)a|b)", "group"),  # conditional
            (r"(a)\1", "escape"),  # backreference
            (r"\Astart", "escape"),
            (r"\h+", "escape"),  # PCRE2 horizontal whitespace
            (r"\p{L}", "escape"),  # unicode property
            (r"\x{2f}", "escape"),  # PCRE2 braced hex
            ("[[:alpha:]]", "character class"),  # POSIX class
            # Leading ']' is a class member, so the POSIX class is still nested.
            ("[][:alpha:]]", "character class"),
            ("{,3}", "quantifier"),  # Python reads {0,3}; PCRE2 reads literal text
            # PCRE2 limits brace repeat counts to 65535; Python does not.
            ("a{70000}", "quantifier"),
            ("a{0,65536}", "quantifier"),
            # Python re: a vertical-tab character. PCRE2: the vertical
            # whitespace CLASS — and '[\v-z]' is a hard PCRE2 error.
            (r"\v", "escape"),
            (r"[\v-z]", "escape"),
        ],
    )
    def test_dialect_specific_patterns_rejected(self, pattern: str, construct: str) -> None:
        with pytest.raises(ValueError, match="common subset") as exc_info:
            HOST.matches(pattern)
        assert construct in str(exc_info.value)

    def test_syntax_errors_still_reported_as_invalid_regex(self) -> None:
        with pytest.raises(ValueError, match="invalid regular expression"):
            HOST.matches("[unclosed")
