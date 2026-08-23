"""Golden-string tests for the Wireshark display-filter backend.

The golden (expr, expected) pairs live in dfilter_corpus.GOLDEN — shared with
tests/test_dfilter_validation.py, which syntax-validates every expected string
against a real tshark. Only cases that cannot join that corpus stay inline
here: structural assertions, deliberately fake fields, and error paths.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dfilter_corpus import (
    DELTA,
    GOLDEN,
    HOST,
    PAYLOAD,
    PORT,
    RESPTIME,
    SRC,
    TIME,
    GoldenCase,
    StubField,
)
from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.expr import Expr

NAN = float("nan")
INF = float("inf")

# Deliberately fake: exercises the unknown-ftype fallback. Its golden string
# can never validate against a real tshark, so it is excluded from GOLDEN.
CUSTOM = StubField("x.custom", "FT_SOMETHING_NEW")


class TestGoldenCorpus:
    @pytest.mark.parametrize("case", GOLDEN, ids=[case.id for case in GOLDEN])
    def test_compiles_to_golden_string(self, case: GoldenCase) -> None:
        assert compile_dfilter(case.expr) == case.expected

    def test_corpus_ids_are_unique(self) -> None:
        ids = [case.id for case in GOLDEN]
        assert len(ids) == len(set(ids))


class TestStructuralInvariants:
    def test_eq_on_multi_value_field_means_any_occurrence_matches(self) -> None:
        # Wireshark semantics: tcp.port occurs twice per packet (src and dst);
        # `tcp.port == 443` is true if ANY occurrence equals 443. That is the
        # DSL's intended meaning, so plain == passes through unchanged.
        assert PORT.multi is True
        assert compile_dfilter(PORT == 443) == "tcp.port == 443"

    def test_ne_compiles_to_negated_eq_never_bang_eq(self) -> None:
        # Wireshark's `tcp.port != 443` on a multi-value field means "SOME
        # occurrence differs" — almost never what the user meant. The DSL's !=
        # arrives as Not(Comparison(EQ, ...)) and must render as
        # !(field == value): "NO occurrence equals".
        rendered = compile_dfilter(PORT != 443)
        assert rendered == "!(tcp.port == 443)"
        assert "!=" not in rendered


class TestFallbacksAndErrors:
    def test_unknown_ftype_falls_back_to_quoted_string(self) -> None:
        assert compile_dfilter(CUSTOM == "hello") == 'x.custom == "hello"'

    def test_bad_ip_literal_raises_value_error_not_unsupported(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_dfilter(SRC == "not-an-ip")

    def test_empty_bytes_raise_unsupported(self) -> None:
        with pytest.raises(UnsupportedExprError, match="empty bytes"):
            compile_dfilter(PAYLOAD == b"")


class TestUnsupported:
    def test_datetime_comparison_raises_unsupported(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(UnsupportedExprError, match="time comparisons"):
            compile_dfilter(TIME >= moment)  # noqa: SIM300

    def test_timedelta_comparison_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedExprError, match="time comparisons"):
            compile_dfilter(DELTA > timedelta(milliseconds=1))  # noqa: SIM300

    def test_unknown_expr_subclass_raises_unsupported(self) -> None:
        class FutureNode(Expr):
            __slots__ = ()

        with pytest.raises(UnsupportedExprError, match="FutureNode"):
            compile_dfilter(FutureNode())


class TestExtendedOperatorErrors:
    """User errors (TypeError/ValueError), never UnsupportedExprError — the
    same compile-time policy as malformed literals."""

    def test_contains_needle_type_must_match_field_type(self) -> None:
        with pytest.raises(TypeError, match="needle"):
            compile_dfilter(HOST.contains(b"ab"))
        with pytest.raises(TypeError, match="needle"):
            compile_dfilter(PAYLOAD.contains("GET"))

    def test_contains_on_non_string_non_bytes_field_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="needle"):
            compile_dfilter(PORT.contains("80"))

    def test_matches_on_non_string_field_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="string fields"):
            compile_dfilter(PORT.matches("443"))

    def test_inverted_range_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="inverted"):
            compile_dfilter(PORT.in_([(443, 80)]))

    def test_bad_element_literal_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_dfilter(SRC.in_(["not-an-ip"]))

    def test_time_membership_raises_unsupported(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(UnsupportedExprError, match="time comparisons"):
            compile_dfilter(TIME.in_([moment]))


class TestNaNLiterals:
    """IEEE-754 NaN is refused (issue #90), everywhere a float literal can reach
    the renderer.

    Python's comparisons with NaN are all false, so the predicate backend the
    planner falls back to already has the right answer; Wireshark's engine does
    not agree, and what it does instead is ftype- and version-dependent (see
    tests/test_dfilter_validation.py::TestNaNIsARecognizedDfilterLiteral).
    """

    @pytest.mark.parametrize(
        "expr",
        [
            RESPTIME == NAN,
            RESPTIME < NAN,
            RESPTIME <= NAN,
            RESPTIME > NAN,
            RESPTIME >= NAN,
        ],
        ids=["eq", "lt", "le", "gt", "ge"],
    )
    def test_every_comparison_operator_refuses_nan(self, expr: Expr) -> None:
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(expr)

    def test_ne_refuses_nan(self) -> None:
        # The DSL's != is Not(Comparison(EQ, ...)); the refusal has to survive
        # the wrapper rather than rendering `!(icmp.resptime == nan)`.
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(RESPTIME != NAN)

    @pytest.mark.parametrize("text", ["nan", "NaN", "-nan"], ids=["lower", "mixed", "signed"])
    def test_string_literal_parsed_to_nan_is_refused(self, text: str) -> None:
        # coerce_literal parses a str with float(), so "nan" arrives as a NaN
        # float: the check has to be on the COERCED value, not on the input.
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(RESPTIME == text)  # noqa: SIM300

    def test_membership_element_refuses_nan(self) -> None:
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(RESPTIME.in_([NAN]))

    def test_membership_refuses_nan_beside_a_good_element(self) -> None:
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(RESPTIME.in_([0.25, NAN]))

    @pytest.mark.parametrize(
        "bounds",
        [(NAN, 1.0), (1.0, NAN), (NAN, NAN)],
        ids=["nan-lo", "nan-hi", "both"],
    )
    def test_range_endpoint_refuses_nan(self, bounds: tuple[float, float]) -> None:
        # Checked before the inverted-range test: `hi < lo` is false for a NaN
        # endpoint, so the inversion check can never fire on one and the
        # refusal must not depend on it.
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter(RESPTIME.in_([bounds]))

    def test_nan_nested_in_boolean_structure_refuses(self) -> None:
        with pytest.raises(UnsupportedExprError, match="NaN"):
            compile_dfilter((SRC == "10.0.0.1") & (RESPTIME > NAN))

    def test_refusal_names_the_python_predicate_fallback(self) -> None:
        with pytest.raises(UnsupportedExprError, match="Python predicate"):
            compile_dfilter(RESPTIME > NAN)


class TestInfinityLiterals:
    """``inf``/``-inf`` are deliberately NOT refused: Wireshark orders them the
    way Python does, so the pushdown is sound. Pinned so nobody "completes" the
    NaN rule by sweeping them in — a real tshark accepts every string below
    (tests/test_dfilter_validation.py)."""

    def test_gt_infinity_renders(self) -> None:
        assert compile_dfilter(RESPTIME > INF) == "icmp.resptime > inf"

    def test_lt_negative_infinity_renders(self) -> None:
        assert compile_dfilter(RESPTIME < -INF) == "icmp.resptime < -inf"

    def test_eq_infinity_renders(self) -> None:
        assert compile_dfilter(RESPTIME == INF) == "icmp.resptime == inf"

    def test_ne_infinity_renders(self) -> None:
        assert compile_dfilter(RESPTIME != INF) == "!(icmp.resptime == inf)"

    def test_infinite_range_endpoint_renders(self) -> None:
        assert compile_dfilter(RESPTIME.in_([(-INF, INF)])) == "icmp.resptime in {-inf .. inf}"

    def test_string_literal_parsed_to_infinity_renders(self) -> None:
        assert compile_dfilter(RESPTIME == "inf") == "icmp.resptime == inf"
