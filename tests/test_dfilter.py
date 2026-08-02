"""Golden-string tests for the Wireshark display-filter backend.

The golden (expr, expected) pairs live in dfilter_corpus.GOLDEN — shared with
tests/test_dfilter_validation.py, which syntax-validates every expected string
against a real tshark. Only cases that cannot join that corpus stay inline
here: structural assertions, deliberately fake fields, and error paths.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dfilter_corpus import DELTA, GOLDEN, PAYLOAD, PORT, SRC, TIME, GoldenCase, StubField
from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.expr import Expr

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
