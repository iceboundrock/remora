"""Golden-string tests for the Wireshark display-filter backend."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.expr import Expr, FieldExprOps


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
SRC6 = StubField("ipv6.src", "FT_IPv6")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)
HOST = StubField("http.host", "FT_STRING")
PAYLOAD = StubField("tcp.payload", "FT_BYTES")
TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")
DELTA = StubField("frame.time_delta", "FT_RELATIVE_TIME")
SYN = StubField("tcp.flags.syn", "FT_BOOLEAN")
LOSS = StubField("frame.loss", "FT_DOUBLE")
CUSTOM = StubField("x.custom", "FT_SOMETHING_NEW")


class TestComparisonOps:
    @pytest.mark.parametrize(
        ("expr", "expected"),
        [
            (PORT == 443, "tcp.port == 443"),
            (PORT < 1024, "tcp.port < 1024"),
            (PORT <= 1024, "tcp.port <= 1024"),
            (PORT > 1024, "tcp.port > 1024"),
            (PORT >= 1024, "tcp.port >= 1024"),
        ],
    )
    def test_every_op_symbol(self, expr: Expr, expected: str) -> None:
        assert compile_dfilter(expr) == expected

    def test_eq_on_multi_value_field_means_any_occurrence_matches(self) -> None:
        # Wireshark semantics: tcp.port occurs twice per packet (src and dst);
        # `tcp.port == 443` is true if ANY occurrence equals 443. That is the
        # DSL's intended meaning, so plain == passes through unchanged.
        assert PORT.multi is True
        assert compile_dfilter(PORT == 443) == "tcp.port == 443"

    def test_ne_compiles_to_negated_eq_never_bang_eq(self) -> None:
        # Wireshark's `tcp.port != 443` on a multi-value field means "SOME
        # occurrence differs" — true for almost every packet, and almost never
        # what the user meant. The DSL's != arrives as Not(Comparison(EQ, ...))
        # and must render as !(field == value): "NO occurrence equals".
        rendered = compile_dfilter(PORT != 443)
        assert rendered == "!(tcp.port == 443)"
        assert "!=" not in rendered

    def test_float_field(self) -> None:
        assert compile_dfilter(LOSS > 0.25) == "frame.loss > 0.25"

    def test_int_widened_to_float(self) -> None:
        assert compile_dfilter(LOSS > 1) == "frame.loss > 1.0"


class TestPresence:
    def test_presence_renders_bare_field_name(self) -> None:
        assert compile_dfilter(SRC.present()) == "ip.src"


class TestBooleanStructure:
    def test_and(self) -> None:
        expr = (SRC == "10.0.0.1") & (PORT == 443)
        assert compile_dfilter(expr) == "(ip.src == 10.0.0.1) && (tcp.port == 443)"

    def test_or(self) -> None:
        expr = (SRC == "10.0.0.1") | (DST == "10.0.0.2")
        assert compile_dfilter(expr) == "(ip.src == 10.0.0.1) || (ip.dst == 10.0.0.2)"

    def test_not_always_wraps_in_bang_parens(self) -> None:
        assert compile_dfilter(~SRC.present()) == "!(ip.src)"

    def test_nested_not_over_or_conjoined(self) -> None:
        expr = ~((SRC == "10.0.0.1") | (PORT == 443)) & (DST == "10.0.0.2")
        assert compile_dfilter(expr) == (
            "(!((ip.src == 10.0.0.1) || (tcp.port == 443))) && (ip.dst == 10.0.0.2)"
        )

    def test_parens_preserve_tree_shape_for_associativity(self) -> None:
        a, b, c = SRC == "10.0.0.1", PORT == 443, DST == "10.0.0.2"
        left_leaning = (a & b) & c
        right_leaning = a & (b & c)
        assert compile_dfilter(left_leaning) == (
            "((ip.src == 10.0.0.1) && (tcp.port == 443)) && (ip.dst == 10.0.0.2)"
        )
        assert compile_dfilter(right_leaning) == (
            "(ip.src == 10.0.0.1) && ((tcp.port == 443) && (ip.dst == 10.0.0.2))"
        )

    def test_or_inside_and_inside_not(self) -> None:
        expr = ~((SRC.present() & (PORT >= 1024)) | (SYN == True))  # noqa: E712
        assert compile_dfilter(expr) == (
            "!(((ip.src) && (tcp.port >= 1024)) || (tcp.flags.syn == 1))"
        )

    def test_double_negation_keeps_both_wrappers(self) -> None:
        assert compile_dfilter(~~(PORT == 443)) == "!(!(tcp.port == 443))"


class TestStringLiterals:
    def test_plain_string_is_double_quoted(self) -> None:
        assert compile_dfilter(HOST == "example.com") == 'http.host == "example.com"'

    def test_embedded_quote_is_escaped(self) -> None:
        assert compile_dfilter(HOST == 'say "hi"') == 'http.host == "say \\"hi\\""'

    def test_backslash_is_escaped(self) -> None:
        assert compile_dfilter(HOST == "a\\b") == 'http.host == "a\\\\b"'

    def test_backslash_before_quote(self) -> None:
        assert compile_dfilter(HOST == '\\"') == 'http.host == "\\\\\\""'

    def test_non_ascii_passes_through_unescaped(self) -> None:
        assert compile_dfilter(HOST == "café.example") == 'http.host == "café.example"'

    def test_unknown_ftype_falls_back_to_quoted_string(self) -> None:
        assert compile_dfilter(CUSTOM == "hello") == 'x.custom == "hello"'


class TestAddressLiterals:
    def test_ipv4_from_str_literal_normalizes_and_renders_bare(self) -> None:
        assert compile_dfilter(SRC == "10.0.0.1") == "ip.src == 10.0.0.1"

    def test_ipv4_address_object_renders_bare(self) -> None:
        from ipaddress import IPv4Address

        # SIM300 ("Yoda condition") is suppressed here and below: swapping
        # operands would dispatch to the literal's own operator, not the field's.
        assert compile_dfilter(SRC == IPv4Address("10.0.0.1")) == "ip.src == 10.0.0.1"  # noqa: SIM300

    def test_ipv6_normalizes_to_compressed_form(self) -> None:
        assert compile_dfilter(SRC6 == "2001:0db8:0::1") == "ipv6.src == 2001:db8::1"

    def test_bad_ip_literal_raises_value_error_not_unsupported(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_dfilter(SRC == "not-an-ip")


class TestBytesLiterals:
    def test_bytes_render_as_colon_hex(self) -> None:
        assert compile_dfilter(PAYLOAD == b"\xaa\xbb\xcc") == "tcp.payload == aa:bb:cc"

    def test_bytes_from_str_literal(self) -> None:
        assert compile_dfilter(PAYLOAD == "aabbcc") == "tcp.payload == aa:bb:cc"

    def test_empty_bytes_raise_unsupported(self) -> None:
        with pytest.raises(UnsupportedExprError, match="empty bytes"):
            compile_dfilter(PAYLOAD == b"")


class TestBoolLiterals:
    def test_true_renders_as_1(self) -> None:
        assert compile_dfilter(SYN == True) == "tcp.flags.syn == 1"  # noqa: E712

    def test_false_renders_as_0(self) -> None:
        assert compile_dfilter(SYN == False) == "tcp.flags.syn == 0"  # noqa: E712


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
