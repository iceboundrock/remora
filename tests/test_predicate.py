"""Unit tests for the Python predicate backend (:mod:`remora.compile.predicate`).

Covers the predicate backend alone; the table-driven suite shared with the
display-filter backend lives in ``tests/test_semantics_table.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from remora.compile.predicate import compile_predicate
from remora.expr import Expr, FieldExprOps


class StubField(FieldExprOps):
    """Minimal FieldLike for tests; FieldRef (issue #8) looks like this."""

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


class FakePacket:
    """Minimal RawPacket: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())


SRC = StubField("ip.src", "FT_IPv4")
DST = StubField("ip.dst", "FT_IPv4")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)
TTL = StubField("ip.ttl", "FT_UINT8")
HOST = StubField("http.host", "FT_STRING")
PAYLOAD = StubField("tcp.payload", "FT_BYTES")
TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")
DELTA = StubField("frame.time_delta", "FT_RELATIVE_TIME")
SYN = StubField("tcp.flags.syn", "FT_BOOLEAN")
LOSS = StubField("frame.loss", "FT_DOUBLE")
CUSTOM = StubField("x.custom", "FT_SOMETHING_NEW")

EMPTY = FakePacket({})


class TestScalarComparisons:
    def test_eq_match(self) -> None:
        pred = compile_predicate(SRC == "10.0.0.1")
        assert pred(FakePacket({"ip.src": ("10.0.0.1",)})) is True

    def test_eq_mismatch(self) -> None:
        pred = compile_predicate(SRC == "10.0.0.1")
        assert pred(FakePacket({"ip.src": ("10.0.0.2",)})) is False

    def test_eq_absent_field_is_false(self) -> None:
        assert compile_predicate(SRC == "10.0.0.1")(EMPTY) is False

    @pytest.mark.parametrize(
        ("expr", "raw", "expected"),
        [
            (TTL < 64, "63", True),
            (TTL < 64, "64", False),
            (TTL <= 64, "64", True),
            (TTL <= 64, "65", False),
            (TTL > 64, "65", True),
            (TTL > 64, "64", False),
            (TTL >= 64, "64", True),
            (TTL >= 64, "63", False),
        ],
    )
    def test_ordering_ops(self, expr: Expr, raw: str, expected: bool) -> None:
        assert compile_predicate(expr)(FakePacket({"ip.ttl": (raw,)})) is expected

    @pytest.mark.parametrize(
        "expr",
        [TTL == 64, TTL < 64, TTL <= 64, TTL > 64, TTL >= 64],
        ids=["eq", "lt", "le", "gt", "ge"],
    )
    def test_every_op_is_false_on_absent_field(self, expr: Expr) -> None:
        assert compile_predicate(expr)(EMPTY) is False


class TestMultiValueFields:
    """Wireshark ``==`` on a multi-value field: true if ANY occurrence matches."""

    def test_one_occurrence_matches(self) -> None:
        pred = compile_predicate(PORT == 443)
        assert pred(FakePacket({"tcp.port": ("52034", "443")})) is True

    def test_no_occurrence_matches(self) -> None:
        pred = compile_predicate(PORT == 443)
        assert pred(FakePacket({"tcp.port": ("52034", "8080")})) is False

    def test_absent_field_is_false(self) -> None:
        assert compile_predicate(PORT == 443)(EMPTY) is False

    def test_ordering_also_means_any_occurrence(self) -> None:
        pred = compile_predicate(PORT < 1024)
        assert pred(FakePacket({"tcp.port": ("52034", "443")})) is True
        assert pred(FakePacket({"tcp.port": ("52034", "8080")})) is False


class TestNeContract:
    """``!=`` is ``Not(Eq)``: true iff NO occurrence equals, like ``!(f == v)``.

    On an ABSENT field the inner Eq is False, so the negation is True — the
    same row set Wireshark selects for ``!(f == v)``. This emergent behavior
    is intended and pinned here.
    """

    def test_some_occurrence_equal_is_false(self) -> None:
        pred = compile_predicate(PORT != 443)
        assert pred(FakePacket({"tcp.port": ("443", "52034")})) is False

    def test_no_occurrence_equal_is_true(self) -> None:
        pred = compile_predicate(PORT != 443)
        assert pred(FakePacket({"tcp.port": ("80", "8080")})) is True

    def test_absent_field_is_true(self) -> None:
        assert compile_predicate(PORT != 443)(EMPTY) is True


class TestPresence:
    def test_present(self) -> None:
        assert compile_predicate(SRC.present())(FakePacket({"ip.src": ("10.0.0.1",)})) is True

    def test_absent_is_false(self) -> None:
        assert compile_predicate(SRC.present())(EMPTY) is False

    def test_multi_occurrence_counts_as_present(self) -> None:
        assert compile_predicate(PORT.present())(FakePacket({"tcp.port": ("80", "443")})) is True


class TestBooleanConnectives:
    PACKET = FakePacket({"ip.src": ("10.0.0.1",), "ip.dst": ("10.0.0.2",), "tcp.port": ("443",)})

    def test_and(self) -> None:
        assert compile_predicate((SRC == "10.0.0.1") & (PORT == 443))(self.PACKET) is True
        assert compile_predicate((SRC == "10.0.0.1") & (PORT == 80))(self.PACKET) is False
        assert compile_predicate((SRC == "10.0.0.9") & (PORT == 443))(self.PACKET) is False

    def test_or(self) -> None:
        assert compile_predicate((SRC == "10.0.0.9") | (PORT == 443))(self.PACKET) is True
        assert compile_predicate((SRC == "10.0.0.1") | (PORT == 80))(self.PACKET) is True
        assert compile_predicate((SRC == "10.0.0.9") | (PORT == 80))(self.PACKET) is False

    def test_not(self) -> None:
        assert compile_predicate(~(PORT == 443))(self.PACKET) is False
        assert compile_predicate(~(PORT == 80))(self.PACKET) is True

    def test_double_negation(self) -> None:
        assert compile_predicate(~~(PORT == 443))(self.PACKET) is True

    def test_nested_not_over_or_conjoined(self) -> None:
        expr = ~((SRC == "10.0.0.9") | (PORT == 80)) & (DST == "10.0.0.2")
        assert compile_predicate(expr)(self.PACKET) is True
        flipped = ~((SRC == "10.0.0.1") | (PORT == 80)) & (DST == "10.0.0.2")
        assert compile_predicate(flipped)(self.PACKET) is False


class TestTypedConversion:
    """Raw text is converted per ftype before comparing, never compared as text."""

    def test_int_hex_raw_form(self) -> None:
        assert compile_predicate(PORT == 31)(FakePacket({"tcp.port": ("0x1f",)})) is True

    def test_bool_raw_forms(self) -> None:
        pred = compile_predicate(SYN == True)  # noqa: E712
        assert pred(FakePacket({"tcp.flags.syn": ("1",)})) is True
        assert pred(FakePacket({"tcp.flags.syn": ("True",)})) is True
        assert pred(FakePacket({"tcp.flags.syn": ("0",)})) is False

    def test_bytes_colon_and_contiguous_hex(self) -> None:
        pred = compile_predicate(PAYLOAD == b"\xaa\xbb\xcc")
        assert pred(FakePacket({"tcp.payload": ("aa:bb:cc",)})) is True
        assert pred(FakePacket({"tcp.payload": ("aabbcc",)})) is True
        assert pred(FakePacket({"tcp.payload": ("aa:bb:cd",)})) is False

    def test_int_literal_widened_for_float_field(self) -> None:
        pred = compile_predicate(LOSS > 1)
        assert pred(FakePacket({"frame.loss": ("1.5",)})) is True
        assert pred(FakePacket({"frame.loss": ("0.5",)})) is False

    def test_datetime_comparison(self) -> None:
        moment = datetime(2021, 7, 1, tzinfo=timezone.utc)  # epoch 1625097600
        # SIM300 ("Yoda condition") suppressed: swapping operands would
        # dispatch to the literal's operator, not the field's.
        pred = compile_predicate(TIME >= moment)  # noqa: SIM300
        assert pred(FakePacket({"frame.time": ("1625097600.123456",)})) is True
        assert pred(FakePacket({"frame.time": ("1625097599.999999",)})) is False

    def test_timedelta_comparison(self) -> None:
        pred = compile_predicate(DELTA > timedelta(milliseconds=1))  # noqa: SIM300
        assert pred(FakePacket({"frame.time_delta": ("0.002000",)})) is True
        assert pred(FakePacket({"frame.time_delta": ("0.000123",)})) is False

    def test_string_field_compares_verbatim(self) -> None:
        pred = compile_predicate(HOST == 'say "hi"')
        assert pred(FakePacket({"http.host": ('say "hi"',)})) is True
        assert pred(FakePacket({"http.host": ("say hi",)})) is False

    def test_unknown_ftype_falls_back_to_text_comparison(self) -> None:
        assert compile_predicate(CUSTOM == "hello")(FakePacket({"x.custom": ("hello",)})) is True


class TestCompileTimeErrors:
    """User errors surface at compile time, mirroring the dfilter backend's timing."""

    def test_bad_literal_raises_value_error_before_any_packet(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_predicate(SRC == "not-an-ip")

    def test_wrong_literal_type_raises_type_error_before_any_packet(self) -> None:
        with pytest.raises(TypeError, match="bool"):
            compile_predicate(PORT == True)  # noqa: E712

    def test_unknown_expr_subclass_raises_type_error_not_unsupported(self) -> None:
        # The predicate backend is the final fallback — an unknown node is a
        # programming error, so plain TypeError, not UnsupportedExprError.
        class FutureNode(Expr):
            __slots__ = ()

        with pytest.raises(TypeError, match="FutureNode"):
            compile_predicate(FutureNode())


class TestEvalTimeErrors:
    def test_malformed_raw_data_raises_value_error(self) -> None:
        # Loud policy: a packet whose raw text cannot be parsed as its ftype
        # is a bug worth surfacing, not a silent non-match.
        pred = compile_predicate(PORT == 443)  # compiles fine
        with pytest.raises(ValueError, match="garbage"):
            pred(FakePacket({"tcp.port": ("garbage",)}))
