"""Unit tests for the Python predicate backend (:mod:`remora.compile.predicate`).

Covers the predicate backend alone; the table-driven suite shared with the
display-filter backend lives in ``tests/test_semantics_table.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

import pytest

from conftest import FakePacket
from remora.compile.dfilter import compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr
from remora.fields import FieldRef

SRC = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
DST = FieldRef[IPv4Address]("ip.dst", "FT_IPv4", False)
PORT = FieldRef[int]("tcp.port", "FT_UINT16", True)
TTL = FieldRef[int]("ip.ttl", "FT_UINT8", False)
HOST = FieldRef[str]("http.host", "FT_STRING", False)
QNAME = FieldRef[str]("dns.qry.name", "FT_STRING", True)
PAYLOAD = FieldRef[bytes]("tcp.payload", "FT_BYTES", False)
TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
DELTA = FieldRef[timedelta]("frame.time_delta", "FT_RELATIVE_TIME", False)
SYN = FieldRef[bool]("tcp.flags.syn", "FT_BOOLEAN", False)
LOSS = FieldRef[float]("frame.loss", "FT_DOUBLE", False)
CUSTOM = FieldRef[str]("x.custom", "FT_SOMETHING_NEW", False)

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


class TestMembership:
    def test_scalar_set_match(self) -> None:
        pred = compile_predicate(PORT.in_([80, 443]))
        assert pred(FakePacket({"tcp.port": ("443",)})) is True
        assert pred(FakePacket({"tcp.port": ("8080",)})) is False
        assert pred(EMPTY) is False

    def test_any_occurrence_matches(self) -> None:
        pred = compile_predicate(PORT.in_([443]))
        assert pred(FakePacket({"tcp.port": ("52034", "443")})) is True
        assert pred(FakePacket({"tcp.port": ("52034", "8080")})) is False

    def test_range_membership_is_inclusive(self) -> None:
        pred = compile_predicate(PORT.in_([range(8000, 8081)]))
        assert pred(FakePacket({"tcp.port": ("8000",)})) is True
        assert pred(FakePacket({"tcp.port": ("8080",)})) is True
        assert pred(FakePacket({"tcp.port": ("8081",)})) is False
        assert pred(FakePacket({"tcp.port": ("7999",)})) is False

    def test_mixed_scalars_and_ranges(self) -> None:
        pred = compile_predicate(PORT.in_([443, (8000, 8080)]))
        assert pred(FakePacket({"tcp.port": ("443",)})) is True
        assert pred(FakePacket({"tcp.port": ("8040",)})) is True
        assert pred(FakePacket({"tcp.port": ("80",)})) is False

    def test_raw_text_is_converted_before_matching(self) -> None:
        # 0x1f == 31: conversion happens per ftype, never text comparison.
        pred = compile_predicate(PORT.in_([31]))
        assert pred(FakePacket({"tcp.port": ("0x1f",)})) is True

    def test_ipv4_range_membership(self) -> None:
        pred = compile_predicate(SRC.in_([("10.0.0.5", "10.0.0.9"), "10.0.0.1"]))
        assert pred(FakePacket({"ip.src": ("10.0.0.7",)})) is True
        assert pred(FakePacket({"ip.src": ("10.0.0.1",)})) is True
        assert pred(FakePacket({"ip.src": ("10.0.0.10",)})) is False

    def test_not_in_is_true_on_absent_field(self) -> None:
        pred = compile_predicate(~PORT.in_([80, 443]))
        assert pred(FakePacket({"tcp.port": ("443", "52034")})) is False
        assert pred(FakePacket({"tcp.port": ("8080",)})) is True
        assert pred(EMPTY) is True

    def test_datetime_membership_evaluates_in_python(self) -> None:
        moment = datetime(2021, 7, 1, tzinfo=timezone.utc)  # epoch 1625097600
        pred = compile_predicate(TIME.in_([moment]))
        assert pred(FakePacket({"frame.time": ("1625097600",)})) is True
        assert pred(FakePacket({"frame.time": ("1625097601",)})) is False

    def test_inverted_range_raises_value_error_at_compile_time(self) -> None:
        with pytest.raises(ValueError, match="inverted"):
            compile_predicate(PORT.in_([(443, 80)]))

    def test_bad_element_literal_raises_at_compile_time(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_predicate(SRC.in_(["not-an-ip"]))


class TestContains:
    def test_substring_match(self) -> None:
        pred = compile_predicate(HOST.contains("ample"))
        assert pred(FakePacket({"http.host": ("example.com",)})) is True
        assert pred(FakePacket({"http.host": ("other.org",)})) is False
        assert pred(EMPTY) is False

    def test_contains_is_case_sensitive(self) -> None:
        # Wireshark `contains` is case-sensitive (unlike `matches`).
        pred = compile_predicate(HOST.contains("ample"))
        assert pred(FakePacket({"http.host": ("EXAMPLE.COM",)})) is False

    def test_any_occurrence_matches(self) -> None:
        pred = compile_predicate(QNAME.contains("example"))
        assert pred(FakePacket({"dns.qry.name": ("alpha.example", "beta.io")})) is True
        assert pred(FakePacket({"dns.qry.name": ("beta.io", "gamma.net")})) is False

    def test_bytes_subsequence_match(self) -> None:
        pred = compile_predicate(PAYLOAD.contains(b"\xbb\xcc"))
        assert pred(FakePacket({"tcp.payload": ("aa:bb:cc:dd",)})) is True
        assert pred(FakePacket({"tcp.payload": ("aa:bb",)})) is False

    def test_needle_type_mismatch_raises_at_compile_time(self) -> None:
        with pytest.raises(TypeError, match="needle"):
            compile_predicate(HOST.contains(b"ab"))
        with pytest.raises(TypeError, match="needle"):
            compile_predicate(PAYLOAD.contains("GET"))

    def test_contains_on_int_field_raises_at_compile_time(self) -> None:
        with pytest.raises(TypeError, match="needle"):
            compile_predicate(PORT.contains("80"))


class TestMatches:
    def test_regex_search_is_unanchored(self) -> None:
        pred = compile_predicate(HOST.matches("ample"))
        assert pred(FakePacket({"http.host": ("example.com",)})) is True

    def test_case_insensitive_by_default(self) -> None:
        # Wireshark's `matches` is case-insensitive by default; mirrored here.
        pred = compile_predicate(HOST.matches("^ex.*com$"))
        assert pred(FakePacket({"http.host": ("example.com",)})) is True
        assert pred(FakePacket({"http.host": ("EXAMPLE.COM",)})) is True
        assert pred(FakePacket({"http.host": ("other.org",)})) is False

    def test_any_occurrence_matches(self) -> None:
        pred = compile_predicate(QNAME.matches("^alpha"))
        assert pred(FakePacket({"dns.qry.name": ("beta.io", "alpha.example")})) is True
        assert pred(FakePacket({"dns.qry.name": ("beta.io",)})) is False

    def test_absent_field_is_false_and_negation_true(self) -> None:
        assert compile_predicate(HOST.matches("x"))(EMPTY) is False
        assert compile_predicate(~HOST.matches("x"))(EMPTY) is True

    def test_matches_on_non_string_field_raises_at_compile_time(self) -> None:
        with pytest.raises(TypeError, match="string fields"):
            compile_predicate(PORT.matches("443"))


class TestCrossBackendErrorParity:
    """Verify that user-error messages are identical between dfilter and predicate backends.

    Both backends must raise the same exception type with the same message for
    shared error cases. This class captures errors from both backends on the
    same Expr and asserts they match exactly.
    """

    @pytest.mark.parametrize(
        "expr",
        [
            PORT.in_([(443, 80)]),  # inverted range
        ],
        ids=["inverted_range"],
    )
    def test_inverted_range_error_parity(self, expr: Expr) -> None:
        """Inverted membership ranges raise identical ValueError messages."""
        with pytest.raises(ValueError) as exc_dfilter:
            compile_dfilter(expr)
        with pytest.raises(ValueError) as exc_predicate:
            compile_predicate(expr)
        assert str(exc_dfilter.value) == str(exc_predicate.value)

    @pytest.mark.parametrize(
        "expr",
        [
            HOST.contains(b"ab"),  # str field, bytes needle
            PAYLOAD.contains("GET"),  # bytes field, str needle
            PORT.contains("80"),  # int field, str needle
        ],
        ids=["str_field_bytes_needle", "bytes_field_str_needle", "int_field_str_needle"],
    )
    def test_contains_needle_mismatch_error_parity(self, expr: Expr) -> None:
        """Contains needle type mismatch raises identical TypeError messages."""
        with pytest.raises(TypeError) as exc_dfilter:
            compile_dfilter(expr)
        with pytest.raises(TypeError) as exc_predicate:
            compile_predicate(expr)
        assert str(exc_dfilter.value) == str(exc_predicate.value)

    @pytest.mark.parametrize(
        "expr",
        [
            PORT.matches("443"),  # int field
        ],
        ids=["int_field"],
    )
    def test_matches_on_non_string_field_error_parity(self, expr: Expr) -> None:
        """Matches on non-string fields raises identical TypeError messages."""
        with pytest.raises(TypeError) as exc_dfilter:
            compile_dfilter(expr)
        with pytest.raises(TypeError) as exc_predicate:
            compile_predicate(expr)
        assert str(exc_dfilter.value) == str(exc_predicate.value)
