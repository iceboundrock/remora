"""SQL backend shape tests (issue #29).

Deliberately no ``pytest.importorskip("duckdb")``: compiling an Expr to SQL is
pure string and parameter construction, so these tests must run where duckdb is
absent. Execution against a real DuckDB lives in tests/test_sql_duckdb.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from remora.compile.sql import SqlPredicate, UnsupportedSqlExprError, compile_sql
from remora.expr import Expr
from remora.fields import FieldRef

SRC = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
DST = FieldRef[IPv4Address]("ip.dst", "FT_IPv4", False)
TTL = FieldRef[int]("ip.ttl", "FT_UINT8", False)
PORT = FieldRef[int]("tcp.port", "FT_UINT16", True)
HOST = FieldRef[str]("http.host", "FT_STRING", False)
QNAME = FieldRef[str]("dns.qry.name", "FT_STRING", True)
PAYLOAD = FieldRef[bytes]("tcp.payload", "FT_BYTES", False)
TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
V6SRC = FieldRef[IPv6Address]("ipv6.src", "FT_IPv6", False)
V6ADDR = FieldRef[IPv6Address]("ipv6.addr", "FT_IPv6", True)


class TestScalarComparisons:
    def test_eq_is_a_bound_parameter(self) -> None:
        result = compile_sql(SRC == "10.0.0.1")
        assert result == SqlPredicate('"ip_src" = ?', (int(IPv4Address("10.0.0.1")),))

    @pytest.mark.parametrize(
        ("expr", "sql"),
        [
            (TTL < 64, '"ip_ttl" < ?'),
            (TTL <= 64, '"ip_ttl" <= ?'),
            (TTL > 64, '"ip_ttl" > ?'),
            (TTL >= 64, '"ip_ttl" >= ?'),
        ],
        ids=["lt", "le", "gt", "ge"],
    )
    def test_ordered_operators(self, expr: Expr, sql: str) -> None:
        result = compile_sql(expr)
        assert result.sql == sql
        assert result.params == (64,)

    def test_timestamps_are_encoded_to_naive_utc(self) -> None:
        moment = datetime(2021, 7, 1, tzinfo=timezone.utc)
        result = compile_sql(TIME >= moment)  # noqa: SIM300
        assert result.sql == '"frame_time" >= ?'
        assert result.params == (datetime(2021, 7, 1),)

    def test_bytes_literals_bind_as_blob_bytes(self) -> None:
        result = compile_sql(PAYLOAD == b"\xaa\xbb")
        assert result == SqlPredicate('"tcp_payload" = ?', (b"\xaa\xbb",))

    def test_malformed_literal_is_a_user_error_not_unsupported(self) -> None:
        # Same policy as the dfilter backend: coerce_literal's ValueError is
        # NOT converted into UnsupportedSqlExprError.
        with pytest.raises(ValueError):
            compile_sql(SRC == "not-an-ip")


class TestIPv6Parameters:
    def test_scalar_ipv6_casts_a_decimal_string(self) -> None:
        # #26's FT_IPv6 encoder emits decimal TEXT, because DuckDB unifies a
        # list's inferred element types before casting them. An explicit CAST
        # keeps the comparison unambiguous in scalar and list position alike.
        result = compile_sql(V6SRC == "ff02::1")
        assert result.sql == '"ipv6_src" = CAST(? AS UHUGEINT)'
        assert result.params == (str(int(IPv6Address("ff02::1"))),)

    def test_multi_ipv6_casts_inside_list_contains(self) -> None:
        result = compile_sql(V6ADDR == "ff02::1:2")
        assert result.sql == 'list_contains("ipv6_addr", CAST(? AS UHUGEINT))'
        assert result.params == (str(int(IPv6Address("ff02::1:2"))),)


class TestMultiValueComparisons:
    def test_eq_is_list_contains(self) -> None:
        # Acceptance criterion 1: any-occurrence semantics, parameter bound.
        result = compile_sql(PORT == 80)
        assert result == SqlPredicate('list_contains("tcp_port", ?)', (80,))

    def test_ordered_operator_is_an_any_occurrence_filter(self) -> None:
        result = compile_sql(PORT > 1024)
        assert result.sql == 'len(list_filter("tcp_port", x -> x > ?)) > 0'
        assert result.params == (1024,)


class TestNegationAndConnectives:
    def test_ne_on_a_multi_field_is_not_list_contains(self) -> None:
        # Acceptance criterion 2: never SQL <> on a list column.
        result = compile_sql(PORT != 443)
        assert result == SqlPredicate('NOT (list_contains("tcp_port", ?))', (443,))
        assert "<>" not in result.sql
        assert "!=" not in result.sql

    def test_ne_on_a_scalar_field_is_not_eq(self) -> None:
        result = compile_sql(SRC != "10.0.0.1")
        assert result.sql == 'NOT ("ip_src" = ?)'
        assert "<>" not in result.sql

    def test_and_or_nest_with_parentheses_and_ordered_params(self) -> None:
        result = compile_sql((SRC == "10.0.0.1") & (PORT == 443))
        assert result.sql == '("ip_src" = ? AND list_contains("tcp_port", ?))'
        assert result.params == (int(IPv4Address("10.0.0.1")), 443)

    def test_or(self) -> None:
        result = compile_sql((SRC == "10.0.0.1") | (DST == "10.0.0.2"))
        assert result.sql == '("ip_src" = ? OR "ip_dst" = ?)'
        assert result.params == (
            int(IPv4Address("10.0.0.1")),
            int(IPv4Address("10.0.0.2")),
        )

    def test_unknown_node_raises_unsupported(self) -> None:
        class Weird(Expr):
            __slots__ = ()

        with pytest.raises(UnsupportedSqlExprError, match="Weird"):
            compile_sql(Weird())
