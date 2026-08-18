"""SQL backend shape tests (issue #29).

Deliberately no ``pytest.importorskip("duckdb")``: compiling an Expr to SQL is
pure string and parameter construction, so these tests must run where duckdb is
absent. Execution against a real DuckDB lives in tests/test_sql_duckdb.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_network

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


class TestPresence:
    def test_scalar_presence_is_is_not_null(self) -> None:
        assert compile_sql(SRC.present()) == SqlPredicate('"ip_src" IS NOT NULL', ())

    def test_multi_presence_is_a_length_test(self) -> None:
        assert compile_sql(PORT.present()) == SqlPredicate('len(coalesce("tcp_port", [])) > 0', ())

    def test_column_name_comes_from_the_naming_policy(self) -> None:
        # Full abbrev, lowercased, non-alnum -> "_": the frozen #25/#26 policy,
        # imported rather than restated (tcp.port and udp.port must not merge).
        assert compile_sql(QNAME.present()).sql == 'len(coalesce("dns_qry_name", [])) > 0'

    def test_negated_presence_is_null_safe(self) -> None:
        # IS NOT NULL never yields NULL, so NOT of it selects the absent rows —
        # the one place the SQL backend matches the predicate backend on absence.
        assert compile_sql(~SRC.present()).sql == 'NOT ("ip_src" IS NOT NULL)'

    def test_negated_multi_presence_is_null_safe(self) -> None:
        # coalesce(..., []) treats a back-filled NULL column as absent, so
        # NOT of that is false (not NULL) — the other exception to the three-valued logic.
        assert compile_sql(~PORT.present()).sql == 'NOT (len(coalesce("tcp_port", [])) > 0)'


class TestMembership:
    def test_scalar_set_is_an_or_of_equalities(self) -> None:
        result = compile_sql(TTL.in_([1, 64]))
        assert result.sql == '("ip_ttl" = ? OR "ip_ttl" = ?)'
        assert result.params == (1, 64)

    def test_multi_set_uses_list_contains_per_element(self) -> None:
        result = compile_sql(PORT.in_([80, 443]))
        assert result.sql == '(list_contains("tcp_port", ?) OR list_contains("tcp_port", ?))'
        assert result.params == (80, 443)

    def test_single_element_set_needs_no_parentheses(self) -> None:
        assert compile_sql(PORT.in_([443])) == SqlPredicate('list_contains("tcp_port", ?)', (443,))

    def test_range_on_a_multi_field_is_an_any_occurrence_between(self) -> None:
        result = compile_sql(PORT.in_([range(8000, 8081)]))
        assert result.sql == 'len(list_filter("tcp_port", x -> x BETWEEN ? AND ?)) > 0'
        assert result.params == (8000, 8080)

    def test_inverted_range_raises(self) -> None:
        with pytest.raises(ValueError, match="inverted membership range"):
            compile_sql(TTL.in_([(64, 1)]))

    def test_not_in_is_not_of_the_whole_set(self) -> None:
        result = compile_sql(~PORT.in_([80, 443]))
        assert result.sql == (
            'NOT ((list_contains("tcp_port", ?) OR list_contains("tcp_port", ?)))'
        )
        assert result.params == (80, 443)


class TestSubnetMembership:
    def test_ipv4_subnet_is_a_between_over_the_integer_column(self) -> None:
        # Acceptance criterion 3. There is no subnet node in the IR: a subnet
        # test is a Membership carrying a ValueRange of the network's first and
        # last address, which lowers to the zone-map-friendly range predicate
        # that #26 stores integer addresses for.
        network = ip_network("10.0.0.0/24")
        result = compile_sql(SRC.in_([(network[0], network[-1])]))
        assert result.sql == '"ip_src" BETWEEN ? AND ?'
        assert result.params == (int(network[0]), int(network[-1]))
        assert "10.0.0" not in result.sql

    def test_ipv6_subnet_casts_both_endpoints(self) -> None:
        network = ip_network("2001:db8::/32")
        result = compile_sql(V6SRC.in_([(network[0], network[-1])]))
        assert result.sql == ('"ipv6_src" BETWEEN CAST(? AS UHUGEINT) AND CAST(? AS UHUGEINT)')
        assert result.params == (str(int(network[0])), str(int(network[-1])))

    def test_subnet_endpoints_may_be_written_as_text(self) -> None:
        result = compile_sql(SRC.in_([("10.0.0.0", "10.0.0.255")]))
        assert result.sql == '"ip_src" BETWEEN ? AND ?'
        assert result.params == (int(IPv4Address("10.0.0.0")), int(IPv4Address("10.0.0.255")))
