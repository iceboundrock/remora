"""FType -> DuckDB column type tests (issue #26)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

import pytest

from remora.values import FTYPE_TABLE
from remora.workspace.naming import column_name
from remora.workspace.schema import add_field_column, create_schema
from remora.workspace.types import (
    COLUMN_TYPES,
    ColumnSpec,
    column_spec,
    column_sql_type,
    from_db_timestamp,
    get_column_type,
    to_db_timestamp,
)

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

# One representative value per ftype, used for the through-storage round trip.
SAMPLES: dict[str, Any] = {
    "FT_IPv4": IPv4Address("10.0.0.1"),
    "FT_IPv6": IPv6Address("2001:db8::1"),
    "FT_ETHER": b"\xaa\xbb\xcc\xdd\xee\xff",
    "FT_BYTES": b"\x00\x01\x02",
    "FT_BOOLEAN": True,
    "FT_ABSOLUTE_TIME": datetime(2026, 8, 9, 1, 2, 3, 123456, tzinfo=timezone.utc),
    "FT_RELATIVE_TIME": timedelta(seconds=1, microseconds=500000),
    "FT_DOUBLE": 1.5,
    "FT_FLOAT": 1.5,
    "FT_STRING": "hello",
}
INT_SAMPLE = 7
STR_SAMPLE = "text"


def sample_for(ftype: str) -> Any:
    if ftype in SAMPLES:
        return SAMPLES[ftype]
    return INT_SAMPLE if FTYPE_TABLE[ftype].py_type is int else STR_SAMPLE


def scratch_column(connection: DuckDBPyConnection, sql_type: str) -> None:
    """Make a scratch table ``t`` with one column ``v`` of ``sql_type``.

    This file is a declared scratch file in tests/test_workspace_schema.py: the
    table is a throwaway probe on a bare in-memory connection, never part of the
    workspace layout, which stays schema.py's alone.
    """
    connection.execute(f"CREATE TABLE t (v {sql_type})")


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    try:
        yield connection
    finally:
        connection.close()


class TestTypeTable:
    def test_covers_every_known_ftype(self) -> None:
        # Drift guard in both directions: values.py and types.py must agree on
        # the ftype universe.
        assert set(COLUMN_TYPES) == set(FTYPE_TABLE)

    def test_unknown_ftype_falls_back_to_varchar(self) -> None:
        entry = get_column_type("FT_NO_SUCH_TYPE")
        assert entry.sql_type == "VARCHAR"
        assert entry.encode("x") == "x"
        assert entry.decode("x") == "x"

    @pytest.mark.parametrize(
        ("ftype", "expected"),
        [
            ("FT_IPv4", "UINTEGER"),
            ("FT_IPv6", "UHUGEINT"),
            ("FT_ETHER", "BLOB"),
            ("FT_BYTES", "BLOB"),
            ("FT_BOOLEAN", "BOOLEAN"),
            ("FT_ABSOLUTE_TIME", "TIMESTAMP"),
            ("FT_RELATIVE_TIME", "INTERVAL"),
            ("FT_DOUBLE", "DOUBLE"),
            ("FT_FLOAT", "DOUBLE"),
            ("FT_UINT8", "UTINYINT"),
            ("FT_CHAR", "UTINYINT"),
            ("FT_UINT16", "USMALLINT"),
            ("FT_UINT24", "UINTEGER"),
            ("FT_UINT32", "UINTEGER"),
            ("FT_FRAMENUM", "UINTEGER"),
            ("FT_UINT40", "UBIGINT"),
            ("FT_UINT64", "UBIGINT"),
            ("FT_INT8", "TINYINT"),
            ("FT_INT16", "SMALLINT"),
            ("FT_INT24", "INTEGER"),
            ("FT_INT32", "INTEGER"),
            ("FT_INT64", "BIGINT"),
            ("FT_STRING", "VARCHAR"),
            ("FT_NONE", "VARCHAR"),
        ],
    )
    def test_frozen_sql_types(self, ftype: str, expected: str) -> None:
        assert column_sql_type(ftype) == expected

    def test_multi_appends_the_list_suffix(self) -> None:
        assert column_sql_type("FT_UINT16", multi=True) == "USMALLINT[]"
        assert column_sql_type("FT_IPv4", multi=True) == "UINTEGER[]"


class TestThroughStorage:
    @pytest.mark.parametrize("ftype", sorted(FTYPE_TABLE))
    def test_round_trip_through_a_real_column(self, con: DuckDBPyConnection, ftype: str) -> None:
        # The codec pair alone cannot prove a column type is wide enough to
        # hold the encoded value; writing it does.
        entry = get_column_type(ftype)
        value = sample_for(ftype)
        scratch_column(con, entry.sql_type)
        con.execute("INSERT INTO t VALUES (?)", [entry.encode(value)])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert entry.decode(row[0]) == value

    @pytest.mark.parametrize(
        "text",
        # Both ends of the range and the values either side of them, plus the
        # 2^31 boundary: the IPv4 analogue of the sign hazard that makes
        # DuckDB's Arrow export of UHUGEINT wrong above 2^127.
        [
            "0.0.0.0",
            "0.0.0.1",
            "127.255.255.255",
            "128.0.0.0",
            "255.255.255.254",
            "255.255.255.255",
        ],
    )
    def test_ipv4_edge_values_survive_storage(self, con: DuckDBPyConnection, text: str) -> None:
        address = IPv4Address(text)
        entry = get_column_type("FT_IPv4")
        scratch_column(con, "UINTEGER")
        con.execute("INSERT INTO t VALUES (?)", [entry.encode(address)])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert entry.decode(row[0]) == address

    @pytest.mark.parametrize(
        "text",
        # Both ends, and the pair straddling 2^127. DuckDB's Arrow export reads
        # UHUGEINT as signed and mangles everything in 8000::/1 (see the module
        # docstring of remora.workspace.types); the native path pinned here is
        # exact, which is what makes UHUGEINT the right column type anyway.
        [
            "::",
            "::1",
            "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "8000::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ],
    )
    def test_ipv6_edge_values_survive_storage(self, con: DuckDBPyConnection, text: str) -> None:
        address = IPv6Address(text)
        entry = get_column_type("FT_IPv6")
        scratch_column(con, "UHUGEINT")
        con.execute("INSERT INTO t VALUES (?)", [entry.encode(address)])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert entry.decode(row[0]) == address

    @pytest.mark.parametrize(
        "delta",
        [
            timedelta(seconds=-1, microseconds=-500000),
            timedelta(seconds=-3600),
            timedelta(microseconds=-1),
        ],
    )
    def test_negative_relative_times_survive_an_interval_column(
        self, con: DuckDBPyConnection, delta: timedelta
    ) -> None:
        # tshark relative times go backwards too (values.py parses a leading
        # "-"), and INTERVAL is only the right choice if it carries the sign.
        entry = get_column_type("FT_RELATIVE_TIME")
        scratch_column(con, "INTERVAL")
        con.execute("INSERT INTO t VALUES (?)", [entry.encode(delta)])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert entry.decode(row[0]) == delta

    def test_an_offset_timestamp_lands_as_utc_in_the_column(self, con: DuckDBPyConnection) -> None:
        # The codec pair converts the zone away, but only writing it proves the
        # naive UTC instant is what the TIMESTAMP column actually holds — a
        # TIMESTAMPTZ column would render it back through the session zone.
        entry = get_column_type("FT_ABSOLUTE_TIME")
        aware = datetime(2026, 8, 9, 1, 2, 3, 123456, tzinfo=timezone(timedelta(hours=8)))
        scratch_column(con, "TIMESTAMP")
        con.execute("INSERT INTO t VALUES (?)", [entry.encode(aware)])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert row[0] == datetime(2026, 8, 8, 17, 2, 3, 123456)
        assert entry.decode(row[0]) == aware

    def test_subnet_membership_is_an_integer_range(self, con: DuckDBPyConnection) -> None:
        # The reason IPs are integers at all (epic #43): subnet matching must
        # degrade to a range comparison a zone map can use.
        entry = get_column_type("FT_IPv4")
        scratch_column(con, "UINTEGER")
        for text in ("10.0.0.1", "10.0.0.255", "10.0.1.0", "9.255.255.255"):
            con.execute("INSERT INTO t VALUES (?)", [entry.encode(IPv4Address(text))])
        lo = int(IPv4Address("10.0.0.0"))
        hi = int(IPv4Address("10.0.0.255"))
        rows = con.execute("SELECT count(*) FROM t WHERE v BETWEEN ? AND ?", [lo, hi]).fetchone()
        assert rows is not None
        assert rows[0] == 2


class TestTimestampPolicy:
    def test_encode_strips_the_zone_after_converting_to_utc(self) -> None:
        aware = datetime(2026, 8, 9, 1, 2, 3, tzinfo=timezone(timedelta(hours=8)))
        stored = to_db_timestamp(aware)
        assert stored.tzinfo is None
        assert stored == datetime(2026, 8, 8, 17, 2, 3)

    def test_naive_input_is_taken_as_utc(self) -> None:
        naive = datetime(2026, 8, 9, 1, 2, 3)
        assert to_db_timestamp(naive) == naive

    def test_decode_retags_as_utc(self) -> None:
        assert from_db_timestamp(datetime(2026, 8, 9, 1, 2, 3)) == datetime(
            2026, 8, 9, 1, 2, 3, tzinfo=timezone.utc
        )

    def test_round_trip_is_identity_for_aware_utc(self) -> None:
        value = datetime(2026, 8, 9, 1, 2, 3, 123456, tzinfo=timezone.utc)
        assert from_db_timestamp(to_db_timestamp(value)) == value


class TestColumnSpec:
    def test_derives_the_column_name_from_the_policy(self) -> None:
        spec: ColumnSpec = column_spec("tcp.port", "FT_UINT16", multi=True)
        assert spec.column_name == column_name("tcp.port")
        assert spec.sql_type == "USMALLINT[]"
        assert spec.multi is True

    def test_scalar_absent_is_none(self) -> None:
        spec = column_spec("ip.src", "FT_IPv4")
        assert spec.encode_raw(()) is None

    def test_scalar_single_occurrence(self) -> None:
        spec = column_spec("ip.src", "FT_IPv4")
        assert spec.encode_raw(("10.0.0.1",)) == int(IPv4Address("10.0.0.1"))

    def test_scalar_with_two_occurrences_raises(self) -> None:
        spec = column_spec("ip.src", "FT_IPv4")
        with pytest.raises(ValueError, match=r"ip\.src"):
            spec.encode_raw(("10.0.0.1", "10.0.0.2"))

    def test_multi_absent_is_an_empty_list(self) -> None:
        # Not NULL: no occurrences is exactly what [] means, and
        # list_contains([], x) is false — matching the predicate backend's rule
        # that an absent field never satisfies a positive test.
        spec = column_spec("tcp.port", "FT_UINT16", multi=True)
        assert spec.encode_raw(()) == []

    def test_multi_encodes_every_occurrence(self) -> None:
        spec = column_spec("tcp.port", "FT_UINT16", multi=True)
        assert spec.encode_raw(("80", "443")) == [80, 443]

    def test_multi_decodes_to_a_tuple(self) -> None:
        spec = column_spec("tcp.port", "FT_UINT16", multi=True)
        assert spec.decode([80, 443]) == (80, 443)

    def test_scalar_decode_passes_none_through(self) -> None:
        spec = column_spec("ip.src", "FT_IPv4")
        assert spec.decode(None) is None
        assert spec.decode(int(IPv4Address("10.0.0.1"))) == IPv4Address("10.0.0.1")

    def test_ipv6_encodes_to_a_decimal_string(self) -> None:
        # Deliberately asserting the representation, not just the round trip:
        # the column is UHUGEINT but the bound value is text, because DuckDB
        # unifies a list's inferred element types before casting (see
        # test_an_ipv6_multi_column_survives_mixed_magnitudes). An int here
        # typechecks and reads fine in scalar position, so only pinning the
        # string stops the encoder being "simplified" back into the bug.
        spec = column_spec("ipv6.src", "FT_IPv6")
        assert spec.encode_raw(("ff02::1:2",)) == str(int(IPv6Address("ff02::1:2")))

    def test_malformed_raw_text_raises_from_values(self) -> None:
        spec = column_spec("ip.src", "FT_IPv4")
        with pytest.raises(ValueError):
            spec.encode_raw(("not-an-ip",))


class TestMultiColumnThroughStorage:
    def test_a_multi_column_round_trips_and_list_contains_works(
        self, con: DuckDBPyConnection
    ) -> None:
        spec = column_spec("tcp.port", "FT_UINT16", multi=True)
        scratch_column(con, spec.sql_type)
        con.execute("INSERT INTO t VALUES (?)", [spec.encode_raw(("80", "443"))])
        con.execute("INSERT INTO t VALUES (?)", [spec.encode_raw(())])
        rows = con.execute("SELECT v, list_contains(v, 80) FROM t").fetchall()
        assert [spec.decode(stored) for stored, _ in rows] == [(80, 443), ()]
        assert [hit for _, hit in rows] == [True, False]

    def test_an_ipv6_multi_column_survives_mixed_magnitudes(self, con: DuckDBPyConnection) -> None:
        # A DAD Neighbour Solicitation carries source :: and a solicited-node
        # multicast destination, so ipv6.addr (curated multi in codegen.toml)
        # holds one address below 2^63 and one above 2^127 in the same list.
        # DuckDB unifies a Python list's *inferred* element types before casting
        # to the column type, so encoding these as Python ints unifies them to
        # signed HUGEINT and the insert fails outright — hence the decimal-string
        # encoding, which this pins through a real UHUGEINT[] column.
        spec = column_spec("ipv6.addr", "FT_IPv6", multi=True)
        scratch_column(con, spec.sql_type)
        con.execute("INSERT INTO t VALUES (?)", [spec.encode_raw(("::", "ff02::1:2"))])
        row = con.execute("SELECT v FROM t").fetchone()
        assert row is not None
        assert spec.decode(row[0]) == (IPv6Address("::"), IPv6Address("ff02::1:2"))
        # The string is a binding detail, not a query one: #29 still probes the
        # column with a plain Python int.
        hit = con.execute(
            "SELECT list_contains(v, ?) FROM t", [int(IPv6Address("ff02::1:2"))]
        ).fetchone()
        assert hit is not None
        assert hit[0] is True

    def test_an_ipv6_scalar_column_round_trips_through_a_column_spec(
        self, con: DuckDBPyConnection
    ) -> None:
        # The string encoding has to hold in scalar position too, where the
        # bound value meets UHUGEINT directly rather than through a LIST.
        spec = column_spec("ipv6.src", "FT_IPv6")
        scratch_column(con, spec.sql_type)
        for raw in (("ff02::1:2",), ("::",), ()):
            con.execute("INSERT INTO t VALUES (?)", [spec.encode_raw(raw)])
        rows = con.execute("SELECT v FROM t").fetchall()
        assert [spec.decode(stored) for (stored,) in rows] == [
            IPv6Address("ff02::1:2"),
            IPv6Address("::"),
            None,
        ]

    def test_a_null_list_would_not_have_answered_false(self, con: DuckDBPyConnection) -> None:
        # The counterfactual the frozen absence rule rests on: had encode_raw
        # returned None for an absent multi field, the predicate would go NULL
        # instead of false and the row would drop out of a NOT filter too.
        spec = column_spec("tcp.port", "FT_UINT16", multi=True)
        scratch_column(con, spec.sql_type)
        con.execute("INSERT INTO t VALUES (NULL)")
        row = con.execute("SELECT list_contains(v, 80) FROM t").fetchone()
        assert row is not None
        assert row[0] is None


class TestEveryTypeIsAcceptedByTheSchemaLayer:
    @pytest.mark.parametrize("ftype", sorted(FTYPE_TABLE))
    @pytest.mark.parametrize("multi", [False, True])
    def test_add_field_column_accepts_it(
        self, con: DuckDBPyConnection, ftype: str, multi: bool
    ) -> None:
        # A type this module emits that #25's validator refuses is a build-time
        # bug; this is the test that keeps the two modules agreeing.
        create_schema(con)
        add_field_column(con, "probe", column_sql_type(ftype, multi))
        rows = con.execute(
            "SELECT data_type FROM duckdb_columns() "
            "WHERE table_name = 'pkts' AND column_name = 'probe'"
        ).fetchall()
        # Asserting the reported type, not just that a column appeared: a
        # column_sql_type that answered "VARCHAR" for everything would satisfy
        # the schema layer perfectly and still be wrong.
        assert rows == [(column_sql_type(ftype, multi),)]
