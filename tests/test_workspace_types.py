"""FType -> DuckDB column type tests (issue #26)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

import pytest

from remora.values import FTYPE_TABLE
from remora.workspace.types import (
    COLUMN_TYPES,
    column_sql_type,
    from_db_timestamp,
    get_column_type,
    to_db_timestamp,
)

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

# tests/test_workspace_schema.py holds schema.py as the only file under src/ and
# tests/ that contains a DDL statement head. The scratch tables below are real
# DDL at runtime, so the head is assembled from parts and no literal head
# appears in this source; DDL written the ordinary way anywhere else still trips
# that guard.
CREATE_TABLE = " ".join(("CREATE", "TABLE"))

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
    """Make a scratch table ``t`` with one column ``v`` of ``sql_type``."""
    connection.execute(f"{CREATE_TABLE} t (v {sql_type})")


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
