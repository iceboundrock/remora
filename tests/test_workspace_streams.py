"""Workspace stream sessionization tests (issue #33).

Everything here drives :func:`remora.workspace.streams.build_streams` over an
in-memory workspace with hand-inserted ``pkts`` rows, so the suite spawns no
tshark. ``tests/integration/test_streams_integration.py`` is the other half:
it materializes a real capture and checks the rollups against tshark's own
``-z conv,tcp`` / ``-z conv,udp`` statistics.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any

import pytest

from remora.workspace.errors import MissingStreamFieldsError, WorkspaceError
from remora.workspace.schema import (
    FieldRecord,
    add_field_column,
    create_schema,
    register_fields,
)
from remora.workspace.streams import (
    REQUIRED_FIELDS,
    STREAM_PROTOCOLS,
    StreamsResult,
    build_streams,
)
from remora.workspace.types import column_spec

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

UTC_NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)

# The prerequisite field set with the ftypes a real materialization would use.
PREREQ_FTYPES: dict[str, str] = {
    "frame.len": "FT_UINT32",
    "ip.src": "FT_IPv4",
    "ip.dst": "FT_IPv4",
    "tcp.stream": "FT_UINT32",
    "tcp.srcport": "FT_UINT16",
    "tcp.dstport": "FT_UINT16",
    "udp.stream": "FT_UINT32",
    "udp.srcport": "FT_UINT16",
    "udp.dstport": "FT_UINT16",
}


def materialize_fields(
    con: DuckDBPyConnection,
    abbrevs: Iterator[str] | tuple[str, ...],
    *,
    multi: frozenset[str] = frozenset(),
) -> None:
    """Add the pkts columns for ``abbrevs`` and register them in meta.fields.

    Exactly what ``materialize.py`` does per field, without spawning tshark.
    """
    records = []
    for abbrev in abbrevs:
        spec = column_spec(abbrev, PREREQ_FTYPES[abbrev], abbrev in multi)
        add_field_column(con, spec.column_name, spec.sql_type)
        records.append(
            FieldRecord(
                abbrev=spec.abbrev,
                column_name=spec.column_name,
                ftype=spec.ftype,
                multi=spec.multi,
                column_type=spec.sql_type,
                materialized_at=UTC_NOW,
            )
        )
    register_fields(con, records)


def ip(text: str) -> int:
    """The uint representation pkts stores an FT_IPv4 field as."""
    return int(IPv4Address(text))


def packet(
    frame: int,
    length: int,
    src: str | None,
    dst: str | None,
    *,
    tcp: tuple[int, int, int] | None = None,
    udp: tuple[int, int, int] | None = None,
) -> list[Any]:
    """One ``pkts`` row, stamped at second ``frame - 1`` of a fixed minute.

    ``tcp``/``udp`` are ``(stream, srcport, dstport)``; the protocol left out
    has NULL columns, exactly as a real materialization would leave them.
    """
    return [
        frame,
        f"2026-08-18 00:00:{frame - 1:02d}",
        length,
        None if src is None else ip(src),
        None if dst is None else ip(dst),
        *(tcp if tcp is not None else (None, None, None)),
        *(udp if udp is not None else (None, None, None)),
    ]


# Two TCP streams and one UDP stream, deliberately interleaved in capture order
# so a rollup that assumed contiguous frames per stream would be caught.
PACKETS: tuple[list[Any], ...] = (
    packet(1, 54, "10.0.0.1", "10.0.0.2", tcp=(0, 51234, 443)),
    packet(2, 60, "10.0.0.3", "10.0.0.4", tcp=(1, 52000, 8080)),
    # The reverse direction of stream 0: endpoints must not follow it.
    packet(3, 66, "10.0.0.2", "10.0.0.1", tcp=(0, 443, 51234)),
    packet(4, 73, "10.0.0.1", "10.0.0.9", udp=(0, 53534, 53)),
    packet(5, 90, "10.0.0.9", "10.0.0.1", udp=(0, 53, 53534)),
    # ARP: no IP, no transport, so it belongs to no stream at all.
    packet(6, 42, None, None),
)

INSERT_PACKETS = """
    INSERT INTO main.pkts (
        frame_number, frame_time, frame_len, ip_src, ip_dst,
        tcp_stream, tcp_srcport, tcp_dstport,
        udp_stream, udp_srcport, udp_dstport
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    """An in-memory workspace whose prerequisite fields are all materialized."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    materialize_fields(connection, tuple(PREREQ_FTYPES))
    connection.executemany(INSERT_PACKETS, list(PACKETS))
    try:
        yield connection
    finally:
        connection.close()


def stream_rows(con: DuckDBPyConnection) -> list[tuple[Any, ...]]:
    return con.execute(
        """
        SELECT protocol, stream_id, src_addr, src_port, dst_addr, dst_port,
               first_frame, last_frame, pkt_count, byte_count, first_time, last_time
        FROM main.streams ORDER BY protocol, stream_id
        """
    ).fetchall()


class TestPrerequisites:
    def test_required_fields_are_the_documented_set(self) -> None:
        # Frozen deliberately: the error message promises these exact abbrevs,
        # and a silently widened set would make a stored workspace un-buildable
        # without saying why.
        assert REQUIRED_FIELDS == (
            "frame.len",
            "ip.dst",
            "ip.src",
            "tcp.dstport",
            "tcp.srcport",
            "tcp.stream",
            "udp.dstport",
            "udp.srcport",
            "udp.stream",
        )

    def test_protocols_are_tcp_and_udp(self) -> None:
        assert STREAM_PROTOCOLS == ("tcp", "udp")

    def test_missing_fields_are_named_exactly(self) -> None:
        connection: DuckDBPyConnection = duckdb.connect(":memory:")
        try:
            create_schema(connection)
            materialize_fields(
                connection, tuple(a for a in PREREQ_FTYPES if not a.startswith("udp."))
            )
            with pytest.raises(MissingStreamFieldsError) as excinfo:
                build_streams(connection)
        finally:
            connection.close()
        assert excinfo.value.missing == ("udp.dstport", "udp.srcport", "udp.stream")
        message = str(excinfo.value)
        for abbrev in ("udp.dstport", "udp.srcport", "udp.stream"):
            assert abbrev in message
        # Not a DuckDB "column not found": the message has to say what to do.
        assert "materialize" in message

    def test_the_error_is_a_workspace_error(self) -> None:
        assert issubclass(MissingStreamFieldsError, WorkspaceError)

    def test_both_protocols_are_required_even_with_no_packets_of_one(self) -> None:
        # The documented rule: build_streams() demands the prerequisites of
        # *both* protocols. Skipping udp because this capture happens to hold
        # no udp packets would hide the omission until a capture that does.
        connection: DuckDBPyConnection = duckdb.connect(":memory:")
        try:
            create_schema(connection)
            materialize_fields(
                connection, tuple(a for a in PREREQ_FTYPES if not a.startswith("udp."))
            )
            connection.execute(
                "INSERT INTO main.pkts (frame_number, frame_time, tcp_stream) "
                "VALUES (1, TIMESTAMP '2026-08-18 00:00:00', 0)"
            )
            with pytest.raises(MissingStreamFieldsError):
                build_streams(connection)
        finally:
            connection.close()

    def test_nothing_is_written_when_a_prerequisite_is_missing(self) -> None:
        connection: DuckDBPyConnection = duckdb.connect(":memory:")
        try:
            create_schema(connection)
            materialize_fields(connection, ("ip.src", "ip.dst"))
            connection.execute("INSERT INTO main.streams (stream_id) VALUES (7)")
            with pytest.raises(MissingStreamFieldsError):
                build_streams(connection)
            rows = connection.execute("SELECT stream_id FROM main.streams").fetchall()
        finally:
            connection.close()
        # Validation runs before any SQL over pkts, so an existing table is not
        # even emptied by a call that turns out to be unbuildable.
        assert rows == [(7,)]

    def test_a_fresh_workspace_names_every_field(self) -> None:
        connection: DuckDBPyConnection = duckdb.connect(":memory:")
        try:
            create_schema(connection)
            with pytest.raises(MissingStreamFieldsError) as excinfo:
                build_streams(connection)
        finally:
            connection.close()
        assert excinfo.value.missing == REQUIRED_FIELDS


class TestRollups:
    def test_result_counts_streams_per_protocol(self, con: DuckDBPyConnection) -> None:
        result = build_streams(con)
        assert result == StreamsResult(tcp_streams=2, udp_streams=1)
        assert result.total == 3

    def test_tcp_and_udp_rollups(self, con: DuckDBPyConnection) -> None:
        build_streams(con)
        assert stream_rows(con) == [
            (
                "tcp",
                0,
                ip("10.0.0.1"),
                51234,
                ip("10.0.0.2"),
                443,
                1,
                3,
                2,
                54 + 66,
                datetime(2026, 8, 18, 0, 0, 0),
                datetime(2026, 8, 18, 0, 0, 2),
            ),
            (
                "tcp",
                1,
                ip("10.0.0.3"),
                52000,
                ip("10.0.0.4"),
                8080,
                2,
                2,
                1,
                60,
                datetime(2026, 8, 18, 0, 0, 1),
                datetime(2026, 8, 18, 0, 0, 1),
            ),
            (
                "udp",
                0,
                ip("10.0.0.1"),
                53534,
                ip("10.0.0.9"),
                53,
                4,
                5,
                2,
                73 + 90,
                datetime(2026, 8, 18, 0, 0, 3),
                datetime(2026, 8, 18, 0, 0, 4),
            ),
        ]

    def test_tcp_and_udp_stream_ids_are_separate_namespaces(self, con: DuckDBPyConnection) -> None:
        # Both protocols number their streams from 0, so stream id alone is not
        # a key: (protocol, stream_id) is.
        build_streams(con)
        ids = con.execute(
            "SELECT protocol, stream_id FROM main.streams WHERE stream_id = 0"
        ).fetchall()
        assert sorted(ids) == [("tcp", 0), ("udp", 0)]

    def test_endpoints_come_from_the_streams_first_frame(self, con: DuckDBPyConnection) -> None:
        # Frame 3 is the reverse direction of tcp stream 0; the endpoints must
        # stay the initiator's, not whichever row the grouping happened to see.
        build_streams(con)
        row = con.execute(
            "SELECT src_addr, src_port, dst_addr, dst_port FROM main.streams "
            "WHERE protocol = 'tcp' AND stream_id = 0"
        ).fetchone()
        assert row == (ip("10.0.0.1"), 51234, ip("10.0.0.2"), 443)

    def test_endpoint_ips_use_the_pkts_uint_representation(self, con: DuckDBPyConnection) -> None:
        # Not "an int that happens to match": the join predicate itself has to
        # hold between the two columns.
        build_streams(con)
        matched = con.execute(
            "SELECT count(*) FROM main.streams s JOIN main.pkts p "
            "ON s.src_addr = p.ip_src AND s.first_frame = p.frame_number"
        ).fetchone()
        assert matched is not None
        assert matched[0] == 3

    def test_packets_join_to_streams_by_stream_id(self, con: DuckDBPyConnection) -> None:
        build_streams(con)
        rows = con.execute(
            """
            SELECT p.frame_number, s.protocol, s.stream_id, s.pkt_count
            FROM main.pkts p
            JOIN main.streams s
              ON s.protocol = 'tcp' AND s.stream_id = p.tcp_stream
            ORDER BY p.frame_number
            """
        ).fetchall()
        assert rows == [(1, "tcp", 0, 2), (2, "tcp", 1, 1), (3, "tcp", 0, 2)]

    def test_udp_packets_join_to_streams_by_stream_id(self, con: DuckDBPyConnection) -> None:
        # The udp side of the join, not just the tcp one: the two protocols
        # are separate columns in pkts and separate rows in streams, so a join
        # that worked for tcp proves nothing about udp.
        build_streams(con)
        rows = con.execute(
            """
            SELECT p.frame_number, s.protocol, s.stream_id, s.pkt_count
            FROM main.pkts p
            JOIN main.streams s
              ON s.protocol = 'udp' AND s.stream_id = p.udp_stream
            ORDER BY p.frame_number
            """
        ).fetchall()
        assert rows == [(4, "udp", 0, 2), (5, "udp", 0, 2)]

    def test_packets_outside_any_stream_are_excluded(self, con: DuckDBPyConnection) -> None:
        build_streams(con)
        total = con.execute("SELECT sum(pkt_count) FROM main.streams").fetchone()
        assert total is not None
        # Frame 6 (ARP) belongs to no stream, so 5 of the 6 rows are rolled up.
        assert total[0] == 5

    def test_empty_pkts_builds_no_streams(self, con: DuckDBPyConnection) -> None:
        con.execute("DELETE FROM main.pkts")
        assert build_streams(con) == StreamsResult(tcp_streams=0, udp_streams=0)
        assert stream_rows(con) == []

    def test_byte_count_is_the_sum_of_frame_len(self, con: DuckDBPyConnection) -> None:
        # Documented byte definition: on-the-wire frame bytes (frame.len),
        # which is what tshark's conversation statistics count.
        build_streams(con)
        row = con.execute(
            "SELECT byte_count FROM main.streams WHERE protocol = 'udp' AND stream_id = 0"
        ).fetchone()
        assert row is not None
        assert row[0] == 73 + 90


class TestMultiValuePrerequisites:
    def test_a_multi_value_prerequisite_uses_the_first_occurrence(self) -> None:
        # ip.src can be materialized multi-value (a tunnel dissects two), in
        # which case the column is a LIST and the rollup takes occurrence one.
        connection: DuckDBPyConnection = duckdb.connect(":memory:")
        try:
            create_schema(connection)
            materialize_fields(
                connection, tuple(PREREQ_FTYPES), multi=frozenset({"ip.src", "ip.dst"})
            )
            connection.execute(
                "INSERT INTO main.pkts (frame_number, frame_time, frame_len, ip_src, ip_dst, "
                "tcp_stream, tcp_srcport, tcp_dstport) VALUES "
                "(1, TIMESTAMP '2026-08-18 00:00:00', 54, ?, ?, 0, 1234, 80)",
                [[ip("10.0.0.1"), ip("192.168.0.1")], [ip("10.0.0.2"), ip("192.168.0.2")]],
            )
            build_streams(connection)
            row = connection.execute("SELECT src_addr, dst_addr FROM main.streams").fetchone()
        finally:
            connection.close()
        assert row == (ip("10.0.0.1"), ip("10.0.0.2"))


class TestIPv4OnlyAddresses:
    """src_addr/dst_addr come from ip.src/ip.dst, so they are IPv4-only.

    The documented rule is that a NULL address means exactly one thing — the
    stream's first frame carried no IPv4 header (in practice: an IPv6 stream).
    tshark does assign tcp.stream/udp.stream to IPv6 packets, so such rows are
    real, and their *ports* are real too: srcport/dstport are transport-layer
    fields and do not depend on the network layer. Only the addresses go
    missing, which is why the rows are kept rather than dropped.
    """

    def test_a_stream_with_no_ipv4_header_nulls_addresses_but_keeps_ports(
        self, con: DuckDBPyConnection
    ) -> None:
        # Frames 7 and 8 stand in for an IPv6 flow the way tshark dissects one:
        # tcp.stream and both ports present, ip.src/ip.dst absent (verified
        # against a real IPv6 capture; the fixtures here are IPv4-only).
        con.executemany(
            INSERT_PACKETS,
            [
                packet(7, 74, None, None, tcp=(2, 51235, 443)),
                packet(8, 86, None, None, tcp=(2, 443, 51235)),
            ],
        )
        build_streams(con)
        row = con.execute(
            "SELECT src_addr, dst_addr, src_port, dst_port, pkt_count, byte_count, "
            "first_frame, last_frame FROM main.streams "
            "WHERE protocol = 'tcp' AND stream_id = 2"
        ).fetchone()
        # Addresses NULL, everything else intact — including the ports, taken
        # from the same first frame, and the counts and frame range.
        assert row == (None, None, 51235, 443, 2, 74 + 86, 7, 8)

    def test_addressless_streams_are_separable_from_ipv4_ones(
        self, con: DuckDBPyConnection
    ) -> None:
        con.executemany(INSERT_PACKETS, [packet(7, 74, None, None, tcp=(2, 51235, 443))])
        build_streams(con)
        # The documented way to select only the fully-addressed streams.
        addressed = con.execute(
            "SELECT protocol, stream_id FROM main.streams "
            "WHERE src_addr IS NOT NULL ORDER BY protocol, stream_id"
        ).fetchall()
        assert addressed == [("tcp", 0), ("tcp", 1), ("udp", 0)]
        # The IPv6 stream is still counted, not dropped.
        total = con.execute("SELECT count(*) FROM main.streams").fetchone()
        assert total is not None
        assert total[0] == 4


class TestIdempotence:
    def test_rebuilding_replaces_rows_without_duplicating(self, con: DuckDBPyConnection) -> None:
        first = build_streams(con)
        before = stream_rows(con)
        second = build_streams(con)
        assert second == first
        assert stream_rows(con) == before

    def test_rebuilding_drops_rows_whose_packets_are_gone(self, con: DuckDBPyConnection) -> None:
        build_streams(con)
        con.execute("DELETE FROM main.pkts WHERE tcp_stream = 1")
        assert build_streams(con) == StreamsResult(tcp_streams=1, udp_streams=1)
        assert [(row[0], row[1]) for row in stream_rows(con)] == [("tcp", 0), ("udp", 0)]

    def test_rebuilding_picks_up_new_packets(self, con: DuckDBPyConnection) -> None:
        build_streams(con)
        con.executemany(
            INSERT_PACKETS,
            [packet(7, 100, "10.0.0.1", "10.0.0.2", tcp=(0, 51234, 443))],
        )
        build_streams(con)
        row = con.execute(
            "SELECT pkt_count, byte_count, last_frame, last_time FROM main.streams "
            "WHERE protocol = 'tcp' AND stream_id = 0"
        ).fetchone()
        assert row == (3, 54 + 66 + 100, 7, datetime(2026, 8, 18, 0, 0, 6))

    def test_a_stale_row_from_another_build_is_cleared(self, con: DuckDBPyConnection) -> None:
        # One workspace holds one capture, so a rebuild owns the whole table.
        con.execute("INSERT INTO main.streams (stream_id, protocol) VALUES (99, 'tcp')")
        build_streams(con)
        assert 99 not in [row[1] for row in stream_rows(con)]

    def test_rebuilding_inside_one_transaction_survives_the_unique_key(
        self, con: DuckDBPyConnection
    ) -> None:
        # The real path: Workspace.build_streams() runs the DELETE and the
        # re-INSERT of the *same* (protocol, stream_id) keys inside a single
        # write() transaction. An index that held the deleted keys until commit
        # would reject that as a duplicate, so the interaction between the
        # UNIQUE key and the whole-table rebuild is pinned rather than assumed.
        build_streams(con)
        before = stream_rows(con)
        con.execute("BEGIN")
        result = build_streams(con)
        con.execute("COMMIT")
        assert result == StreamsResult(tcp_streams=2, udp_streams=1)
        assert stream_rows(con) == before

    def test_the_key_rejects_a_duplicate_conversation(self, con: DuckDBPyConnection) -> None:
        # Storage backs the one-row-per-conversation rule up, so a second
        # writer cannot leave two rows for one stream even outside build_streams.
        build_streams(con)
        with pytest.raises(duckdb.ConstraintException):
            con.execute("INSERT INTO main.streams (stream_id, protocol) VALUES (0, 'tcp')")
