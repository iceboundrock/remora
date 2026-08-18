"""Workspace annotations API tests (issue #30)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from remora.workspace.annotations import (
    ANNOTATION_SCOPES,
    AnnotationRecord,
    add_annotation,
    delete_orphan_annotations,
    list_annotations,
    remove_annotation,
    remove_annotations,
)
from remora.workspace.schema import create_schema

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

UTC_NOW = datetime(2026, 8, 18, 12, 30, 45, 123456, tzinfo=timezone.utc)


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    """An in-memory workspace with two packets and one stream."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    connection.execute(
        "INSERT INTO main.pkts (frame_number, frame_time) VALUES "
        "(1, TIMESTAMP '2026-08-18 00:00:00'), (2, TIMESTAMP '2026-08-18 00:00:01')"
    )
    connection.execute("INSERT INTO main.streams (stream_id) VALUES (7)")
    try:
        yield connection
    finally:
        connection.close()


class TestAddAndList:
    def test_scopes_are_packet_and_stream(self) -> None:
        assert ANNOTATION_SCOPES == ("packet", "stream")

    def test_packet_annotation_round_trips(self, con: DuckDBPyConnection) -> None:
        annotation_id = add_annotation(
            con, "packet", 1, "verdict", "retransmission storm", created_at=UTC_NOW
        )
        assert annotation_id == 1
        assert list_annotations(con) == (
            AnnotationRecord(
                annotation_id=1,
                scope="packet",
                target_id=1,
                key="verdict",
                value="retransmission storm",
                created_at=UTC_NOW,
                orphaned=False,
            ),
        )

    def test_stream_annotation_round_trips(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "stream", 7, "owner", "ruoshi", created_at=UTC_NOW)
        record = list_annotations(con)[0]
        assert record.scope == "stream"
        assert record.target_id == 7
        assert record.orphaned is False

    def test_value_is_optional(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "flagged", created_at=UTC_NOW)
        assert list_annotations(con)[0].value is None

    def test_ids_ascend(self, con: DuckDBPyConnection) -> None:
        first = add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        second = add_annotation(con, "packet", 2, "b", created_at=UTC_NOW)
        assert (first, second) == (1, 2)
        assert [r.annotation_id for r in list_annotations(con)] == [1, 2]

    def test_created_at_comes_back_as_aware_utc(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        stored = list_annotations(con)[0].created_at
        assert stored.tzinfo is timezone.utc
        assert stored == UTC_NOW

    def test_naive_created_at_is_taken_as_utc(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW.replace(tzinfo=None))
        assert list_annotations(con)[0].created_at == UTC_NOW

    def test_default_created_at_is_now_utc(self, con: DuckDBPyConnection) -> None:
        before = datetime.now(timezone.utc)
        add_annotation(con, "packet", 1, "a")
        stored = list_annotations(con)[0].created_at
        assert stored.tzinfo is timezone.utc
        assert stored >= before.replace(microsecond=0)

    def test_missing_target_is_flagged_orphaned(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 999, "ghost", created_at=UTC_NOW)
        add_annotation(con, "stream", 42, "ghost", created_at=UTC_NOW)
        assert [r.orphaned for r in list_annotations(con)] == [True, True]

    def test_unknown_scope_is_refused(self, con: DuckDBPyConnection) -> None:
        with pytest.raises(ValueError, match="scope"):
            add_annotation(con, "flow", 1, "a", created_at=UTC_NOW)  # type: ignore[arg-type]

    def test_empty_key_is_refused(self, con: DuckDBPyConnection) -> None:
        with pytest.raises(ValueError, match="key"):
            add_annotation(con, "packet", 1, "", created_at=UTC_NOW)

    def test_filters(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "verdict", "bad", created_at=UTC_NOW)
        add_annotation(con, "packet", 2, "verdict", "good", created_at=UTC_NOW)
        add_annotation(con, "stream", 7, "owner", "ruoshi", created_at=UTC_NOW)
        assert [r.annotation_id for r in list_annotations(con, scope="stream")] == [3]
        assert [r.annotation_id for r in list_annotations(con, target_id=2)] == [2]
        assert [r.annotation_id for r in list_annotations(con, key="verdict")] == [1, 2]
        exact = list_annotations(con, scope="packet", target_id=2, key="verdict")
        assert [r.annotation_id for r in exact] == [2]

    def test_empty_table_lists_empty(self, con: DuckDBPyConnection) -> None:
        assert list_annotations(con) == ()

    def test_duplicate_frame_numbers_do_not_multiply_rows(self, con: DuckDBPyConnection) -> None:
        # pkts has no PRIMARY KEY (uniqueness is convention), so the orphan
        # check must not be a join that fans out on a repeated frame_number.
        con.execute("INSERT INTO main.pkts VALUES (1, TIMESTAMP '2026-08-18 00:00:02')")
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        assert len(list_annotations(con)) == 1


class TestRemoval:
    def test_remove_by_id(self, con: DuckDBPyConnection) -> None:
        first = add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        add_annotation(con, "packet", 2, "b", created_at=UTC_NOW)
        assert remove_annotation(con, first) is True
        assert [r.annotation_id for r in list_annotations(con)] == [2]

    def test_remove_unknown_id_is_false(self, con: DuckDBPyConnection) -> None:
        assert remove_annotation(con, 404) is False

    def test_remove_by_key(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "verdict", created_at=UTC_NOW)
        add_annotation(con, "packet", 2, "verdict", created_at=UTC_NOW)
        add_annotation(con, "stream", 7, "owner", created_at=UTC_NOW)
        assert remove_annotations(con, key="verdict") == 2
        assert [r.key for r in list_annotations(con)] == ["owner"]

    def test_remove_by_scope_and_target(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        add_annotation(con, "stream", 1, "a", created_at=UTC_NOW)
        assert remove_annotations(con, scope="stream", target_id=1) == 1
        assert [r.scope for r in list_annotations(con)] == ["packet"]

    def test_remove_without_filters_is_refused(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        with pytest.raises(ValueError, match="at least one"):
            remove_annotations(con)
        assert len(list_annotations(con)) == 1

    def test_removing_nothing_returns_zero(self, con: DuckDBPyConnection) -> None:
        assert remove_annotations(con, key="absent") == 0

    def test_delete_orphans_leaves_live_annotations(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "live", created_at=UTC_NOW)
        add_annotation(con, "packet", 999, "ghost", created_at=UTC_NOW)
        add_annotation(con, "stream", 7, "live", created_at=UTC_NOW)
        add_annotation(con, "stream", 42, "ghost", created_at=UTC_NOW)
        assert delete_orphan_annotations(con) == 2
        assert [r.key for r in list_annotations(con)] == ["live", "live"]
        assert all(r.orphaned is False for r in list_annotations(con))

    def test_delete_orphans_with_none_present_returns_zero(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "live", created_at=UTC_NOW)
        assert delete_orphan_annotations(con) == 0
