"""Workspace annotations API tests (issue #30)."""

from __future__ import annotations

import subprocess
import sys
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from remora.workspace import Workspace
from remora.workspace.annotations import (
    ANNOTATION_SCOPES,
    AnnotationRecord,
    add_annotation,
    delete_orphan_annotations,
    list_annotations,
    remove_annotation,
    remove_annotations,
)
from remora.workspace.errors import WorkspaceModeError
from remora.workspace.schema import add_field_column, create_schema
from remora.workspace.types import column_spec

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


READ_MARK = "SELECT value FROM meta.info WHERE key = 'next_annotation_id'"
DROP_MARK = "DELETE FROM meta.info WHERE key = 'next_annotation_id'"


class TestIdAllocation:
    """Ids come from the meta.info high-water mark: monotonic, never reused."""

    def test_ids_are_never_recycled(self, con: DuckDBPyConnection) -> None:
        first = add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        assert first == 1
        assert remove_annotation(con, first) is True
        second = add_annotation(con, "packet", 2, "b", created_at=UTC_NOW)
        # The mark does not go back down, so the freed id is not reissued.
        assert second == 2
        # A stale id therefore names nothing rather than the newer finding.
        assert remove_annotation(con, first) is False
        assert [r.annotation_id for r in list_annotations(con)] == [2]

    def test_the_mark_is_stored_in_meta_info(self, con: DuckDBPyConnection) -> None:
        add_annotation(con, "packet", 1, "a", created_at=UTC_NOW)
        row = con.execute(READ_MARK).fetchone()
        assert row is not None and int(row[0]) == 2

    def test_a_legacy_workspace_without_the_key_is_seeded(self, tmp_path: Path) -> None:
        # A workspace written before the mark existed has no row; the next
        # add seeds it from max(annotation_id) + 1 and carries on.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            ws.add_annotation("packet", 1, "a", created_at=UTC_NOW)
            ws.add_annotation("packet", 2, "b", created_at=UTC_NOW)
            with ws.write() as con:
                con.execute(DROP_MARK)
            assert ws.add_annotation("packet", 3, "c", created_at=UTC_NOW) == 3
            with ws.read() as con:
                row = con.execute(READ_MARK).fetchone()
            assert row is not None and int(row[0]) == 4
            assert [r.annotation_id for r in ws.list_annotations()] == [1, 2, 3]

    def test_concurrent_adds_never_share_an_id(self, tmp_path: Path) -> None:
        # Workspace.write() permits concurrent same-process transactions, so
        # the allocator is what has to keep ids distinct: the losers of the
        # race conflict on the meta.info mark row and roll back loudly
        # instead of committing a shared id.
        path = tmp_path / "ws.duckdb"
        workers = 8
        ready = threading.Barrier(workers)
        guard = threading.Lock()
        succeeded: list[int] = []
        conflicts: list[BaseException] = []
        with Workspace(path, mode="rw") as ws:

            def add(target: int) -> None:
                ready.wait()
                try:
                    annotation_id = ws.add_annotation(
                        "packet", target, "verdict", created_at=UTC_NOW
                    )
                except duckdb.Error as exc:
                    with guard:
                        conflicts.append(exc)
                    return
                with guard:
                    succeeded.append(annotation_id)

            threads = [threading.Thread(target=add, args=(i,)) for i in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            committed = [r.annotation_id for r in ws.list_annotations()]

        assert succeeded, "every add lost the race, which cannot happen"
        assert len(set(committed)) == len(committed), f"an id was shared: {committed}"
        assert sorted(succeeded) == committed
        # No exact failure count: how many transactions overlap is timing.
        assert len(succeeded) + len(conflicts) == workers


def _subprocess_read(path: Path) -> subprocess.CompletedProcess[bytes]:
    """Count annotations from another process over a read-only connection."""
    code = (
        "import duckdb, sys; "
        "con = duckdb.connect(sys.argv[1], read_only=True); "
        "print(con.execute('SELECT count(*) FROM main.annotations').fetchone()[0]); "
        "con.close()"
    )
    return subprocess.run(
        [sys.executable, "-c", code, str(path)],
        check=True,
        capture_output=True,
        timeout=60,
    )


class TestWorkspaceMethods:
    def test_add_list_remove_in_rw_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO main.pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2026-08-18 00:00:00')"
                )
            annotation_id = ws.add_annotation("packet", 1, "verdict", "bad", created_at=UTC_NOW)
            assert annotation_id == 1
            listed = ws.list_annotations()
            assert listed == (
                AnnotationRecord(
                    annotation_id=1,
                    scope="packet",
                    target_id=1,
                    key="verdict",
                    value="bad",
                    created_at=UTC_NOW,
                    orphaned=False,
                ),
            )
            assert ws.remove_annotation(annotation_id) is True
            assert ws.list_annotations() == ()

    def test_stream_annotation_through_the_workspace(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute("INSERT INTO main.streams (stream_id) VALUES (7)")
            ws.add_annotation("stream", 7, "owner", "ruoshi", created_at=UTC_NOW)
            assert ws.list_annotations(scope="stream")[0].target_id == 7

    def test_remove_annotations_and_orphan_cleanup_through_the_workspace(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            ws.add_annotation("packet", 1, "ghost", created_at=UTC_NOW)
            ws.add_annotation("packet", 2, "ghost", created_at=UTC_NOW)
            assert ws.remove_annotations(target_id=2) == 1
            assert ws.delete_orphan_annotations() == 1
            assert ws.list_annotations() == ()

    def test_ro_mode_lists_but_refuses_writes(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            ws.add_annotation("packet", 1, "verdict", "bad", created_at=UTC_NOW)
        with Workspace(path) as ws:
            assert [r.key for r in ws.list_annotations()] == ["verdict"]
            with pytest.raises(WorkspaceModeError, match="mode='rw'"):
                ws.add_annotation("packet", 2, "verdict", "worse", created_at=UTC_NOW)
            with pytest.raises(WorkspaceModeError, match="mode='rw'"):
                ws.remove_annotation(1)
            with pytest.raises(WorkspaceModeError, match="mode='rw'"):
                ws.remove_annotations(key="verdict")
            with pytest.raises(WorkspaceModeError, match="mode='rw'"):
                ws.delete_orphan_annotations()
            # Refused means untouched.
            assert len(ws.list_annotations()) == 1

    def test_no_connection_is_held_between_calls(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            ws.add_annotation("packet", 1, "verdict", "bad", created_at=UTC_NOW)
            # The write lock was released at the end of the call: another
            # process can read while this Workspace object still exists.
            assert _subprocess_read(path).stdout.strip() == b"1"
            ws.add_annotation("packet", 2, "verdict", "worse", created_at=UTC_NOW)
            assert _subprocess_read(path).stdout.strip() == b"2"

    def test_a_failing_call_rolls_back(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with pytest.raises(ValueError, match="key"):
                ws.add_annotation("packet", 1, "", created_at=UTC_NOW)
            assert ws.list_annotations() == ()


class TestSurvival:
    """What a re-materialization does to annotations (issue #30's core question)."""

    @staticmethod
    def _materialize(ws: Workspace, frames: tuple[int, ...]) -> None:
        """Rewrite pkts the way #31's materialize pipeline will: replace rows."""
        with ws.write() as con:
            con.execute("DELETE FROM main.pkts")
            for frame in frames:
                con.execute(
                    "INSERT INTO main.pkts (frame_number, frame_time) VALUES (?, ?)",
                    # Naive: DuckDB TIMESTAMP is timezone-naive UTC by the
                    # convention in remora.workspace.types.
                    [frame, datetime(2026, 8, 18, 0, 0, frame)],
                )

    def test_annotations_survive_a_column_being_added(self, tmp_path: Path) -> None:
        # Re-materializing with a wider field set adds columns to pkts and
        # rewrites its rows; annotations live in their own table and must be
        # untouched, still pointing at the same frames.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1, 2, 3))
            ws.add_annotation("packet", 2, "verdict", "retransmit", created_at=UTC_NOW)
            spec = column_spec("tcp.port", "FT_UINT16", multi=True)
            with ws.write() as con:
                add_field_column(con, spec.column_name, spec.sql_type)
                sql = (
                    "SELECT count(*) FROM duckdb_columns() "
                    "WHERE database_name = current_database() "
                    "AND schema_name = 'main' AND table_name = 'pkts' "
                    "AND column_name = ?"
                )
                cols = con.execute(sql, [spec.column_name]).fetchone()
                assert cols is not None and cols[0] == 1
            self._materialize(ws, (1, 2, 3))
            assert ws.list_annotations() == (
                AnnotationRecord(
                    annotation_id=1,
                    scope="packet",
                    target_id=2,
                    key="verdict",
                    value="retransmit",
                    created_at=UTC_NOW,
                    orphaned=False,
                ),
            )

    def test_annotations_survive_close_and_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1,))
            ws.add_annotation("packet", 1, "verdict", "bad", created_at=UTC_NOW)
        with Workspace(path) as ws:
            assert [r.value for r in ws.list_annotations()] == ["bad"]

    def test_a_narrower_rematerialization_orphans_but_keeps(self, tmp_path: Path) -> None:
        # The decided policy: kept-but-flagged. A narrower display filter
        # drops frame 3 from pkts; the finding about it is analyst data and
        # is never destroyed on its own.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1, 2, 3))
            ws.add_annotation("packet", 1, "verdict", "kept", created_at=UTC_NOW)
            ws.add_annotation("packet", 3, "verdict", "dropped", created_at=UTC_NOW)
            self._materialize(ws, (1, 2))
            by_id = {r.annotation_id: r for r in ws.list_annotations()}
            assert len(by_id) == 2
            assert by_id[1].orphaned is False
            assert by_id[2].orphaned is True
            assert by_id[2].value == "dropped"

    def test_a_wider_rematerialization_un_orphans(self, tmp_path: Path) -> None:
        # Orphanhood is derived at read time, which is why nothing deletes an
        # orphan implicitly: widening the filter brings the target back.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1,))
            ws.add_annotation("packet", 3, "verdict", "dropped", created_at=UTC_NOW)
            assert ws.list_annotations()[0].orphaned is True
            self._materialize(ws, (1, 2, 3))
            assert ws.list_annotations()[0].orphaned is False

    def test_explicit_cleanup_is_the_only_thing_that_deletes_orphans(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1, 2, 3))
            ws.add_annotation("packet", 1, "verdict", "kept", created_at=UTC_NOW)
            ws.add_annotation("packet", 3, "verdict", "dropped", created_at=UTC_NOW)
            self._materialize(ws, (1,))
            assert len(ws.list_annotations()) == 2
            assert ws.delete_orphan_annotations() == 1
            remaining = ws.list_annotations()
            assert [r.target_id for r in remaining] == [1]
            assert remaining[0].orphaned is False

    def test_annotations_survive_compact(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._materialize(ws, (1, 2))
            ws.add_annotation("packet", 1, "verdict", "kept", created_at=UTC_NOW)
            ws.compact()
            assert [r.value for r in ws.list_annotations()] == ["kept"]
