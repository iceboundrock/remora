"""Cache hit/miss detection and incremental column backfill (#32).

Driven entirely through the injected ``TsharkRunner`` seam, so no test here
spawns a process: a hit is *proved* by the runner never being called, and a
backfill by exactly which fields the one call it does make projects.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

pytest.importorskip("duckdb")

from ipaddress import IPv4Address

from remora.fields import FieldRef
from remora.reader.fields_reader import OCC_SEP, UNIT_SEP
from remora.workspace import (
    CacheKeyRecord,
    ColumnNameCollisionError,
    FieldRecord,
    MaterializationMismatchError,
    MaterializeResult,
    Workspace,
    WorkspaceError,
    fingerprint_pcap,
    materialize_into,
)
from remora.workspace.materialize import _argv_residue
from remora.workspace.schema import (
    read_cache_keys,
    read_fields,
    read_pkts_columns,
    record_cache_key,
    register_fields,
)
from workspace_doubles import (
    FRAME_NUMBER,
    IP_DST,
    IP_SRC,
    ROWS,
    TCP_PORT,
    FakeRunner,
    count,
    line,
    make_pcap,
    pkts_columns,
    reading,
)

#: ``ROWS`` without the ``tcp.port`` column — what a first run projecting only
#: ``ip.src`` sees. Every canned line set here has to match its run's
#: projection exactly, which is itself part of what the suite pins.
IP_ROWS = [
    line("1", "1614597071.5", "10.0.0.1"),
    line("2", "1614597072.25", "10.0.0.2"),
    line("3", "1614597073.0", ""),
]

#: The same frames projecting only ``tcp.port``.
PORT_ROWS = [
    line("1", "1614597071.5", ("51234", "443")),
    line("2", "1614597072.25", ("443", "51234")),
    line("3", "1614597073.0", ""),
]

#: The same three frames as ``ROWS``, projected for a *backfill* scan: the row
#: key plus the one new field, which is all a backfill asks tshark for.
BACKFILL_ROWS = [
    line("1", ("51234", "443")),
    line("2", ("443", "51234")),
    line("3", ""),
]


def run(
    ws_path: Path,
    pcap: Path,
    fields: list[FieldRef[Any]],
    *,
    lines: list[str] | None = None,
    **kwargs: Any,
) -> tuple[FakeRunner, MaterializeResult]:
    """Materialize into ``ws_path`` through a fake runner; return both."""
    runner = FakeRunner(IP_ROWS if lines is None else lines)
    kwargs.setdefault("tshark", "tshark")
    kwargs.setdefault("tshark_version", "4.6.7")
    with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
        result = materialize_into(con, pcap=pcap, fields=fields, runner=runner, **kwargs)
    return runner, result


def refuse(
    ws_path: Path,
    pcap: Path,
    fields: list[FieldRef[Any]],
    error: type[Exception],
    match: str,
    **kwargs: Any,
) -> FakeRunner:
    """Assert a second materialize is refused, and that nothing was spawned."""
    runner = FakeRunner(ROWS)
    kwargs.setdefault("tshark", "tshark")
    kwargs.setdefault("tshark_version", "4.6.7")
    with (
        Workspace(ws_path, mode="rw") as ws,
        pytest.raises(error, match=match),
        ws.write() as con,
    ):
        materialize_into(con, pcap=pcap, fields=fields, runner=runner, **kwargs)
    assert runner.argv is None
    return runner


def checksum(con: DuckDBPyConnection, columns: list[str]) -> str:
    """Digest of every value in ``columns``, row-key ordered.

    The acceptance criterion for a backfill is that the columns that were
    already there come back *identical*, so it is compared as one digest over
    the whole column set rather than value by value.
    """
    projection = ", ".join(f'"{column}"' for column in columns)
    rows = con.execute(f"SELECT {projection} FROM main.pkts ORDER BY frame_number").fetchall()
    return hashlib.sha256(repr(rows).encode()).hexdigest()


class TestArgvResidue:
    """The argv comparison's parser, pinned directly.

    ``_argv_residue`` strips the argv parts other cache-key components own,
    and in doing so assumes each of ``-e`` / ``-r`` / ``-Y`` takes exactly one
    following value. That holds because ``_build_argv`` — the only producer of
    these argvs — is the other half of the same module. These tests pin the
    assumption on both sides so it cannot drift silently.
    """

    def test_matches_the_argv_the_pipeline_builds(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        runner, result = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS, filter=TCP_PORT == 443)
        assert runner.argv is not None
        # Every owned option present, each with exactly one value, and what is
        # left is argv[0] plus the -T/-E options that shape the dissection.
        assert result.cache_key.argv == tuple(runner.argv)
        assert _argv_residue(runner.argv) == (
            "tshark",
            "-T",
            "fields",
            "-E",
            f"separator={UNIT_SEP}",
            "-E",
            f"aggregator={OCC_SEP}",
            "-E",
            "occurrence=a",
        )

    def test_strips_each_owned_option_with_its_value(self) -> None:
        argv = ["tshark", "-r", "cap.pcap", "-Y", "tcp.port == 443", "-e", "ip.src"]
        assert _argv_residue(argv) == ("tshark",)

    def test_absent_filter_leaves_the_same_residue(self) -> None:
        # -Y present or absent must not change the residue, since the dfilter
        # is compared as its own component.
        with_filter = ["tshark", "-r", "cap.pcap", "-Y", "ip", "-T", "fields"]
        without = ["tshark", "-r", "cap.pcap", "-T", "fields"]
        assert _argv_residue(with_filter) == _argv_residue(without) == ("tshark", "-T", "fields")

    def test_unknown_options_survive_verbatim(self) -> None:
        # Anything that changes how bytes are dissected is exactly what the
        # residue exists to compare, so it must pass through untouched — order
        # and values included.
        argv = [
            "tshark",
            "-X",
            "lua_script:evil.lua",
            "-r",
            "cap.pcap",
            "-d",
            "tcp.port==8888,http",
            "-o",
            "tcp.desegment_tcp_streams:FALSE",
            "-e",
            "ip.src",
        ]
        assert _argv_residue(argv) == (
            "tshark",
            "-X",
            "lua_script:evil.lua",
            "-d",
            "tcp.port==8888,http",
            "-o",
            "tcp.desegment_tcp_streams:FALSE",
        )

    def test_a_value_that_looks_like_an_option_is_not_reparsed(self) -> None:
        # The value after an owned option is consumed as a value, never
        # re-examined: a display filter spelled "-e" cannot swallow the token
        # after it.
        assert _argv_residue(["tshark", "-Y", "-e", "-T", "fields"]) == (
            "tshark",
            "-T",
            "fields",
        )

    def test_repeated_projection_options_all_strip(self) -> None:
        argv = ["tshark", "-e", "a", "-e", "b", "-e", "c", "-T", "fields"]
        assert _argv_residue(argv) == ("tshark", "-T", "fields")


class TestCacheHit:
    """Requested fields are a subset of what is materialized: no rescan."""

    def test_exact_repeat_spawns_nothing(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _first_runner, first = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)
        again, second = run(ws_path, pcap, [IP_SRC, TCP_PORT])
        # The whole point: the second call never builds an argv, so no tshark
        # process could have been spawned even by a real runner.
        assert again.argv is None
        assert second.outcome == "hit"
        assert second.row_count == 0
        assert second.batch_count == 0
        assert second.added_fields == ()
        assert second.cache_key == first.cache_key
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 3
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src", "tcp_port"]
            assert read_cache_keys(con) == (first.cache_key,)

    def test_subset_request_is_served_from_cache(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _first_runner, first = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)
        again, second = run(ws_path, pcap, [IP_SRC])
        assert again.argv is None
        assert second.outcome == "hit"
        # The stored key still describes the *materialized* set, not the
        # narrower request: narrowing must never discard columns.
        assert second.cache_key == first.cache_key
        assert second.cache_key.fields == ("ip.src", "tcp.port")
        assert [record.abbrev for record in second.fields] == ["ip.src", "tcp.port"]
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src", "tcp_port"]

    def test_empty_request_hits_any_materialization(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        again, second = run(ws_path, pcap, [])
        assert again.argv is None
        assert second.outcome == "hit"

    def test_row_key_only_widening_needs_no_rescan(self, tmp_path: Path) -> None:
        # frame.number is served by the pkts row key, so adding it to the
        # request adds no column — but it does count in the key's field set
        # (#31), so the key is widened all the same, and the next identical
        # request is then a plain hit instead of deciding this over again.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        again, second = run(ws_path, pcap, [IP_SRC, FRAME_NUMBER])
        assert again.argv is None
        assert second.outcome == "hit"
        assert second.added_fields == ()
        assert second.cache_key.fields == ("frame.number", "ip.src")
        third_runner, third = run(ws_path, pcap, [IP_SRC, FRAME_NUMBER])
        assert third_runner.argv is None
        assert third.outcome == "hit"
        assert third.cache_key == second.cache_key
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src"]
            assert read_cache_keys(con) == (second.cache_key,)

    def test_moved_capture_with_identical_bytes_still_hits(self, tmp_path: Path) -> None:
        # The fingerprint identifies the capture by its bytes, so the ``-r``
        # path is deliberately outside the argv comparison: the same capture
        # under a new name is the same capture.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _first_runner, first = run(ws_path, pcap, [IP_SRC])
        moved = tmp_path / "moved.pcap"
        shutil.copy2(pcap, moved)
        assert fingerprint_pcap(moved) == fingerprint_pcap(pcap)
        again, second = run(ws_path, moved, [IP_SRC])
        assert again.argv is None
        assert second.outcome == "hit"
        assert second.cache_key == first.cache_key

    def test_workspace_method_hits_too(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        runner = FakeRunner(IP_ROWS)
        again = FakeRunner(IP_ROWS)
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            first = ws.materialize(pcap, [IP_SRC], tshark_version="4.6.7", runner=runner)
            second = ws.materialize(pcap, [IP_SRC], tshark_version="4.6.7", runner=again)
            with ws.read() as con:
                assert count(con, "main.pkts") == 3
        assert first.outcome == "materialized"
        assert second.outcome == "hit"
        assert again.argv is None


class TestBackfill:
    """New fields rescan the capture for those fields only, adding columns."""

    def test_backfill_projects_only_new_fields_and_the_row_key(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with reading(ws_path) as con:
            before = checksum(con, ["frame_number", "frame_time", "ip_src"])
        again, second = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=BACKFILL_ROWS)
        assert again.argv is not None
        # The rescan is unavoidable (tshark has to dissect again), but it must
        # cost only the new field: no ip.src, no frame.time_epoch.
        assert again.projected() == ["frame.number", "tcp.port"]
        assert second.outcome == "backfilled"
        assert second.row_count == 3
        assert [record.abbrev for record in second.added_fields] == ["tcp.port"]
        assert [record.abbrev for record in second.fields] == ["ip.src", "tcp.port"]
        with reading(ws_path) as con:
            # Byte-identical: the columns that were already there are not
            # rewritten, only read.
            assert checksum(con, ["frame_number", "frame_time", "ip_src"]) == before
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src", "tcp_port"]
            rows = con.execute(
                "SELECT frame_number, ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
            ).fetchall()
            assert rows == [
                (1, int(IPv4Address("10.0.0.1")), [51234, 443]),
                (2, int(IPv4Address("10.0.0.2")), [443, 51234]),
                (3, None, []),
            ]
            # An absent multi-value field is [] after a backfill exactly as it
            # is after a fresh run — never the NULL that ADD COLUMN leaves.
            assert count(con, "main.pkts WHERE tcp_port IS NULL") == 0
            assert [record.abbrev for record in read_fields(con)] == ["ip.src", "tcp.port"]
            assert read_cache_keys(con) == (second.cache_key,)
        assert second.cache_key.fields == ("ip.src", "tcp.port")

    def test_backfilled_workspace_matches_a_single_run(self, tmp_path: Path) -> None:
        # The strongest statement of the contract: materializing {a} then {b}
        # leaves exactly the workspace materializing {a, b} in one go would —
        # same rows, same registry, and the same cache key, because the
        # recorded key describes the union and its argv is canonicalized.
        pcap = make_pcap(tmp_path)
        incremental = tmp_path / "incremental.duckdb"
        run(incremental, pcap, [IP_SRC])
        _runner, backfilled = run(incremental, pcap, [IP_SRC, TCP_PORT], lines=BACKFILL_ROWS)
        one_shot_path = tmp_path / "one_shot.duckdb"
        _one_shot_runner, one_shot = run(one_shot_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)

        assert backfilled.cache_key.key == one_shot.cache_key.key
        assert backfilled.cache_key.fields == one_shot.cache_key.fields
        assert backfilled.cache_key.argv == one_shot.cache_key.argv
        with reading(incremental) as con:
            incremental_rows = con.execute(
                "SELECT frame_number, frame_time, ip_src, tcp_port "
                "FROM main.pkts ORDER BY frame_number"
            ).fetchall()
            incremental_columns = pkts_columns(con)
            incremental_fields = [
                (record.abbrev, record.column_name, record.ftype, record.multi, record.column_type)
                for record in read_fields(con)
            ]
        with reading(one_shot_path) as con:
            one_shot_rows = con.execute(
                "SELECT frame_number, frame_time, ip_src, tcp_port "
                "FROM main.pkts ORDER BY frame_number"
            ).fetchall()
            one_shot_columns = pkts_columns(con)
            one_shot_fields = [
                (record.abbrev, record.column_name, record.ftype, record.multi, record.column_type)
                for record in read_fields(con)
            ]
        assert incremental_rows == one_shot_rows
        assert incremental_columns == one_shot_columns
        assert incremental_fields == one_shot_fields

    def test_backfill_over_an_empty_capture(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC], lines=[])
        again, second = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=[])
        assert again.argv is not None
        assert second.outcome == "backfilled"
        assert second.row_count == 0
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src", "tcp_port"]

    def test_backfill_batches_are_bounded(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        first_lines = [line(str(n), f"16145970{70 + n}.0", "10.0.0.1") for n in range(1, 11)]
        run(ws_path, pcap, [IP_SRC], lines=first_lines)
        backfill_lines = [line(str(n), "443") for n in range(1, 11)]
        _runner, second = run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=backfill_lines, batch_size=4)
        assert second.row_count == 10
        assert second.batch_count == 3
        with reading(ws_path) as con:
            assert count(con, "main.pkts WHERE list_contains(tcp_port, 443)") == 10

    def refuse_backfill(self, ws_path: Path, pcap: Path, lines: list[str], match: str) -> None:
        """Assert a backfill scan is refused and leaves the workspace as it was."""
        with reading(ws_path) as con:
            before_columns = pkts_columns(con)
            before_keys = read_cache_keys(con)
            before_data = checksum(con, before_columns)
        runner = FakeRunner(lines)
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match=match),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        with reading(ws_path) as con:
            assert pkts_columns(con) == before_columns
            assert read_cache_keys(con) == before_keys
            assert checksum(con, before_columns) == before_data

    def test_duplicate_and_missing_frame_at_equal_count_refused(self, tmp_path: Path) -> None:
        # The case a row *count* cannot see: three scanned rows for three
        # stored rows, but frame 2 twice and frame 3 never — one stored row
        # updated twice, another left at the NULL its ADD COLUMN back-filled,
        # and the cache key recorded as if the backfill were complete. The row
        # keys are therefore compared as sets, not counted.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        duplicated = [line("1", "51234"), line("2", "443"), line("2", "8080")]
        self.refuse_backfill(
            ws_path, pcap, duplicated, r"produced more than once: \[2\].*never produced: \[3\]"
        )

    def test_duplicate_frame_alone_refused(self, tmp_path: Path) -> None:
        # A scan repeating a frame with no row missing: the count is *larger*
        # than pkts, but what makes it wrong is the repeat, which is what the
        # message must say.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        duplicated = [*BACKFILL_ROWS, line("2", "8080")]
        self.refuse_backfill(ws_path, pcap, duplicated, r"produced more than once: \[2\]")

    def test_missing_frame_refused(self, tmp_path: Path) -> None:
        # The fingerprint's known blind spot (an in-place edit that changes
        # neither size nor mtime) would otherwise leave frame 3 silently
        # unmatched by the UPDATE.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        self.refuse_backfill(ws_path, pcap, BACKFILL_ROWS[:2], r"never produced: \[3\]")

    def test_frame_absent_from_pkts_refused(self, tmp_path: Path) -> None:
        # A scanned key matching no stored row: its UPDATE silently affects
        # nothing, so it has to be caught by the anti-join in the other
        # direction.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        shifted = [line("1", "51234"), line("2", "443"), line("9", "8080")]
        self.refuse_backfill(
            ws_path, pcap, shifted, r"pkts does not hold: \[9\].*never produced: \[3\]"
        )

    def test_duplicate_stored_frame_number_refused(self, tmp_path: Path) -> None:
        # pkts has no PRIMARY KEY, so frame_number's uniqueness is a
        # convention. A workspace where it does not hold would have its
        # UPDATE fan out across every row sharing a number — writing one
        # scanned row's values into two stored rows — so the convention is
        # verified before any column is added or any row touched.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("UPDATE main.pkts SET frame_number = 1 WHERE frame_number = 3")
        runner = FakeRunner([line("1", "51234"), line("2", "443")])
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match=r"more than one row: \[1\]"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        # Refused before the scan: no argv was ever built, and no column added.
        assert runner.argv is None
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src"]

    def test_null_stored_frame_number_refused(self, tmp_path: Path) -> None:
        # A NULL row key matches nothing, so its row would silently keep the
        # NULL its ADD COLUMN back-filled.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("UPDATE main.pkts SET frame_number = NULL WHERE frame_number = 3")
        runner = FakeRunner([line("1", "51234"), line("2", "443")])
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match=r"no frame number at all: 1"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        assert runner.argv is None

    def test_null_scan_frame_number_refused(self, tmp_path: Path) -> None:
        # A scanned row carrying no frame number at all matches nothing, and
        # SQL equality never matches NULL — so it must be counted and reported
        # on its own rather than reaching the diagnostics as a value to render
        # (which used to escape as a bare TypeError from int(None), replacing
        # the bounded refusal with a traceback from inside the error path).
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        self.refuse_backfill(
            ws_path,
            pcap,
            [line("1", "51234"), line("", "443"), line("3", "8080")],
            r"carrying no frame number at all: 1",
        )

    def test_every_scan_frame_number_null_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        self.refuse_backfill(
            ws_path,
            pcap,
            [line("", "51234"), line("", "443"), line("", "8080")],
            r"carrying no frame number at all: 3.*never produced: \[1, 2, 3\]",
        )

    def test_drift_examples_are_bounded(self, tmp_path: Path) -> None:
        # A wholly mismatched scan must not build a message naming every row.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        first_lines = [line(str(n), f"16145970{70 + n}.0", "10.0.0.1") for n in range(1, 21)]
        run(ws_path, pcap, [IP_SRC], lines=first_lines)
        shifted = [line(str(n + 100), "443") for n in range(1, 21)]
        runner = FakeRunner(shifted)
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError) as excinfo,
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        message = str(excinfo.value)
        assert "pkts does not hold: [101, 102, 103, 104, 105]" in message
        assert "never produced: [1, 2, 3, 4, 5]" in message

    def test_midstream_failure_rolls_the_backfill_back(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _first, first = run(ws_path, pcap, [IP_SRC])
        with reading(ws_path) as con:
            before = checksum(con, ["frame_number", "frame_time", "ip_src"])
        runner = FakeRunner(BACKFILL_ROWS, fail_after=2)
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(RuntimeError, match="mid-stream failure"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
                batch_size=1,
            )
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src"]
            assert checksum(con, ["frame_number", "frame_time", "ip_src"]) == before
            assert read_cache_keys(con) == (first.cache_key,)

    def test_workspace_method_backfills(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            ws.materialize(pcap, [IP_SRC], tshark_version="4.6.7", runner=FakeRunner(IP_ROWS))
            second = ws.materialize(
                pcap,
                [IP_SRC, TCP_PORT],
                tshark_version="4.6.7",
                runner=FakeRunner(BACKFILL_ROWS),
            )
            with ws.read() as con:
                assert count(con, "main.pkts WHERE tcp_port IS NOT NULL") == 3
        assert second.outcome == "backfilled"


class TestRefusedComponents:
    """Every key component but the field set refuses rather than rescanning."""

    def test_changed_capture_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _runner, first = run(ws_path, pcap, [IP_SRC])
        pcap.write_bytes(b"\xff" * 256)
        refuse(ws_path, pcap, [IP_SRC], MaterializationMismatchError, "capture fingerprint")
        with reading(ws_path) as con:
            assert read_cache_keys(con) == (first.cache_key,)
            assert count(con, "main.pkts") == 3

    def test_changed_dfilter_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC], filter=TCP_PORT == 443)
        refuse(
            ws_path,
            pcap,
            [IP_SRC],
            MaterializationMismatchError,
            "display filter",
            filter=TCP_PORT == 80,
        )

    def test_dropped_dfilter_refused(self, tmp_path: Path) -> None:
        # None and "no filter at all" are different materializations, and #27
        # digests them differently; the comparison must agree.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC], filter=TCP_PORT == 443)
        refuse(ws_path, pcap, [IP_SRC], MaterializationMismatchError, "display filter")

    def test_changed_tshark_version_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        refuse(
            ws_path,
            pcap,
            [IP_SRC],
            MaterializationMismatchError,
            "tshark version",
            tshark_version="4.7.0",
        )

    def test_changed_tshark_arguments_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        refuse(
            ws_path,
            pcap,
            [IP_SRC],
            MaterializationMismatchError,
            "tshark arguments",
            tshark="/opt/other/tshark",
        )

    def test_message_says_what_to_do(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        refuse(
            ws_path,
            pcap,
            [IP_SRC],
            MaterializationMismatchError,
            "fresh workspace",
            tshark_version="4.7.0",
        )

    def test_field_redeclared_with_another_type_refused(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        multi_ip_src: FieldRef[IPv4Address] = FieldRef("ip.src", "FT_IPv4", True)
        refuse(ws_path, pcap, [multi_ip_src], MaterializationMismatchError, "ip.src")

    def test_new_field_colliding_with_a_stored_column_refused(self, tmp_path: Path) -> None:
        # find_collisions runs over the union of stored and requested abbrevs,
        # so a new abbrev cannot claim a column an earlier run already owns.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [TCP_PORT], lines=PORT_ROWS)
        hostile: FieldRef[int] = FieldRef("tcp_port", "FT_UINT16", False)
        refuse(ws_path, pcap, [TCP_PORT, hostile], ColumnNameCollisionError, "tcp_port")
        with reading(ws_path) as con:
            assert pkts_columns(con) == ["frame_number", "frame_time", "tcp_port"]

    def test_rows_without_a_cache_key_refused(self, tmp_path: Path) -> None:
        # A workspace holding packet rows but no cache key was not written by
        # this pipeline, so nothing can be said about what its rows cover.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("INSERT INTO main.pkts (frame_number, frame_time) VALUES (1, NULL)")
        refuse(ws_path, pcap, [IP_SRC], WorkspaceError, "no cache key")

    def test_key_claiming_an_unregistered_field_refused_on_the_hit_path(
        self, tmp_path: Path
    ) -> None:
        # The subset rule reads meta.cache_keys alone, so a key claiming a
        # field meta.fields does not register would answer a request for that
        # field with a *hit* — reporting stored data for a column the
        # workspace may not hold. The two catalogs are written together and
        # are checked to agree before any reuse decision is made.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("DELETE FROM meta.fields WHERE abbrev = 'tcp.port'")
        refuse(ws_path, pcap, [TCP_PORT], WorkspaceError, r"absent from meta.fields.*tcp.port")

    def test_key_claiming_an_unregistered_field_refused_on_the_backfill_path(
        self, tmp_path: Path
    ) -> None:
        # The same inconsistency reached through a widening request, where it
        # would otherwise silently recompute the backfill delta from a
        # registry that disagrees with the key.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("DELETE FROM meta.fields WHERE abbrev = 'tcp.port'")
        refuse(
            ws_path,
            pcap,
            [IP_SRC, TCP_PORT, IP_DST],
            WorkspaceError,
            r"absent from meta.fields.*tcp.port",
        )

    def test_registry_row_the_key_does_not_claim_refused(self, tmp_path: Path) -> None:
        # The other direction: a registered column no key claims means the key
        # does not describe this workspace either, so the subset rule cannot be
        # trusted about it.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _runner, first = run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            register_fields(
                con,
                [
                    FieldRecord(
                        abbrev="ip.dst",
                        column_name="ip_dst",
                        ftype="FT_IPv4",
                        multi=False,
                        column_type="UINTEGER",
                        materialized_at=first.cache_key.created_at,
                    )
                ],
            )
        refuse(ws_path, pcap, [IP_SRC], WorkspaceError, r"not claimed by the cache key.*ip.dst")

    def test_dropped_column_refused_on_the_hit_path(self, tmp_path: Path) -> None:
        # meta.fields describes main.pkts rather than proving anything about
        # it. A column dropped outside this pipeline leaves the registry
        # saying otherwise, and reuse would report a hit for a column that is
        # gone — the caller's next query then failing with a raw DuckDB binder
        # error, far from the cause.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=ROWS)
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("ALTER TABLE main.pkts DROP COLUMN tcp_port")
        refuse(ws_path, pcap, [TCP_PORT], WorkspaceError, r"missing from pkts.*tcp.port")

    def test_dropped_column_refused_on_the_backfill_path(self, tmp_path: Path) -> None:
        # Same corruption reached through a widening request, where the delta
        # is non-empty and a scan would otherwise run against a table missing
        # a column the registry still lists.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("ALTER TABLE main.pkts DROP COLUMN ip_src")
        refuse(ws_path, pcap, [IP_SRC, TCP_PORT], WorkspaceError, r"missing from pkts.*ip.src")

    def test_retyped_column_refused_on_the_hit_path(self, tmp_path: Path) -> None:
        # A column recreated with another type would be read back through the
        # codec its registered type implies, silently.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("ALTER TABLE main.pkts DROP COLUMN ip_src")
            con.execute("ALTER TABLE main.pkts ADD COLUMN ip_src VARCHAR")
        refuse(
            ws_path,
            pcap,
            [IP_SRC],
            WorkspaceError,
            r"type changed.*ip_src is VARCHAR, registered as UINTEGER",
        )

    def test_retyped_column_refused_on_the_backfill_path(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            con.execute("ALTER TABLE main.pkts DROP COLUMN ip_src")
            con.execute("ALTER TABLE main.pkts ADD COLUMN ip_src VARCHAR")
        refuse(ws_path, pcap, [IP_SRC, TCP_PORT], WorkspaceError, r"type changed.*ip_src")

    def test_list_column_type_survives_the_round_trip(self, tmp_path: Path) -> None:
        # The comparison is a string equality against what duckdb_columns()
        # reports, so a list column reporting anything but the "T[]" spelling
        # meta.fields stores would refuse every healthy multi-value workspace.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [TCP_PORT], lines=PORT_ROWS)
        with reading(ws_path) as con:
            assert read_pkts_columns(con)["tcp_port"] == "USMALLINT[]"
            assert [record.column_type for record in read_fields(con)] == ["USMALLINT[]"]
        again, second = run(ws_path, pcap, [TCP_PORT])
        assert again.argv is None
        assert second.outcome == "hit"

    def test_several_cache_keys_refused(self, tmp_path: Path) -> None:
        # One workspace records exactly one materialization; more than one key
        # means something outside this pipeline wrote the catalog.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        _runner, first = run(ws_path, pcap, [IP_SRC])
        planted: CacheKeyRecord = dataclasses.replace(
            first.cache_key, key=first.cache_key.key + "-planted"
        )
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            record_cache_key(con, planted)
        refuse(ws_path, pcap, [IP_SRC], WorkspaceError, "2 cache keys")


class TestInheritedFingerprintBlindSpot:
    """What a backfill does *not* verify — pinned, not fixed.

    Row alignment between the rescan and the stored rows is verified exactly
    (frame-number set match). Value identity of the columns a backfill does
    not rescan rests entirely on the #27 fingerprint, which is a sample of the
    first and last 64 KiB plus size and mtime — never a whole-file digest,
    because materializing a multi-gigabyte capture must not read it twice.

    So #27's pinned trade-off
    (``test_workspace_cachekey.py::TestFingerprint::test_middle_change_does_not_flip``)
    is inherited here with a sharper consequence: an in-place middle edit that
    preserves size, mtime and both sampled blocks is invisible, and if it also
    preserves frame numbering the backfill joins new-field values read from
    the edited capture to old columns read from the original. This test
    documents that, so the limitation cannot be lost silently; closing it
    would need either the whole-file digest #27 refused or a re-projection of
    columns the backfill promises not to rewrite.
    """

    def rewrite_keeping_mtime(self, path: Path, body: bytes) -> None:
        """Replace a capture's bytes and restore its mtime (as #27's suite does)."""
        stamp = path.stat().st_mtime_ns
        path.write_bytes(body)
        os.utime(path, ns=(stamp, stamp))

    def test_middle_edit_is_invisible_to_a_backfill(self, tmp_path: Path) -> None:
        # Comfortably past head + tail, so the middle is unsampled.
        large = 300 * 1024
        body = bytearray(b"\x00" * large)
        body[:16] = b"HEAD" * 4
        body[-16:] = b"TAIL" * 4
        pcap = tmp_path / "big.pcap"
        pcap.write_bytes(bytes(body))
        ws_path = tmp_path / "ws.duckdb"

        first_lines = [
            line("1", "1614597071.5", "10.0.0.1"),
            line("2", "1614597072.25", "10.0.0.2"),
        ]
        run(ws_path, pcap, [IP_SRC], lines=first_lines)
        before = fingerprint_pcap(pcap)

        # Edit the unsampled middle in place, keeping size and mtime.
        body[large // 2 : large // 2 + 3] = b"ZAP"
        self.rewrite_keeping_mtime(pcap, bytes(body))
        # The precondition this test rests on: #27's fingerprint cannot see it.
        assert fingerprint_pcap(pcap) == before

        # A rescan of the edited capture, same frame numbers, values that
        # could only have come from the edited bytes.
        runner, second = run(
            ws_path, pcap, [IP_SRC, TCP_PORT], lines=[line("1", "9999"), line("2", "8888")]
        )
        assert runner.argv is not None

        # Documenting the limitation: this succeeds.
        assert second.outcome == "backfilled"
        with reading(ws_path) as con:
            rows = con.execute(
                "SELECT ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
            ).fetchall()
        # One row, two capture contents: ip_src read from the original bytes,
        # tcp_port from the edited ones, under a cache key that looks valid.
        assert rows == [
            (int(IPv4Address("10.0.0.1")), [9999]),
            (int(IPv4Address("10.0.0.2")), [8888]),
        ]

    def test_a_visible_edit_is_still_refused(self, tmp_path: Path) -> None:
        # The limitation is specific to edits the sample cannot see. An edit
        # that changes size, mtime or a sampled block refuses as it should, so
        # the test above is documenting a narrow blind spot rather than an
        # absent check.
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        body = bytearray(pcap.read_bytes())
        body[0:4] = b"ZAPZ"
        self.rewrite_keeping_mtime(pcap, bytes(body))
        refuse(
            ws_path, pcap, [IP_SRC, TCP_PORT], MaterializationMismatchError, "capture fingerprint"
        )


class TestBackfillAfterNarrowing:
    """A hit followed by a widening request still backfills only what is new."""

    def test_two_backfills_accumulate(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        run(ws_path, pcap, [IP_SRC])
        run(ws_path, pcap, [IP_SRC, TCP_PORT], lines=BACKFILL_ROWS)
        third_lines = [line("1", "10.0.0.9"), line("2", "10.0.0.8"), line("3", "")]
        runner, third = run(ws_path, pcap, [IP_DST], lines=third_lines)
        assert runner.projected() == ["frame.number", "ip.dst"]
        assert third.outcome == "backfilled"
        assert third.cache_key.fields == ("ip.dst", "ip.src", "tcp.port")
        with reading(ws_path) as con:
            assert pkts_columns(con) == [
                "frame_number",
                "frame_time",
                "ip_src",
                "tcp_port",
                "ip_dst",
            ]
            rows = con.execute(
                "SELECT ip_src, tcp_port, ip_dst FROM main.pkts ORDER BY frame_number"
            ).fetchall()
            assert rows == [
                (int(IPv4Address("10.0.0.1")), [51234, 443], int(IPv4Address("10.0.0.9"))),
                (int(IPv4Address("10.0.0.2")), [443, 51234], int(IPv4Address("10.0.0.8"))),
                (None, [], None),
            ]
        # Narrowing back to the first field set is still a plain hit.
        again, fourth = run(ws_path, pcap, [IP_SRC])
        assert again.argv is None
        assert fourth.outcome == "hit"
