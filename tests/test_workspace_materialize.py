"""Unit tests for the #31 streaming materialize pipeline (fake runner, real DuckDB)."""

from __future__ import annotations

from contextlib import contextmanager
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

from collections.abc import Iterable, Iterator, Sequence  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from remora.compile.dfilter import UnsupportedExprError, compile_dfilter  # noqa: E402
from remora.fields import FieldRef  # noqa: E402
from remora.reader.fields_reader import OCC_SEP, UNIT_SEP  # noqa: E402
from remora.reader.process import TsharkError, TsharkNotFoundError  # noqa: E402
from remora.workspace import (  # noqa: E402
    ColumnNameCollisionError,
    MaterializeResult,
    Workspace,
    WorkspaceError,
    WorkspaceModeError,
    detect_tshark_version,
    materialize_into,
)
from remora.workspace.schema import read_cache_key, read_fields  # noqa: E402

IP_SRC: FieldRef[IPv4Address] = FieldRef("ip.src", "FT_IPv4", False)
TCP_PORT: FieldRef[int] = FieldRef("tcp.port", "FT_UINT16", True)
FRAME_TIME_T: FieldRef[datetime] = FieldRef("frame.time", "FT_ABSOLUTE_TIME", False)
FRAME_NUMBER: FieldRef[int] = FieldRef("frame.number", "FT_FRAMENUM", False)
IPV6_ADDR: FieldRef[IPv6Address] = FieldRef("ipv6.addr", "FT_IPv6", True)


def line(*cols: tuple[str, ...] | str) -> str:
    """Join projected columns with the real separators tshark uses."""
    return UNIT_SEP.join(OCC_SEP.join((c,) if isinstance(c, str) else c) for c in cols)


class FakeRunner:
    """Runner double: records argv, streams canned lines, optionally fails mid-stream.

    ``fail_after`` equal to the line count fails at end of stream instead —
    which is where the real ``TsharkProcess`` raises ``TsharkError`` on a
    nonzero exit — and ``fail_with`` picks the exception raised either way.

    ``lines`` is held as given and iterated lazily, never materialized: that
    is what lets a test drive a large synthetic capture from a generator and
    watch how much of it is resident at each flush. One runner therefore
    consumes its iterable once.
    """

    def __init__(
        self,
        lines: Iterable[str],
        fail_after: int | None = None,
        fail_with: BaseException | None = None,
    ) -> None:
        self._lines = lines
        self._fail_after = fail_after
        self._fail_with = fail_with
        self.argv: list[str] | None = None
        self.pulled = 0

    def __call__(self, argv: Sequence[str]) -> Any:
        self.argv = list(argv)

        @contextmanager
        def ctx() -> Iterator[Iterable[str]]:
            yield self._iter()

        return ctx()

    def _failure(self) -> BaseException:
        if self._fail_with is not None:
            return self._fail_with
        return RuntimeError("mid-stream failure injected by test")

    def _iter(self) -> Iterator[str]:
        produced = 0
        for i, text in enumerate(self._lines):
            if self._fail_after is not None and i >= self._fail_after:
                raise self._failure()
            self.pulled += 1
            produced += 1
            yield text
        # Counted rather than len()'d: the input may be a lazy generator.
        if self._fail_after is not None and self._fail_after >= produced:
            raise self._failure()


class SpyCon:
    """Connection proxy recording, per ``executemany``, its size and input consumed."""

    def __init__(self, con: DuckDBPyConnection, runner: FakeRunner) -> None:
        self._con = con
        self._runner = runner
        self.batches: list[tuple[int, int]] = []

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        return self._con.execute(*args, **kwargs)

    def executemany(self, sql: str, parameters: Any) -> Any:
        self.batches.append((len(parameters), self._runner.pulled))
        return self._con.executemany(sql, parameters)


ROWS = [
    line("1", "1614597071.5", "10.0.0.1", ("51234", "443")),
    line("2", "1614597072.25", "10.0.0.2", ("443", "51234")),
    line("3", "1614597073.0", "", ""),
]


def make_pcap(tmp_path: Path) -> Path:
    """A real (tiny) file for make_cache_key to fingerprint; tshark never runs."""
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\x00" * 128)
    return pcap


def materialized(tmp_path: Path, **kwargs: Any) -> tuple[Path, FakeRunner, MaterializeResult]:
    """Open a fresh rw workspace, materialize ROWS (or kwargs overrides), return handles."""
    runner = FakeRunner(
        kwargs.pop("lines", ROWS),
        fail_after=kwargs.pop("fail_after", None),
        fail_with=kwargs.pop("fail_with", None),
    )
    kwargs.setdefault("fields", [IP_SRC, TCP_PORT])
    pcap = make_pcap(tmp_path)
    ws_path = tmp_path / "ws.duckdb"
    with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
        result = materialize_into(
            con,
            pcap=pcap,
            tshark="tshark",
            tshark_version="4.6.7",
            runner=runner,
            **kwargs,
        )
    return ws_path, runner, result


@contextmanager
def reading(ws_path: Path) -> Iterator[DuckDBPyConnection]:
    """Reopen a workspace read-only and yield its connection."""
    with Workspace(ws_path, mode="ro") as ws, ws.read() as con:
        yield con


def pkts_columns(con: DuckDBPyConnection) -> list[str]:
    """Column names of ``main.pkts``, in ordinal order."""
    rows = con.execute(
        "SELECT column_name FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' ORDER BY column_index"
    ).fetchall()
    return [str(row[0]) for row in rows]


def pkts_column_type(con: DuckDBPyConnection, column: str) -> str:
    """DuckDB type of one ``main.pkts`` column."""
    row = con.execute(
        "SELECT data_type FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' AND column_name = ?",
        [column],
    ).fetchone()
    assert row is not None
    return str(row[0])


def count(con: DuckDBPyConnection, table: str) -> int:
    """Row count of a table, by name."""
    row = con.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


def assert_untouched(ws_path: Path) -> None:
    """The workspace holds nothing but the empty skeleton."""
    with reading(ws_path) as con:
        assert pkts_columns(con) == ["frame_number", "frame_time"]
        assert count(con, "main.pkts") == 0
        assert count(con, "meta.fields") == 0
        assert count(con, "meta.cache_keys") == 0


class TestMaterializeInto:
    """The pipeline's observable behaviour, driven through a fake tshark runner."""

    def test_rows_and_types_land(self, tmp_path: Path) -> None:
        ws_path, _runner, result = materialized(tmp_path)
        assert result.row_count == 3
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 3
            rows = con.execute(
                "SELECT ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
            ).fetchall()
            assert rows == [
                (int(IPv4Address("10.0.0.1")), [51234, 443]),
                (int(IPv4Address("10.0.0.2")), [443, 51234]),
                (None, []),
            ]
            assert pkts_column_type(con, "ip_src") == "UINTEGER"
            assert pkts_column_type(con, "tcp_port") == "USMALLINT[]"
            times = con.execute("SELECT frame_time FROM main.pkts ORDER BY frame_number").fetchall()
            assert times[0][0] == datetime(2021, 3, 1, 11, 11, 11, 500000)
            assert times[2][0] == datetime(2021, 3, 1, 11, 11, 13)

    def test_registry_and_cache_key_written(self, tmp_path: Path) -> None:
        ws_path, runner, result = materialized(tmp_path)
        assert result.row_count == 3
        assert result.dfilter is None
        with reading(ws_path) as con:
            records = read_fields(con)
            assert [record.abbrev for record in records] == ["ip.src", "tcp.port"]
            assert [record.column_name for record in records] == ["ip_src", "tcp_port"]
            assert [record.column_type for record in records] == ["UINTEGER", "USMALLINT[]"]
            assert [record.multi for record in records] == [False, True]
            assert all(record.materialized_at == result.cache_key.created_at for record in records)
            # read_fields orders by abbrev, result.fields keeps request order,
            # so compare by a key rather than relying on this request happening
            # to be abbrev-sorted already.
            assert records == tuple(sorted(result.fields, key=lambda record: record.abbrev))
            stored = read_cache_key(con, result.cache_key.key)
            assert stored == result.cache_key
            # The key covers the *full effective* argv, verbatim: the exact
            # command line that ran, separator options included, since a
            # different -E would dissect the same bytes into different
            # columns. Asserted against what the runner was handed rather
            # than rebuilt here, which would only restate fields_argv.
            assert stored is not None
            assert runner.argv is not None
            assert stored.argv == tuple(runner.argv)
            for option in (f"separator={UNIT_SEP}", f"aggregator={OCC_SEP}", "occurrence=a"):
                assert option in stored.argv

    def test_filter_lands_in_argv_as_dash_y(self, tmp_path: Path) -> None:
        expected = compile_dfilter(TCP_PORT == 443)
        ws_path, runner, result = materialized(tmp_path, filter=TCP_PORT == 443)
        assert result.dfilter == expected
        argv = runner.argv
        assert argv is not None
        assert argv[argv.index("-Y") + 1] == expected
        assert argv[argv.index("-r") + 1] == str(tmp_path / "cap.pcap")
        projected = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-e"]
        assert projected == ["frame.number", "frame.time_epoch", "ip.src", "tcp.port"]
        with reading(ws_path) as con:
            stored = read_cache_key(con, result.cache_key.key)
            assert stored is not None
            assert stored.dfilter == expected

    def test_unpushable_filter_refused_untouched(self, tmp_path: Path) -> None:
        # SIM300: the field ref must be on the left; that is what builds an Expr.
        unpushable = FRAME_TIME_T == datetime(2021, 3, 1, tzinfo=timezone.utc)  # noqa: SIM300
        runner = FakeRunner(ROWS)
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(UnsupportedExprError),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                filter=unpushable,
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        assert runner.argv is None
        assert_untouched(ws_path)

    def test_midstream_failure_rolls_back_everything(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="mid-stream failure"):
            materialized(tmp_path, fail_after=2, batch_size=1)
        assert_untouched(tmp_path / "ws.duckdb")

    def test_scalar_multi_occurrence_rolls_back(self, tmp_path: Path) -> None:
        bad = [line("1", "1614597071.5", ("10.0.0.1", "10.0.0.2"), "443")]
        with pytest.raises(ValueError, match="declared scalar but occurred 2 times"):
            materialized(tmp_path, lines=bad)
        assert_untouched(tmp_path / "ws.duckdb")

    def test_batching_is_bounded_and_streaming(self, tmp_path: Path) -> None:
        lines = [line(str(n), f"16145970{70 + n}.0", "10.0.0.1", "443") for n in range(1, 11)]
        runner = FakeRunner(lines)
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            spy = SpyCon(con, runner)
            result = materialize_into(
                cast("DuckDBPyConnection", spy),
                pcap=pcap,
                fields=[IP_SRC, TCP_PORT],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
                batch_size=4,
            )
            recorded = list(spy.batches)
        assert result.row_count == 10
        assert result.batch_count == 3
        assert [size for size, _ in recorded] == [4, 4, 2]
        assert recorded[0][1] == 4
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 10

    def test_large_input_bounded_by_batch_size(self, tmp_path: Path) -> None:
        # #31's acceptance criterion: a synthetic large input is written with
        # at most one batch resident. The lines come from a generator, so the
        # only way 10_000 of them can be resident is if the pipeline pulls
        # them all before flushing — which is exactly what the residency
        # assertion below rules out. fields=[] keeps the row two skeleton
        # columns wide, so this measures streaming, not DuckDB throughput.
        total = 10_000
        batch_size = 1000
        runner = FakeRunner(line(str(n), f"1614597071.{n % 10}") for n in range(1, total + 1))
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with Workspace(ws_path, mode="rw") as ws, ws.write() as con:
            spy = SpyCon(con, runner)
            result = materialize_into(
                cast("DuckDBPyConnection", spy),
                pcap=pcap,
                fields=[],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
                batch_size=batch_size,
            )
            recorded = list(spy.batches)
        assert result.row_count == total
        assert result.batch_count == total // batch_size
        flushed = 0
        for size, pulled in recorded:
            assert size <= batch_size
            # pulled counts lines taken from the generator so far; flushed
            # counts the rows already written. The difference is how much of
            # the input is still held in memory at this flush.
            assert pulled - flushed <= batch_size
            flushed += size
        assert flushed == total
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == total

    def test_ipv6_multi_mixed_magnitude_binds(self, tmp_path: Path) -> None:
        lines = [line("1", "1614597071.5", ("::", "ff02::1:2"))]
        ws_path, _runner, result = materialized(tmp_path, lines=lines, fields=[IPV6_ADDR])
        assert result.row_count == 1
        with reading(ws_path) as con:
            row = con.execute("SELECT ipv6_addr FROM main.pkts").fetchone()
            assert row is not None
            assert row[0] == [0, int(IPv6Address("ff02::1:2"))]
            assert pkts_column_type(con, "ipv6_addr") == "UHUGEINT[]"

    def test_skeleton_field_requests_are_satisfied_by_row_key(self, tmp_path: Path) -> None:
        lines = [line("1", "1614597071.5", "10.0.0.1")]
        ws_path, runner, result = materialized(tmp_path, lines=lines, fields=[FRAME_NUMBER, IP_SRC])
        assert result.cache_key.fields == ("frame.number", "ip.src")
        argv = runner.argv
        assert argv is not None
        projected = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-e"]
        assert projected == ["frame.number", "frame.time_epoch", "ip.src"]
        with reading(ws_path) as con:
            assert [record.abbrev for record in read_fields(con)] == ["ip.src"]
            assert pkts_columns(con) == ["frame_number", "frame_time", "ip_src"]
            row = con.execute("SELECT frame_number FROM main.pkts").fetchone()
            assert row is not None
            assert row[0] == 1

    def test_collision_refused(self, tmp_path: Path) -> None:
        runner = FakeRunner(ROWS)
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(ColumnNameCollisionError, match="tcp_port"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[TCP_PORT, FieldRef("tcp_port", "FT_UINT16", False)],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        assert runner.argv is None
        assert_untouched(ws_path)

    def test_second_materialization_refused(self, tmp_path: Path) -> None:
        ws_path, _runner, first = materialized(tmp_path)
        again = FakeRunner(ROWS)
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match="#32"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=tmp_path / "cap.pcap",
                fields=[IP_SRC],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=again,
            )
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 3
            assert read_cache_key(con, first.cache_key.key) == first.cache_key

    def test_zero_row_first_run_still_refuses_a_second(self, tmp_path: Path) -> None:
        # The hole the three-table probe closes: fields=() plus a filter that
        # matches nothing writes no rows and registers no fields, so a refusal
        # keyed on pkts and meta.fields alone would admit a second run and
        # leave this key describing rows it never produced.
        ws_path, _runner, first = materialized(
            tmp_path, lines=[], fields=[], filter=TCP_PORT == 443
        )
        assert first.row_count == 0
        assert first.fields == ()
        again = FakeRunner(ROWS)
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match="0 pkts rows, 0 registered fields, 1 cache keys"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=tmp_path / "cap.pcap",
                fields=[IP_SRC],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=again,
            )
        assert again.argv is None
        with reading(ws_path) as con:
            assert count(con, "meta.cache_keys") == 1
            assert read_cache_key(con, first.cache_key.key) == first.cache_key

    def test_tshark_error_propagates_and_rolls_back(self, tmp_path: Path) -> None:
        # A nonzero tshark exit reaches this pipeline as TsharkError from the
        # line iterator at end of stream, inside the caller's transaction.
        with pytest.raises(TsharkError, match="exited with code 2"):
            materialized(
                tmp_path,
                fail_after=len(ROWS),
                fail_with=TsharkError("tshark exited with code 2"),
                batch_size=1,
            )
        assert_untouched(tmp_path / "ws.duckdb")

    def test_field_claiming_skeleton_column_refused(self, tmp_path: Path) -> None:
        # A hostile abbrev whose column name is the row key's. find_collisions
        # cannot see it (it collides with no other abbrev), so add_field_column
        # is what refuses — and that runs before tshark would be built.
        hostile: FieldRef[int] = FieldRef("frame_number", "FT_UINT16", False)
        runner = FakeRunner(ROWS)
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with (
            Workspace(ws_path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match="already the pkts row key"),
            ws.write() as con,
        ):
            materialize_into(
                con,
                pcap=pcap,
                fields=[hostile],
                tshark="tshark",
                tshark_version="4.6.7",
                runner=runner,
            )
        assert runner.argv is None
        assert_untouched(ws_path)

    def test_empty_capture(self, tmp_path: Path) -> None:
        ws_path, _runner, result = materialized(tmp_path, lines=[])
        assert result.row_count == 0
        assert result.batch_count == 0
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 0
            assert [record.abbrev for record in read_fields(con)] == ["ip.src", "tcp.port"]
            assert read_cache_key(con, result.cache_key.key) == result.cache_key

    def test_batch_size_validated(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="batch_size must be at least 1"):
            materialized(tmp_path, batch_size=0)
        assert_untouched(tmp_path / "ws.duckdb")


class TestDetectTsharkVersion:
    """Version probing, which the Workspace method falls back to."""

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        with pytest.raises(TsharkNotFoundError, match="not found or not runnable"):
            detect_tshark_version(str(tmp_path / "no-such-tshark"))

    def test_unrunnable_binary_raises_too(self, tmp_path: Path) -> None:
        # A directory is an OSError other than FileNotFoundError; "pointed at
        # something that is not a runnable tshark" is one problem either way.
        with pytest.raises(TsharkNotFoundError, match="not found or not runnable"):
            detect_tshark_version(str(tmp_path))


class TestWorkspaceMethod:
    """``Workspace.materialize``: one transaction, one lock, promptly released."""

    def test_workspace_method_end_to_end(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        runner = FakeRunner(ROWS)
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as ws:
            result = ws.materialize(pcap, [IP_SRC, TCP_PORT], tshark_version="4.6.7", runner=runner)
            assert isinstance(result, MaterializeResult)
            assert result.row_count == 3
            assert result.dfilter is None
            with ws.read() as con:
                assert count(con, "main.pkts") == 3
                rows = con.execute(
                    "SELECT ip_src, tcp_port FROM main.pkts ORDER BY frame_number"
                ).fetchall()
                assert rows == [
                    (int(IPv4Address("10.0.0.1")), [51234, 443]),
                    (int(IPv4Address("10.0.0.2")), [443, 51234]),
                    (None, []),
                ]
        argv = runner.argv
        assert argv is not None
        assert argv[argv.index("-r") + 1] == str(pcap)

    def test_ro_mode_raises_before_spawning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        with Workspace(ws_path, mode="rw"):
            pass
        runner = FakeRunner(ROWS)
        # Neither subprocess-spawning step may run: the version probe is
        # replaced by a sentinel that records its calls, and no tshark_version
        # is passed, so a detection would show up here.
        detected: list[str] = []

        def spy(tshark: str) -> str:
            detected.append(tshark)
            return "4.6.7"

        monkeypatch.setattr("remora.workspace.workspace.detect_tshark_version", spy)
        with Workspace(ws_path) as ws, pytest.raises(WorkspaceModeError, match="read-only"):
            ws.materialize(pcap, [IP_SRC], runner=runner)
        assert detected == []
        assert runner.argv is None
        assert_untouched(ws_path)

    def test_rw_lock_released_after_materialize(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        runner = FakeRunner(ROWS)
        with Workspace(ws_path, mode="rw") as ws:
            ws.materialize(pcap, [IP_SRC, TCP_PORT], tshark_version="4.6.7", runner=runner)
            # DuckDB refuses a same-process connection whose configuration
            # differs from a live one, so a read-only connect succeeding here
            # proves the write connection was closed.
            probe = duckdb.connect(str(ws_path), read_only=True)
            probe.close()
        with reading(ws_path) as con:
            assert count(con, "main.pkts") == 3

    def test_failed_materialize_releases_lock_too(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        runner = FakeRunner(ROWS, fail_after=1)
        with Workspace(ws_path, mode="rw") as ws:
            with pytest.raises(RuntimeError, match="mid-stream failure"):
                ws.materialize(
                    pcap,
                    [IP_SRC, TCP_PORT],
                    tshark_version="4.6.7",
                    runner=runner,
                    batch_size=1,
                )
            probe = duckdb.connect(str(ws_path), read_only=True)
            probe.close()
        assert_untouched(ws_path)

    def test_explicit_version_skips_detection(self, tmp_path: Path) -> None:
        pcap = make_pcap(tmp_path)
        ws_path = tmp_path / "ws.duckdb"
        runner = FakeRunner(ROWS)
        # A binary that does not exist: detection would raise, so the call
        # succeeding proves the explicit version short-circuited it.
        missing = str(tmp_path / "no-such-tshark")
        with Workspace(ws_path, mode="rw") as ws:
            result = ws.materialize(
                pcap,
                [IP_SRC, TCP_PORT],
                tshark=missing,
                tshark_version="9.9.9",
                runner=runner,
            )
        assert result.cache_key.tshark_version == "9.9.9"
        with reading(ws_path) as con:
            stored = read_cache_key(con, result.cache_key.key)
            assert stored is not None
            assert stored.tshark_version == "9.9.9"
            assert stored.argv[0] == missing
