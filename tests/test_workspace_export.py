"""Parquet export tests (issue #34).

The Parquet file is the *export* format, never the storage format: these tests
pin what a reader gets back, which columns DuckDB's Parquet writer cannot
represent losslessly (and are therefore exported as exact text), and that the
export never routes a row through Python.
"""

from __future__ import annotations

import os
import stat
import tracemalloc
from collections.abc import Iterator
from ipaddress import IPv6Address
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

import remora.workspace.export as export_module  # noqa: E402
from remora.workspace import Workspace  # noqa: E402
from remora.workspace.errors import WorkspaceError  # noqa: E402
from remora.workspace.export import (  # noqa: E402
    EXPORTABLE_TABLES,
    TEXT_EXPORTED_TYPES,
    export_parquet,
)
from remora.workspace.schema import add_field_column  # noqa: E402
from remora.workspace.types import ColumnSpec, column_spec  # noqa: E402

# Both sides of 2^127, which is where DuckDB's Parquet writer stops being able
# to represent a UHUGEINT: 7fff:… is 2^127-1 and 8000:: is 2^127, and written
# natively they collide on one double.
V6_ZERO = "::"
V6_BELOW = "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
V6_ABOVE = "8000::"
V6_MULTICAST = "ff02::1:2"
V6_MAX = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

SPECS: tuple[ColumnSpec, ...] = (
    column_spec("ip.src", "FT_IPv4"),
    column_spec("tcp.port", "FT_UINT16", True),
    column_spec("ipv6.dst", "FT_IPv6"),
    column_spec("ipv6.addr", "FT_IPv6", True),
    column_spec("http.host", "FT_STRING"),
    column_spec("eth.src", "FT_ETHER"),
    column_spec("frame.time_delta", "FT_RELATIVE_TIME"),
)

# raw tshark occurrences per column, per row, in SPECS order.
ROWS: tuple[tuple[tuple[str, ...], ...], ...] = (
    (
        ("192.168.1.1",),
        ("80", "443"),
        (V6_ZERO,),
        (V6_ZERO, V6_MULTICAST),
        ("example.com",),
        ("aa:bb:cc:dd:ee:ff",),
        ("0.001234",),
    ),
    (
        ("10.0.0.255",),
        ("53",),
        (V6_BELOW,),
        (V6_ABOVE,),
        (),
        ("00:11:22:33:44:55",),
        ("2.500000",),
    ),
    (
        ("255.255.255.255",),
        (),
        (V6_MAX,),
        (),
        ("remora.invalid",),
        (),
        (),
    ),
)


def parquet() -> Any:
    """pyarrow.parquet, or skip: pyarrow is a test-only dependency."""
    return pytest.importorskip("pyarrow.parquet")


def read_table(path: Path) -> Any:
    """Read an exported file back with pyarrow."""
    return parquet().read_table(str(path))


@pytest.fixture
def ws_path(tmp_path: Path) -> Iterator[Path]:
    """A workspace whose ``pkts`` holds one materialization-shaped projection."""
    path = tmp_path / "ws.duckdb"
    with Workspace(path, mode="rw") as ws, ws.write() as con:
        for spec in SPECS:
            add_field_column(con, spec.column_name, spec.sql_type)
        columns = ", ".join(f'"{spec.column_name}"' for spec in SPECS)
        placeholders = ", ".join("?" for _ in range(len(SPECS) + 2))
        con.executemany(
            f"INSERT INTO main.pkts (frame_number, frame_time, {columns}) VALUES ({placeholders})",
            [
                [
                    number,
                    None,
                    *(spec.encode_raw(raw) for spec, raw in zip(SPECS, row, strict=True)),
                ]
                for number, row in enumerate(ROWS, start=1)
            ],
        )
    yield path


@pytest.fixture
def ro_ws(ws_path: Path) -> Iterator[Workspace]:
    """The populated workspace, open read-only."""
    with Workspace(ws_path) as ws:
        yield ws


class TestTableValidation:
    def test_exportable_tables_are_the_closed_set(self) -> None:
        assert EXPORTABLE_TABLES == ("pkts", "streams", "annotations")

    @pytest.mark.parametrize(
        "table",
        [
            "meta.info",
            "main.pkts",
            "PKTS",
            "",
            "pkts; DROP TABLE main.pkts",
            'pkts" ',
            "duckdb_columns()",
        ],
    )
    def test_unknown_table_is_refused(self, ro_ws: Workspace, tmp_path: Path, table: str) -> None:
        with pytest.raises(ValueError, match="pkts"):
            ro_ws.export_parquet(table, tmp_path / "out.parquet")
        assert not (tmp_path / "out.parquet").exists()

    def test_table_name_cannot_inject_sql(self, ws_path: Path, tmp_path: Path) -> None:
        # A table name cannot be a bound parameter, so the whitelist is what
        # blocks injection; the rows must still be there afterwards.
        with Workspace(ws_path) as ws:
            with pytest.raises(ValueError):
                ws.export_parquet("pkts; DELETE FROM main.pkts", tmp_path / "out.parquet")
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM main.pkts").fetchone()
        assert row is not None
        assert row[0] == len(ROWS)


class TestPathQuoting:
    def test_path_containing_a_single_quote_round_trips(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        out = tmp_path / "o'brien pkts.parquet"
        assert ro_ws.export_parquet("pkts", out) == out
        assert out.exists()
        assert read_table(out).num_rows == len(ROWS)

    def test_path_quote_cannot_inject_sql(self, ws_path: Path, tmp_path: Path) -> None:
        # The path is embedded in the COPY statement as a SQL string literal,
        # so a quote in it must escape rather than terminate the literal.
        out = tmp_path / "x'); DELETE FROM main.pkts; --.parquet"
        with Workspace(ws_path) as ws:
            ws.export_parquet("pkts", out)
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM main.pkts").fetchone()
        assert out.exists()
        assert row is not None
        assert row[0] == len(ROWS)

    def test_existing_file_is_overwritten(self, ro_ws: Workspace, tmp_path: Path) -> None:
        out = tmp_path / "pkts.parquet"
        out.write_bytes(b"not parquet")
        ro_ws.export_parquet("pkts", out)
        assert read_table(out).num_rows == len(ROWS)


def assert_still_a_workspace(path: Path) -> None:
    """The workspace file is untouched: not Parquet, and still openable."""
    with open(path, "rb") as handle:
        assert handle.read(4) != b"PAR1"
    with Workspace(path) as ws, ws.read() as con:
        row = con.execute("SELECT count(*) FROM main.pkts").fetchone()
    assert row is not None
    assert row[0] == len(ROWS)


class TestDestinationGuard:
    # COPY overwrites its destination, so an export aimed at the workspace is a
    # deletion. Reproduced before the guard existed: the database file became a
    # 336-byte Parquet file and reopening it raised duckdb's IOException.

    def test_exporting_onto_the_workspace_is_refused(self, ws_path: Path) -> None:
        with Workspace(ws_path) as ws, pytest.raises(WorkspaceError, match="database file itself"):
            ws.export_parquet("pkts", ws_path)
        assert_still_a_workspace(ws_path)

    @pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
    def test_symlink_to_the_workspace_is_refused(self, ws_path: Path, tmp_path: Path) -> None:
        # A pathname comparison misses this; file identity does not.
        alias = tmp_path / "alias.duckdb"
        alias.symlink_to(ws_path)
        with Workspace(ws_path) as ws, pytest.raises(WorkspaceError, match="database file itself"):
            ws.export_parquet("pkts", alias)
        assert alias.is_symlink()
        assert_still_a_workspace(ws_path)

    @pytest.mark.skipif(os.name != "posix", reason="hard links need privileges on Windows")
    def test_hard_link_to_the_workspace_is_refused(self, ws_path: Path, tmp_path: Path) -> None:
        alias = tmp_path / "hardlink.duckdb"
        os.link(ws_path, alias)
        with Workspace(ws_path) as ws, pytest.raises(WorkspaceError, match="database file itself"):
            ws.export_parquet("pkts", alias)
        assert os.stat(alias).st_ino == os.stat(ws_path).st_ino
        assert_still_a_workspace(ws_path)

    @pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
    def test_workspace_opened_through_a_symlink_is_protected_both_ways(
        self, ws_path: Path, tmp_path: Path
    ) -> None:
        # DuckDB reports the resolved path, so the guard checks the resolved
        # form as well as the reported one and catches either spelling.
        alias = tmp_path / "opened-through.duckdb"
        alias.symlink_to(ws_path)
        with Workspace(alias) as ws:
            with pytest.raises(WorkspaceError, match="database file itself"):
                ws.export_parquet("pkts", ws_path)
            with pytest.raises(WorkspaceError, match="database file itself"):
                ws.export_parquet("pkts", alias)
        assert_still_a_workspace(ws_path)

    @pytest.mark.parametrize("preexisting", [False, True], ids=["absent", "present"])
    def test_wal_sidecar_is_refused(self, ws_path: Path, preexisting: bool) -> None:
        # The worst of the four: DuckDB replays a write-ahead log on open, so a
        # log overwritten with Parquet is discarded along with every committed
        # row it still held — and the database then opens without complaint.
        # Reproduced before the guard: 1999 rows became 1, with no error.
        wal = ws_path.with_name(ws_path.name + ".wal")
        if preexisting:
            wal.write_bytes(b"")
        with Workspace(ws_path) as ws, pytest.raises(WorkspaceError, match="write-ahead log"):
            ws.export_parquet("pkts", wal)
        assert_still_a_workspace(ws_path)

    def test_module_function_guards_the_destination_too(self, ro_ws: Workspace) -> None:
        # The guard reads the database file from the catalog, not from a
        # Workspace attribute, so a caller holding their own connection gets it.
        with ro_ws.read() as con, pytest.raises(WorkspaceError, match="database file itself"):
            export_parquet(con, "pkts", ro_ws.path)

    def test_in_memory_connection_has_nothing_to_guard(self, tmp_path: Path) -> None:
        from remora.workspace.schema import create_schema

        con = duckdb.connect(":memory:")
        try:
            create_schema(con)
            out = tmp_path / "memory.parquet"
            assert export_parquet(con, "pkts", out) == out
        finally:
            con.close()
        assert out.exists()

    @pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
    def test_link_planted_after_the_check_cannot_reach_the_workspace(
        self, ws_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The pre-check is check-then-act: COPY opens the path itself, so
        # another process could plant a link at the destination in between.
        # Neutering the check simulates that swap deterministically — no real
        # race needed. The write goes to a temp file and is renamed into place,
        # and a rename replaces the directory entry rather than following the
        # link, so the workspace inode is never opened.
        monkeypatch.setattr(export_module, "_check_destination", lambda target, database: None)
        out = tmp_path / "planted.parquet"
        out.symlink_to(ws_path)
        with Workspace(ws_path) as ws:
            ws.export_parquet("pkts", out)
        assert not out.is_symlink()
        with open(out, "rb") as handle:
            assert handle.read(4) == b"PAR1"
        assert_still_a_workspace(ws_path)

    @pytest.mark.skipif(os.name != "posix", reason="hard links need privileges on Windows")
    def test_hard_link_planted_after_the_check_cannot_reach_the_workspace(
        self, ws_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(export_module, "_check_destination", lambda target, database: None)
        out = tmp_path / "planted-hard.parquet"
        os.link(ws_path, out)
        db_inode = os.stat(ws_path).st_ino
        with Workspace(ws_path) as ws:
            ws.export_parquet("pkts", out)
        assert os.stat(out).st_ino != db_inode
        with open(out, "rb") as handle:
            assert handle.read(4) == b"PAR1"
        assert_still_a_workspace(ws_path)

    def test_export_beside_the_workspace_still_works(self, ws_path: Path) -> None:
        # No false positives: same directory, and a name sharing the database's
        # prefix, are both perfectly legitimate destinations.
        with Workspace(ws_path) as ws:
            beside = ws.export_parquet("pkts", ws_path.with_name("pkts.parquet"))
            prefixed = ws.export_parquet("pkts", ws_path.with_name(ws_path.name + ".parquet"))
        assert read_table(beside).num_rows == len(ROWS)
        assert read_table(prefixed).num_rows == len(ROWS)
        assert_still_a_workspace(ws_path)


class TestAtomicReplace:
    def test_success_leaves_no_temporary_behind(self, ro_ws: Workspace, tmp_path: Path) -> None:
        out = tmp_path / "clean.parquet"
        ro_ws.export_parquet("pkts", out)
        assert sorted(p.name for p in tmp_path.iterdir()) == ["clean.parquet", "ws.duckdb"]

    def test_failed_copy_cleans_up_and_leaves_the_destination(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        # A direct COPY to the destination used to leave a truncated file where
        # a good export had been; writing to a temporary means a failure leaves
        # the previous export exactly as it was, and takes the temporary with it.
        out = tmp_path / "kept.parquet"
        ro_ws.export_parquet("pkts", out)
        good = out.read_bytes()

        class FailingCopy:
            def __init__(self, inner: DuckDBPyConnection) -> None:
                self._inner = inner

            def execute(self, sql: str, parameters: Any = None) -> Any:
                if sql.lstrip().upper().startswith("COPY "):
                    raise RuntimeError("copy failed")
                if parameters is None:
                    return self._inner.execute(sql)
                return self._inner.execute(sql, parameters)

        with ro_ws.read() as con, pytest.raises(RuntimeError, match="copy failed"):
            export_parquet(FailingCopy(con), "pkts", out)  # type: ignore[arg-type]
        assert out.read_bytes() == good
        assert sorted(p.name for p in tmp_path.iterdir()) == ["kept.parquet", "ws.duckdb"]

    def test_temp_directory_is_private_and_beside_the_target(self, tmp_path: Path) -> None:
        # 0700 is the whole point: a temp *file* only has an unpredictable
        # name, which stops protecting the moment the name is in the directory
        # listing and DuckDB reopens it by name. Beside the target, so the
        # rename out of it stays on one filesystem.
        target = tmp_path / "out.parquet"
        first = export_module._make_temp_dir(target)
        second = export_module._make_temp_dir(target)
        try:
            assert stat.S_IMODE(os.stat(first).st_mode) == 0o700
            assert first.is_dir()
            assert first != second
            assert first.parent == tmp_path
        finally:
            first.rmdir()
            second.rmdir()

    def test_copy_writes_inside_a_private_directory(self, ro_ws: Workspace, tmp_path: Path) -> None:
        # Checked while the COPY is running, since the directory is gone by the
        # time the export returns.
        seen: list[tuple[Path, int]] = []

        class Watcher:
            def __init__(self, inner: DuckDBPyConnection) -> None:
                self._inner = inner

            def execute(self, sql: str, parameters: Any = None) -> Any:
                if sql.lstrip().upper().startswith("COPY "):
                    written = Path(sql.rsplit(" TO '", 1)[1].split("'", 1)[0])
                    seen.append((written.parent, stat.S_IMODE(os.stat(written.parent).st_mode)))
                if parameters is None:
                    return self._inner.execute(sql)
                return self._inner.execute(sql, parameters)

        out = tmp_path / "watched.parquet"
        with ro_ws.read() as con:
            export_parquet(Watcher(con), "pkts", out)  # type: ignore[arg-type]
        assert len(seen) == 1
        directory, mode = seen[0]
        assert mode == 0o700
        assert directory != tmp_path
        assert directory.parent == tmp_path
        assert not directory.exists()
        assert read_table(out).num_rows == len(ROWS)

    def test_missing_destination_directory_raises_oserror(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        with pytest.raises(OSError):
            ro_ws.export_parquet("pkts", tmp_path / "absent" / "out.parquet")

    def test_copy_never_names_the_destination(self, ro_ws: Workspace, tmp_path: Path) -> None:
        # The discriminating test for the whole scheme: whatever DuckDB does
        # with a link at the destination is irrelevant if COPY never opens the
        # destination. Reverting to a direct write fails here on any platform.
        statements: list[str] = []

        class Recorder:
            def __init__(self, inner: DuckDBPyConnection) -> None:
                self._inner = inner

            def execute(self, sql: str, parameters: Any = None) -> Any:
                statements.append(sql)
                if parameters is None:
                    return self._inner.execute(sql)
                return self._inner.execute(sql, parameters)

        out = tmp_path / "recorded.parquet"
        with ro_ws.read() as con:
            export_parquet(Recorder(con), "pkts", out)  # type: ignore[arg-type]
        copies = [sql for sql in statements if sql.lstrip().upper().startswith("COPY ")]
        assert len(copies) == 1
        assert f"TO '{out}'" not in copies[0]
        assert f"/{export_module._TEMP_FILE_NAME}'" in copies[0]
        assert out.exists()


class TestSchemaMapping:
    def test_pkts_schema_matches_the_workspace_columns(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        pa = pytest.importorskip("pyarrow")
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        schema = read_table(out).schema
        assert schema.names == [
            "frame_number",
            "frame_time",
            "ip_src",
            "tcp_port",
            "ipv6_dst",
            "ipv6_addr",
            "http_host",
            "eth_src",
            "frame_time_delta",
        ]
        types = dict(zip(schema.names, schema.types, strict=True))
        # The frozen mapping, column type by column type.
        assert types["frame_number"] == pa.int64()  # BIGINT
        assert types["frame_time"] == pa.timestamp("us")  # TIMESTAMP
        assert types["ip_src"] == pa.uint32()  # UINTEGER, an unsigned IPv4
        assert types["tcp_port"] == pa.list_(pa.uint16())  # USMALLINT[] stays list<T>
        assert types["ipv6_dst"] == pa.string()  # UHUGEINT, exported as decimal text
        assert types["ipv6_addr"] == pa.list_(pa.string())  # UHUGEINT[] -> list<string>
        assert types["http_host"] == pa.string()  # VARCHAR
        assert types["eth_src"] == pa.binary()  # BLOB
        assert types["frame_time_delta"] == pa.string()  # INTERVAL, exported as text

    def test_text_exported_types_are_the_lossy_ones(self) -> None:
        assert set(TEXT_EXPORTED_TYPES) == {"HUGEINT", "UHUGEINT", "INTERVAL"}


class TestValues:
    def test_uint_ip_values_survive(self, ro_ws: Workspace, tmp_path: Path) -> None:
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        table = read_table(out)
        assert table.column("ip_src").to_pylist() == [
            3232235777,  # 192.168.1.1
            167772415,  # 10.0.0.255
            4294967295,  # 255.255.255.255
        ]

    def test_ipv6_values_are_exact_both_sides_of_2_127(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        # The hazard types.py documents for the Arrow path is *worse* on the
        # Parquet path: DuckDB writes UHUGEINT as a double, so 2^127-1 and
        # 2^127 land on the same value. Exact decimal text is what makes these
        # distinguishable at all.
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        table = read_table(out)
        assert table.column("ipv6_dst").to_pylist() == [
            str(int(IPv6Address(V6_ZERO))),
            str(int(IPv6Address(V6_BELOW))),
            str(int(IPv6Address(V6_MAX))),
        ]
        assert table.column("ipv6_addr").to_pylist() == [
            [str(int(IPv6Address(V6_ZERO))), str(int(IPv6Address(V6_MULTICAST)))],
            [str(int(IPv6Address(V6_ABOVE)))],
            [],
        ]
        # Re-readable as the addresses they came from.
        below, above = table.column("ipv6_dst")[1].as_py(), table.column("ipv6_addr")[1][0].as_py()
        assert IPv6Address(int(below)) == IPv6Address(V6_BELOW)
        assert IPv6Address(int(above)) == IPv6Address(V6_ABOVE)
        assert int(below) + 1 == int(above)

    def test_native_uhugeint_export_would_collide(self, ro_ws: Workspace, tmp_path: Path) -> None:
        # Why the cast exists, pinned rather than asserted in prose: writing
        # the UHUGEINT column as DuckDB would natively makes 2^127-1 and 2^127
        # indistinguishable doubles.
        out = tmp_path / "native.parquet"
        with ro_ws.read() as con:
            con.execute(f"COPY (SELECT ipv6_dst FROM main.pkts) TO '{out}' (FORMAT PARQUET)")
        native = read_table(out).column("ipv6_dst").to_pylist()
        assert native[1] == float(int(IPv6Address(V6_BELOW)))
        assert native[1] == float(int(IPv6Address(V6_ABOVE)))

    def test_list_and_scalar_absence_survive(self, ro_ws: Workspace, tmp_path: Path) -> None:
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        table = read_table(out)
        assert table.column("tcp_port").to_pylist() == [[80, 443], [53], []]
        assert table.column("http_host").to_pylist() == ["example.com", None, "remora.invalid"]
        assert table.column("eth_src").to_pylist() == [
            b"\xaa\xbb\xcc\xdd\xee\xff",
            b"\x00\x11\x22\x33\x44\x55",
            None,
        ]

    def test_interval_keeps_microsecond_precision(self, ro_ws: Workspace, tmp_path: Path) -> None:
        # Parquet's own INTERVAL logical type is millisecond-resolution, so a
        # native write truncates 1234us to 1000us; text does not.
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        assert read_table(out).column("frame_time_delta").to_pylist() == [
            "00:00:00.001234",
            "00:00:02.5",
            None,
        ]

    def test_exported_file_reloads_into_duckdb(self, ro_ws: Workspace, tmp_path: Path) -> None:
        out = tmp_path / "pkts.parquet"
        ro_ws.export_parquet("pkts", out)
        con = duckdb.connect(":memory:")
        try:
            rows = con.execute(
                "SELECT CAST(ipv6_dst AS UHUGEINT), CAST(frame_time_delta AS INTERVAL) "
                "FROM read_parquet(?) ORDER BY frame_number",
                [str(out)],
            ).fetchall()
        finally:
            con.close()
        assert rows[1][0] == int(IPv6Address(V6_BELOW))
        assert rows[0][1].microseconds == 1234


class TestModes:
    def test_export_works_in_ro_mode(self, ws_path: Path, tmp_path: Path) -> None:
        out = tmp_path / "ro.parquet"
        with Workspace(ws_path) as ws:
            assert ws.mode == "ro"
            ws.export_parquet("pkts", out)
        assert read_table(out).num_rows == len(ROWS)

    def test_export_works_in_rw_mode(self, ws_path: Path, tmp_path: Path) -> None:
        out = tmp_path / "rw.parquet"
        with Workspace(ws_path, mode="rw") as ws:
            ws.export_parquet("pkts", out)
        assert read_table(out).num_rows == len(ROWS)

    def test_export_needs_an_open_workspace(self, ws_path: Path, tmp_path: Path) -> None:
        with pytest.raises(WorkspaceError, match="not open"):
            Workspace(ws_path).export_parquet("pkts", tmp_path / "out.parquet")


class TestEmptyTables:
    @pytest.mark.parametrize(
        ("table", "columns"),
        [
            (
                "streams",
                [
                    "stream_id",
                    "protocol",
                    "src_addr",
                    "src_port",
                    "dst_addr",
                    "dst_port",
                    "first_frame",
                    "last_frame",
                    "pkt_count",
                    "byte_count",
                    "first_time",
                    "last_time",
                ],
            ),
            (
                "annotations",
                [
                    "annotation_id",
                    "scope",
                    "target_id",
                    "protocol",
                    "key",
                    "value",
                    "created_at",
                ],
            ),
        ],
    )
    def test_empty_table_exports_with_its_schema(
        self, ro_ws: Workspace, tmp_path: Path, table: str, columns: list[str]
    ) -> None:
        out = tmp_path / f"{table}.parquet"
        ro_ws.export_parquet(table, out)
        exported = read_table(out)
        assert exported.num_rows == 0
        assert exported.schema.names == columns

    def test_annotations_export_carries_rows(self, ws_path: Path, tmp_path: Path) -> None:
        with Workspace(ws_path, mode="rw") as ws:
            ws.add_annotation("packet", 1, "verdict", "retransmission storm")
            out = tmp_path / "annotations.parquet"
            ws.export_parquet("annotations", out)
        table = read_table(out)
        assert table.column("key").to_pylist() == ["verdict"]
        assert table.column("value").to_pylist() == ["retransmission storm"]


class TestStreaming:
    def test_only_statement_touching_the_table_is_one_copy(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        # The primary streaming assertion is the implementation's *shape*: the
        # export must be one COPY TO statement that DuckDB executes end to end,
        # with no fetch of the table's rows into Python. A recording proxy makes
        # that checkable — the only statement naming the table is the COPY, and
        # nothing fetches from it.
        statements: list[str] = []

        class Recorder:
            def __init__(self, inner: DuckDBPyConnection) -> None:
                self._inner = inner

            def execute(self, sql: str, parameters: Any = None) -> Any:
                statements.append(sql)
                return (
                    self._inner.execute(sql)
                    if parameters is None
                    else (self._inner.execute(sql, parameters))
                )

        with ro_ws.read() as con:
            export_parquet(Recorder(con), "pkts", tmp_path / "spy.parquet")  # type: ignore[arg-type]
        touching = [sql for sql in statements if "pkts" in sql and "duckdb_columns" not in sql]
        assert len(touching) == 1
        assert touching[0].lstrip().upper().startswith("COPY ")
        assert "FORMAT PARQUET" in touching[0]

    @pytest.mark.slow
    def test_large_table_streams_without_materializing(self, ws_path: Path, tmp_path: Path) -> None:
        # Rows are generated inside DuckDB (range(), not a Python loop) so the
        # only thing under test is the export. tracemalloc measures the *Python*
        # heap, which is exactly the claim: no full-table materialization into
        # Python memory. DuckDB's own buffers are C++ and deliberately not
        # counted.
        n = 1_000_000
        with Workspace(ws_path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO main.pkts (frame_number, frame_time, ip_src, tcp_port) "
                    "SELECT i, NULL, i % 4294967295, [i % 65535] FROM range(?) t(i)",
                    [n],
                )
            out = tmp_path / "big.parquet"
            tracemalloc.start()
            try:
                ws.export_parquet("pkts", out)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        assert out.exists()
        # Observed: a few kilobytes, against a multi-megabyte output file. The
        # bound is loose enough for interpreter noise and still orders of
        # magnitude below anything that fetched the rows.
        assert peak < 1024 * 1024, f"export allocated {peak} bytes of Python heap"
        con = duckdb.connect(":memory:")
        try:
            row = con.execute("SELECT count(*) FROM read_parquet(?)", [str(out)]).fetchone()
        finally:
            con.close()
        assert row is not None
        assert row[0] == n + len(ROWS)


class TestModuleFunction:
    def test_module_function_takes_a_caller_supplied_connection(
        self, ro_ws: Workspace, tmp_path: Path
    ) -> None:
        out = tmp_path / "direct.parquet"
        with ro_ws.read() as con:
            assert export_parquet(con, "pkts", out) == out
        assert read_table(out).num_rows == len(ROWS)

    def test_module_function_refuses_unknown_tables(self, ro_ws: Workspace, tmp_path: Path) -> None:
        with ro_ws.read() as con, pytest.raises(ValueError, match="annotations"):
            export_parquet(con, "meta.fields", tmp_path / "out.parquet")
