"""Workspace lifecycle, lock discipline, and compact() tests (issue #28)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from remora.workspace.errors import SchemaVersionError, WorkspaceError, WorkspaceModeError
from remora.workspace.schema import SCHEMA_VERSION
from remora.workspace.workspace import Workspace

duckdb = pytest.importorskip("duckdb")


class TestLifecycle:
    def test_default_mode_is_ro(self, tmp_path: Path) -> None:
        ws = Workspace(tmp_path / "ws.duckdb")
        assert ws.mode == "ro"

    def test_invalid_mode_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="mode"):
            Workspace(tmp_path / "ws.duckdb", mode="rwx")  # type: ignore[arg-type]

    def test_rw_creates_workspace(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        assert path.exists()
        con = duckdb.connect(str(path), read_only=True)
        try:
            row = con.execute("SELECT value FROM meta.info WHERE key = 'schema_version'").fetchone()
            assert row is not None
            assert int(row[0]) == SCHEMA_VERSION
        finally:
            con.close()

    def test_rw_reopens_existing_workspace(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path, mode="rw") as ws:
            assert ws.path == path

    def test_ro_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(WorkspaceError, match="rw"):
            Workspace(tmp_path / "absent.duckdb").open()

    def test_ro_opens_existing_workspace(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path) as ws:
            assert ws.mode == "ro"

    def test_ro_rejects_non_workspace_file(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.duckdb"
        con = duckdb.connect(str(path))
        con.close()
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            Workspace(path).open()

    def test_rw_rejects_newer_schema_version(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        con = duckdb.connect(str(path))
        con.execute("UPDATE meta.info SET value = '999' WHERE key = 'schema_version'")
        con.close()
        with pytest.raises(SchemaVersionError, match="newer"):
            Workspace(path, mode="rw").open()

    def test_double_open_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, pytest.raises(WorkspaceError, match="already open"):
            ws.open()

    def test_reopen_after_close_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        ws = Workspace(path, mode="rw")
        with ws:
            pass
        with pytest.raises(WorkspaceError, match="not open"):  # noqa: SIM117
            with ws.read():
                pass


class TestNoModuleLevelConnection:
    def test_import_does_not_import_duckdb(self) -> None:
        # A module-level connection is impossible without the duckdb module:
        # importing the package in a fresh interpreter must not pull it in.
        code = (
            "import remora.workspace, remora.workspace.workspace, sys; "
            "assert 'duckdb' not in sys.modules, 'duckdb imported at module level'"
        )
        subprocess.run([sys.executable, "-c", code], check=True, timeout=60)

    def test_constructing_workspace_opens_nothing(self, tmp_path: Path) -> None:
        # Constructing (not entering) a Workspace must not touch the file.
        path = tmp_path / "ws.duckdb"
        Workspace(path, mode="rw")
        assert not path.exists()


def _subprocess_read(path: Path) -> subprocess.CompletedProcess[bytes]:
    """Read pkts from another process over a read-only connection."""
    code = (
        "import duckdb, sys; "
        "con = duckdb.connect(sys.argv[1], read_only=True); "
        "print(con.execute('SELECT count(*) FROM pkts').fetchone()[0]); "
        "con.close()"
    )
    return subprocess.run(
        [sys.executable, "-c", code, str(path)],
        check=True,
        capture_output=True,
        timeout=60,
    )


class TestLockDiscipline:
    def test_write_in_ro_mode_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path) as ws:  # noqa: SIM117
            with pytest.raises(WorkspaceModeError, match="mode='rw'"):
                with ws.write():
                    pass

    def test_read_in_ro_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path) as ws:  # noqa: SIM117
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 0

    def test_write_then_read_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1

    def test_write_rolls_back_on_error(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with pytest.raises(RuntimeError, match="boom"):  # noqa: SIM117
                with ws.write() as con:
                    con.execute(
                        "INSERT INTO pkts (frame_number, frame_time) "
                        "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                    )
                    raise RuntimeError("boom")
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 0

    def test_idle_ro_workspace_allows_second_process_read(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path):
            # The held read-only connection takes only a shared lock.
            result = _subprocess_read(path)
            assert result.stdout.strip() == b"0"

    def test_idle_rw_workspace_allows_second_process_read(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            # The write lock was released at the end of write(): another
            # process can read while this Workspace object still exists.
            result = _subprocess_read(path)
            assert result.stdout.strip() == b"1"


class TestCompact:
    @staticmethod
    def _bulk_fill(ws: Workspace, rows: int) -> None:
        with ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "SELECT (hash(range) >> 1)::BIGINT, "
                "TIMESTAMP '2024-01-01 00:00:00' + INTERVAL (range % 86400) SECOND "
                f"FROM range({rows})"
            )

    def test_compact_in_ro_mode_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw"):
            pass
        with Workspace(path) as ws, pytest.raises(WorkspaceModeError, match="mode='rw'"):
            ws.compact()

    def test_compact_reclaims_space_after_delete(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            self._bulk_fill(ws, 2000000)
            size_full = path.stat().st_size
            with ws.write() as con:
                con.execute("DELETE FROM pkts WHERE frame_number % 128 != 0")
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                kept = row[0]
            assert 0 < kept < 100000
            # A scattered delete leaves interior free blocks that a
            # checkpoint cannot truncate, so the file stays large.
            size_after_delete = path.stat().st_size
            assert size_after_delete >= size_full // 2
            ws.compact()
            size_after_compact = path.stat().st_size
            assert size_after_compact < size_after_delete // 2
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == kept

    def test_compact_preserves_data_and_catalog(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            ws.compact()
            with ws.read() as con:
                pkts = con.execute("SELECT frame_number FROM pkts").fetchall()
                version = con.execute(
                    "SELECT value FROM meta.info WHERE key = 'schema_version'"
                ).fetchone()
            assert pkts == [(7,)]
            assert version is not None
            assert int(version[0]) == SCHEMA_VERSION
        # The compacted file is a workspace the ro opener accepts.
        with Workspace(path) as ws, ws.read() as con:
            row = con.execute("SELECT count(*) FROM pkts").fetchone()
            assert row is not None
            assert row[0] == 1

    def test_compact_leaves_no_temp_file(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    def test_interrupted_compact_leaves_original_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )

            def boom(src: object, dst: object) -> None:
                raise OSError("simulated crash before the swap")

            monkeypatch.setattr("remora.workspace.workspace.os.replace", boom)
            with pytest.raises(OSError, match="simulated crash"):
                ws.compact()
            monkeypatch.undo()
            # Original untouched, temp cleaned up.
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    def test_compact_removes_stale_temp_from_earlier_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        stale = tmp_path / "ws.duckdb.compacting"
        stale.write_bytes(b"garbage from an interrupted compact")
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert not stale.exists()
