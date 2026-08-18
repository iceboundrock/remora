"""Workspace lifecycle, lock discipline, and compact() tests (issue #28)."""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

import remora.workspace.workspace as workspace_module
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

    @pytest.mark.parametrize(
        "ddl",
        [
            "CREATE VIEW foreign_view AS SELECT 1",
            "CREATE SEQUENCE foreign_seq",
            "CREATE MACRO foreign_macro() AS 42",
            "CREATE TYPE foreign_type AS ENUM ('x')",
            "CREATE SCHEMA foreign_schema",
        ],
        ids=["view", "sequence", "macro", "type", "schema"],
    )
    def test_rw_rejects_foreign_database_without_tables(self, tmp_path: Path, ddl: str) -> None:
        # A foreign database is not necessarily betrayed by a table: a file
        # holding only a view (the reviewer's reproduction), a sequence, a
        # macro, a type or a schema is foreign all the same, and _is_empty
        # counting only duckdb_tables() used to classify it as fresh, graft
        # the remora schema onto it, and accept it.
        path = tmp_path / "foreign.duckdb"
        con = duckdb.connect(str(path))
        con.execute(ddl)
        con.close()
        with pytest.raises(SchemaVersionError, match="not a remora workspace"):
            Workspace(path, mode="rw").open()
        # Refused means untouched: no remora catalog was created.
        con = duckdb.connect(str(path), read_only=True)
        try:
            row = con.execute(
                "SELECT count(*) FROM duckdb_schemas() "
                "WHERE database_name = current_database() AND schema_name = 'meta'"
            ).fetchone()
            assert row is not None
            assert row[0] == 0
        finally:
            con.close()

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


# Compacts in a child process and parks forever at the swap, temp fully
# written and the source's exclusive lock still held, so the parent can
# SIGKILL it at exactly the point a hard interruption hurts most.
_BLOCK_AT_SWAP = """
import os, sys

def hook(src, dst):
    print("SWAP", flush=True)
    sys.stdin.readline()

os.replace = hook

from remora.workspace import Workspace

ws = Workspace(sys.argv[1], mode="rw")
ws.open()
ws.compact()
"""


# Runs one complete compact in a child process — swapping a new inode into
# the path — and exits. Used to land a foreign swap inside the parent
# compact's claim-to-connect window.
_CHILD_COMPACT = """
import sys
from remora.workspace import Workspace

ws = Workspace(sys.argv[1], mode="rw")
ws.open()
ws.compact()
"""


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
        stale_wal = tmp_path / "ws.duckdb.compacting.wal"
        stale.write_bytes(b"garbage from an interrupted compact")
        stale_wal.write_bytes(b"garbage wal from an interrupted compact")
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert not stale.exists()
        assert not stale_wal.exists()

    def test_compact_swap_holds_exclusive_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_replace = os.replace
            probed: list[bytes] = []

            def probing_replace(src: object, dst: object) -> None:
                # A second-process writer must be locked out at the moment
                # of the swap; otherwise its commit could be overwritten.
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import duckdb, sys; duckdb.connect(sys.argv[1], read_only=False)",
                        str(path),
                    ],
                    capture_output=True,
                    timeout=60,
                )
                assert result.returncode != 0
                assert b"lock" in result.stderr.lower()
                probed.append(result.stderr)
                real_replace(src, dst)  # type: ignore[arg-type]

            monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)
            ws.compact()
            monkeypatch.undo()
            assert len(probed) == 1
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1

    def test_second_process_may_connect_after_swap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_replace = os.replace
            probed: list[str] = []

            def probing_replace(src: object, dst: object) -> None:
                real_replace(src, dst)  # type: ignore[arg-type]
                # The rename, not the return, is the cross-process
                # linearization point: it installs a new inode the old
                # file's lock does not cover, so a second process may
                # connect the instant it lands — safely, its write going
                # into the compacted file, where it must survive. This is
                # the documented contract's outer edge, the mirror of
                # test_compact_swap_holds_exclusive_lock's pre-rename
                # exclusion probe.
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import duckdb, sys; "
                        "con = duckdb.connect(sys.argv[1], read_only=False); "
                        'con.execute("INSERT INTO pkts (frame_number, frame_time) '
                        "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')\"); "
                        "con.close()",
                        str(path),
                    ],
                    capture_output=True,
                    timeout=60,
                )
                assert result.returncode == 0, result.stderr
                probed.append("committed")

            monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)
            ws.compact()
            monkeypatch.undo()
            assert probed == ["committed"]
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts ORDER BY frame_number").fetchall()
            assert rows == [(1,), (2,)]

    def test_compact_refuses_inflight_write(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write(), pytest.raises(WorkspaceError, match="in flight"):
                ws.compact()
            # The guard resets once the write finishes.
            ws.compact()

    def test_write_from_second_instance_during_compact_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_replace = os.replace
            probed: list[str] = []

            def probing_replace(src: object, dst: object) -> None:
                # A second Workspace on the same file shares this process's
                # DuckDB instance, so it never hits the file lock: without
                # process-wide coordination its commit would land between
                # the snapshot and the swap and be discarded.
                with pytest.raises(WorkspaceError, match="compact"), ws2.write() as con:
                    con.execute(
                        "INSERT INTO pkts (frame_number, frame_time) "
                        "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                    )
                probed.append("rejected")
                real_replace(src, dst)  # type: ignore[arg-type]

            monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)
            ws1.compact()
            monkeypatch.undo()
            assert probed == ["rejected"]
            # Once compaction is done the second instance writes normally.
            with ws2.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                )
            with ws1.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts ORDER BY frame_number").fetchall()
            assert rows == [(1,), (2,)]

    def test_write_after_swap_before_compact_end_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_replace = os.replace
            probed: list[str] = []

            def swapping_replace(src: object, dst: object) -> None:
                real_replace(src, dst)  # type: ignore[arg-type]
                # Past the swap the path stats to the *new* inode, so a
                # registry keyed only on the pre-swap identity has no entry
                # for it and admits this writer — which then joins the
                # pre-swap DuckDB instance (its cache keys on the path, and
                # compact's source connection still holds it open) and
                # commits into the file os.replace has already discarded.
                with pytest.raises(WorkspaceError, match="compact"), ws2.write() as con:
                    con.execute(
                        "INSERT INTO pkts (frame_number, frame_time) "
                        "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                    )
                probed.append("rejected")

            monkeypatch.setattr("remora.workspace.workspace.os.replace", swapping_replace)
            ws1.compact()
            monkeypatch.undo()
            assert probed == ["rejected"]
            # Once compact has fully finished the same write goes through.
            with ws2.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                )
            with ws1.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts ORDER BY frame_number").fetchall()
            assert rows == [(1,), (2,)]

    @staticmethod
    def _reject_write_at_swap(
        ws: Workspace, monkeypatch: pytest.MonkeyPatch, probed: list[str]
    ) -> None:
        """Assert ``ws.write()`` is refused at the moment of the swap.

        Installed as the ``os.replace`` hook: at that point the temp is
        written but the source has not been replaced yet, so an alias still
        resolves to compact's inode and the rejection is deterministic.
        """
        real_replace = os.replace

        def probing_replace(src: object, dst: object) -> None:
            with pytest.raises(WorkspaceError, match="compact"), ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                )
            probed.append("rejected")
            real_replace(src, dst)  # type: ignore[arg-type]

        monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)

    def test_write_from_hardlink_alias_during_compact_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = tmp_path / "real.duckdb"
        hard = tmp_path / "hard.duckdb"
        probed: list[str] = []
        with Workspace(real, mode="rw") as ws1:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            os.link(real, hard)
            # One inode, two names: a registry keyed on the pathname files
            # these two Workspaces separately and lets the alias commit
            # between compact's snapshot and its swap, silently discarding
            # the commit. Keying on (st_dev, st_ino) makes them one entry.
            with Workspace(hard, mode="rw") as ws2:
                self._reject_write_at_swap(ws2, monkeypatch, probed)
                ws1.compact()
                monkeypatch.undo()
        assert probed == ["rejected"]
        with Workspace(real) as ws, ws.read() as con:
            rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(1,)]

    def test_write_from_case_alias_during_compact_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = tmp_path / "real.duckdb"
        probed: list[str] = []
        with Workspace(real, mode="rw") as ws1:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            alias = real.with_name("REAL.DUCKDB")
            if not alias.exists():
                pytest.skip("case-sensitive filesystem")
            # os.path.realpath preserves the spelling it was given, so on a
            # case-insensitive filesystem the two spellings of one file used
            # to key differently — the reviewer's reproduction.
            with Workspace(alias, mode="rw") as ws2:
                self._reject_write_at_swap(ws2, monkeypatch, probed)
                ws1.compact()
                monkeypatch.undo()
        assert probed == ["rejected"]
        with Workspace(real) as ws, ws.read() as con:
            rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(1,)]

    def test_second_process_compact_in_claim_to_connect_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_connect = workspace_module._connect
            swapped: list[str] = []

            def delayed_connect(path_: str, *, read_only: bool) -> Any:
                # The first connect is compact's source connect: run an
                # entire child-process compact inside the gap between the
                # registry claim and this connect, so the path now stats to
                # a new inode the claim does not cover. Without
                # revalidation under the held lock the local compact would
                # keep its flag on the dead inode, admit a same-process
                # writer keyed on the live one, and swap its commit away.
                if not swapped:
                    swapped.append("swapped")
                    subprocess.run(
                        [sys.executable, "-c", _CHILD_COMPACT, str(path)],
                        check=True,
                        capture_output=True,
                        timeout=120,
                    )
                return real_connect(path_, read_only=read_only)

            monkeypatch.setattr(workspace_module, "_connect", delayed_connect)
            probed: list[str] = []
            self._reject_write_at_swap(ws2, monkeypatch, probed)
            ws1.compact()
            monkeypatch.undo()
            assert swapped == ["swapped"]
            assert probed == ["rejected"]
            with ws2.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                )
            with ws1.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts ORDER BY frame_number").fetchall()
            assert rows == [(1,), (2,)]

    def test_write_from_thread_during_compact_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            with ws1.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (1, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_replace = os.replace
            outcome: list[BaseException | None] = []

            def attempt_write() -> None:
                try:
                    with ws2.write() as con:
                        con.execute(
                            "INSERT INTO pkts (frame_number, frame_time) "
                            "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                        )
                except BaseException as exc:
                    outcome.append(exc)
                else:
                    outcome.append(None)

            def probing_replace(src: object, dst: object) -> None:
                # The registry guards threads, not just Workspace objects:
                # a writer on another thread must be refused for compact's
                # whole duration exactly as a second process is.
                thread = threading.Thread(target=attempt_write)
                thread.start()
                thread.join(timeout=60)
                assert not thread.is_alive()
                real_replace(src, dst)  # type: ignore[arg-type]

            monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)
            ws1.compact()
            monkeypatch.undo()
            assert len(outcome) == 1
            failure = outcome[0]
            assert isinstance(failure, WorkspaceError)
            assert "compact" in str(failure)
            with ws1.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(1,)]

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
    def test_compact_preserves_permission_bits(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            os.chmod(path, 0o640)
            ws.compact()
            # The temp is a fresh file with umask defaults; without copying
            # the source's mode the swap would widen 0o640 to 0o644.
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]

    def test_compact_refuses_second_instance_inflight_write(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            with ws2.write(), pytest.raises(WorkspaceError, match="in flight"):
                ws1.compact()
            # The registry entry clears when the other instance's write ends.
            ws1.compact()

    def test_concurrent_compact_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws1, Workspace(path, mode="rw") as ws2:
            real_replace = os.replace
            probed: list[str] = []

            def probing_replace(src: object, dst: object) -> None:
                with pytest.raises(WorkspaceError, match="already in progress"):
                    ws2.compact()
                probed.append("rejected")
                real_replace(src, dst)  # type: ignore[arg-type]

            monkeypatch.setattr("remora.workspace.workspace.os.replace", probing_replace)
            ws1.compact()
            monkeypatch.undo()
            assert probed == ["rejected"]
            # Both instances can compact again, one after the other.
            ws2.compact()

    def test_lock_conflicted_compact_modifies_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        decoy = tmp_path / "ws.duckdb.compacting"
        decoy_wal = tmp_path / "ws.duckdb.compacting.wal"
        sentinel = b"other compaction in flight"
        sentinel_wal = b"other compaction wal in flight"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            # Stand in for another process's in-flight compaction.
            decoy.write_bytes(sentinel)
            decoy_wal.write_bytes(sentinel_wal)
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import duckdb, sys; "
                    "con = duckdb.connect(sys.argv[1], read_only=False); "
                    "print('READY', flush=True); "
                    "sys.stdin.readline(); "
                    "con.close()",
                    str(path),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert holder.stdout is not None
                assert holder.stdout.readline().strip() == "READY"
                with pytest.raises(WorkspaceError, match="sole access"):
                    ws.compact()
                # The connect failed, so cleanup never ran: the other
                # process's temp files are byte-for-byte untouched.
                assert decoy.read_bytes() == sentinel
                assert decoy_wal.read_bytes() == sentinel_wal
            finally:
                assert holder.stdin is not None
                try:
                    holder.stdin.write("done\n")
                    holder.stdin.flush()
                    holder.stdin.close()
                except OSError:
                    pass
                try:
                    holder.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=30)
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
            # With the lock free, compaction runs and reclaims the debris.
            ws.compact()
        assert not decoy.exists()
        assert not decoy_wal.exists()

    def test_windows_swap_failure_is_wrapped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )

            def denied(src: object, dst: object) -> None:
                # What a Windows rename over a file this process holds open
                # raises; POSIX-first is tracked in #85.
                raise PermissionError("Access is denied")

            monkeypatch.setattr("remora.workspace.workspace.os.replace", denied)
            with pytest.raises(WorkspaceError, match=r"#85"):
                ws.compact()
            monkeypatch.undo()
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    def test_copy_stage_failure_leaves_original_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            real_connect = workspace_module._connect

            class _CopyBomb:
                def __init__(self, real: Any) -> None:
                    self._real = real

                def execute(self, sql: str, *args: object) -> object:
                    if sql.startswith("COPY FROM DATABASE"):
                        raise RuntimeError("simulated crash during copy")
                    return self._real.execute(sql, *args)

                def close(self) -> None:
                    self._real.close()

            def bombed_connect(path_: str, *, read_only: bool) -> Any:
                return _CopyBomb(real_connect(path_, read_only=read_only))

            monkeypatch.setattr(workspace_module, "_connect", bombed_connect)
            with pytest.raises(RuntimeError, match="simulated crash during copy"):
                ws.compact()
            monkeypatch.undo()
            leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
            assert leftovers == []
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
            ws.compact()

    def test_compact_through_symlink_preserves_alias(self, tmp_path: Path) -> None:
        real = tmp_path / "real.duckdb"
        alias = tmp_path / "alias.duckdb"
        with Workspace(real, mode="rw") as ws:  # noqa: SIM117
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        os.symlink(real, alias)
        with Workspace(alias, mode="rw") as ws:
            ws.compact()
            # Compaction happened at the resolved target, so the alias is
            # still a symlink to it rather than an independent regular file
            # left over from an os.replace onto the link itself.
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
        assert alias.is_symlink()
        assert os.readlink(alias) == str(real)
        assert real.exists()
        assert not real.is_symlink()
        leftovers = sorted(
            p.name for p in tmp_path.iterdir() if p.name not in {real.name, alias.name}
        )
        assert leftovers == []

    def test_compact_with_ro_instance_open_raises_workspace_error(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as seed:  # noqa: SIM117
            with seed.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        # The rw instance opens first: it holds no connection between
        # operations, whereas the ro instance holds one for its lifetime and
        # DuckDB refuses a same-process connection with a different config.
        rw = Workspace(path, mode="rw").open()
        try:
            reader = Workspace(path).open()
            try:
                with pytest.raises(WorkspaceError, match="sole access"):
                    rw.compact()
            finally:
                reader.close()
            # With the shared instance gone, compaction takes the lock.
            rw.compact()
            with rw.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
        finally:
            rw.close()

    def test_hard_killed_compact_leaves_original_and_next_compact_recovers(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ws.duckdb"
        tmp = tmp_path / "ws.duckdb.compacting"
        with Workspace(path, mode="rw") as ws:  # noqa: SIM117
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        proc = subprocess.Popen(
            [sys.executable, "-c", _BLOCK_AT_SWAP, str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            # At this line the temp is fully written and the child still
            # holds the source's exclusive lock: the worst moment to die.
            assert proc.stdout.readline().strip() == "SWAP"
            proc.kill()  # SIGKILL: no cleanup handler runs
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        # The original was never replaced, and the kill left the temp behind.
        assert tmp.exists()
        with Workspace(path) as ws, ws.read() as con:
            rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        with Workspace(path, mode="rw") as ws:
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
        leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name != path.name)
        assert leftovers == []


class TestCoordinationRegistry:
    def test_registry_empty_when_idle(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        assert workspace_module._FILE_STATES == {}
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            with ws.read() as con:
                con.execute("SELECT count(*) FROM pkts").fetchone()
            ws.compact()
        # The registry holds counters and flags only while an operation is
        # running: nothing — least of all a connection — outlives it.
        assert workspace_module._FILE_STATES == {}
        with Workspace(path) as ws, ws.read() as con:
            con.execute("SELECT count(*) FROM pkts").fetchone()
        assert workspace_module._FILE_STATES == {}
