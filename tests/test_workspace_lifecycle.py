"""Workspace lifecycle, lock discipline, and compact() tests (issue #28)."""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import remora.workspace.workspace as workspace_module
from remora.workspace.errors import SchemaVersionError, WorkspaceError, WorkspaceModeError
from remora.workspace.permissions import copy_permissions
from remora.workspace.schema import SCHEMA_VERSION
from remora.workspace.swap import replace_file
from remora.workspace.workspace import Workspace

duckdb = pytest.importorskip("duckdb")


def _stagings(path: Path) -> list[Path]:
    """compact()'s staging directories beside the workspace at ``path`` (#147).

    Their names do not embed the workspace's, so the marker inside says whose
    they are.
    """
    expected = workspace_module._staging_marker(path.name)
    found = []
    for p in path.parent.iterdir():
        if not p.name.startswith("remora-compact-") or p.is_symlink() or not p.is_dir():
            continue
        with contextlib.suppress(OSError):
            if (p / "remora-compact").read_bytes() == expected:
                found.append(p)
    return sorted(found)


def _compact_temp(path: Path) -> Path:
    """The temp database of the one compact staging beside ``path``.

    On POSIX ``compact.duckdb`` inside the private staging directory, on
    Windows the staging directory's sibling ``<staging name>.tmp``.
    """
    (staging,) = _stagings(path)
    return workspace_module._staging_temp(staging)


def _stale_staging(path: Path) -> Path:
    """Leave what a compact of ``path`` killed mid-copy leaves: its marked
    staging directory, the temp and the temp's ``.wal``, and in the Windows
    layout the claim recording the temp."""
    staging = workspace_module._make_staging(path)
    tmp = workspace_module._staging_temp(staging)
    tmp.write_bytes(b"garbage from an interrupted compact")
    tmp.with_name(tmp.name + ".wal").write_bytes(b"garbage wal")
    if workspace_module._TEMP_BESIDE_STAGING:
        workspace_module._claim_temp(staging)
    return staging


def _beside(script: str) -> str:
    """``script`` with compact() using the Windows layout, whatever the platform."""
    line = "import remora.workspace.workspace as workspace_module\n"
    assert line in script
    return script.replace(line, line + "workspace_module._TEMP_BESIDE_STAGING = True\n", 1)


@pytest.fixture
def windows_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run compact() with its temp beside the staging directory, as on Windows."""
    monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)


@pytest.fixture(params=["native", "windows"])
def layout(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Run compact() in this platform's layout and in the Windows one.

    Returns whether the temp is beside the staging directory. A test that
    starts a compact in a subprocess passes its script through
    :func:`_beside` when this is true.
    """
    if request.param == "windows":
        monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)
    return workspace_module._TEMP_BESIDE_STAGING


def _snapshot(root: Path, *, but: str | None = None) -> dict[str, tuple[str, object]]:
    """Everything under ``root`` without following links: kind and content.

    ``but`` leaves out one top-level entry, such as the workspace a compact
    rewrites.
    """
    found: dict[str, tuple[str, object]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for entry in (*dirnames, *filenames):
            p = Path(dirpath) / entry
            rel = p.relative_to(root).as_posix()
            if rel == but:
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                found[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                found[rel] = ("dir", None)
            else:
                found[rel] = ("file", p.read_bytes())
    return found


@contextlib.contextmanager
def _held_without_delete_sharing(path: Path) -> Iterator[None]:
    """Hold ``path`` open on Windows the one way that refuses only a rename over it.

    The handle asks for DELETE access alone and shares read and write but not
    delete. A CRT ``open()`` would not do: it asks for read access, and
    DuckDB opens a read-write database sharing nothing but delete, so the
    workspace's own connect would fail on the CRT handle before compact ever
    reached the swap. DELETE is shared by DuckDB and data access is not
    asked for, so the connect succeeds beside this handle; the missing
    delete sharing then refuses the rename, as a pre-1.5.0 duckdb's own
    handle would.
    """
    if sys.platform != "win32":
        raise NotImplementedError("Windows share modes only")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    delete_access = 0x00010000
    share_read_write = 0x00000001 | 0x00000002  # FILE_SHARE_READ | FILE_SHARE_WRITE
    open_existing = 3
    handle: int = kernel32.CreateFileW(
        str(path), delete_access, share_read_write, None, open_existing, 0x80, None
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


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

    @staticmethod
    def _make_v1_workspace(path: Path) -> None:
        """Write a file shaped like the version 1 layout #33 superseded.

        Built by degrading a current workspace rather than by hand-writing the
        old DDL: nothing outside ``schema.py`` may CREATE a layout name (the
        DDL-invariant rule in ``tests/test_workspace_schema.py``), and ALTER is
        not CREATE. The result is byte-for-byte the shape that mattered — a
        ``streams`` table without #33's endpoint columns, recorded as version 1.
        """
        with Workspace(path, mode="rw"):
            pass
        con = duckdb.connect(str(path))
        try:
            for column in ("src_addr", "src_port", "dst_addr", "dst_port"):
                con.execute(f"ALTER TABLE main.streams DROP COLUMN {column}")
            con.execute("UPDATE meta.info SET value = '1' WHERE key = 'schema_version'")
        finally:
            con.close()

    def test_rw_rejects_a_version_1_workspace(self, tmp_path: Path) -> None:
        # #33 added main.streams' endpoint columns, so SCHEMA_VERSION went to
        # 2. Without the bump a v1 file opened happily (1 == 1) and only blew
        # up later, deep inside build_streams(), as a raw DuckDB binder error
        # about a missing src_addr column: create_schema is IF NOT EXISTS-only
        # and cannot add a column to an existing file. The refusal has to
        # happen at open, naming both versions.
        path = tmp_path / "v1.duckdb"
        self._make_v1_workspace(path)
        with pytest.raises(SchemaVersionError) as excinfo:
            Workspace(path, mode="rw").open()
        message = str(excinfo.value)
        assert "1" in message
        assert str(SCHEMA_VERSION) in message
        assert "older remora" in message
        assert "recreate the workspace" in message

    def test_ro_rejects_a_version_1_workspace(self, tmp_path: Path) -> None:
        path = tmp_path / "v1.duckdb"
        self._make_v1_workspace(path)
        with pytest.raises(SchemaVersionError, match="older remora"):
            Workspace(path).open()

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
import sys

import remora.workspace.workspace as workspace_module

def hook(src, dst):
    print("SWAP", flush=True)
    sys.stdin.readline()

workspace_module.replace_file = hook

from remora.workspace import Workspace

ws = Workspace(sys.argv[1], mode="rw")
ws.open()
ws.compact()
"""


# Compacts in a child process whose permission carry-over fails, so the
# compact fails with its temp created, and parks at the first removal of its
# cleanup, so the parent can probe the lock at that moment.
_FAIL_AND_BLOCK_IN_CLEANUP = """
import sys

import remora.workspace.workspace as workspace_module

real_remove = workspace_module._remove_staging
state = {"failed": False, "parked": False}

def fail(src, dst):
    state["failed"] = True
    raise OSError("simulated failure to carry permissions")

def remove(staging, temp):
    if state["failed"] and not state["parked"]:
        state["parked"] = True
        print("CLEANUP", flush=True)
        sys.stdin.readline()
    real_remove(staging, temp)

workspace_module.copy_permissions = fail
workspace_module._remove_staging = remove

from remora.workspace import Workspace

ws = Workspace(sys.argv[1], mode="rw")
ws.open()
try:
    ws.compact()
except Exception as exc:
    print("RAISED", type(exc).__name__, flush=True)
"""


# Compacts in a child process and parks just after the swap has landed, the
# source connection still open, so the parent can run a compact of its own
# before this one finishes.
_BLOCK_AFTER_SWAP = """
import sys

import remora.workspace.workspace as workspace_module

real_replace = workspace_module.replace_file

def hook(src, dst):
    real_replace(src, dst)
    print("SWAPPED", flush=True)
    sys.stdin.readline()

workspace_module.replace_file = hook

from remora.workspace import Workspace

ws = Workspace(sys.argv[1], mode="rw")
ws.open()
ws.compact()
print("DONE", flush=True)
"""


# Holds the workspace argv[1] open read-write and parks the compact of the
# workspace argv[2] just before its first row is copied, so the parent can
# compact a workspace whose name both of theirs extend.
_HOLD_AND_PARK_COMPACT = """
import sys

import duckdb

import remora.workspace.workspace as workspace_module

real_copy = workspace_module.copy_permissions

def park(src, dst):
    real_copy(src, dst)
    print("PARKED", flush=True)
    sys.stdin.readline()

workspace_module.copy_permissions = park

from remora.workspace import Workspace

held = duckdb.connect(sys.argv[1], read_only=False)
ws = Workspace(sys.argv[2], mode="rw")
ws.open()
ws.compact()
ws.close()
held.close()
print("DONE", flush=True)
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

    @pytest.mark.parametrize("error_type", [OSError, PermissionError])
    def test_interrupted_compact_leaves_original_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[OSError]
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )

            error = error_type("simulated crash before the swap")

            def boom(src: Path, dst: Path) -> None:
                raise error

            monkeypatch.setattr(workspace_module, "replace_file", boom)
            with pytest.raises(error_type, match="simulated crash") as excinfo:
                ws.compact()
            assert excinfo.value is error
            monkeypatch.undo()
            # Original untouched, temp cleaned up.
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
            assert _stagings(path) == []
            ws.compact()  # the refusal must release both identity flags and the connection
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    def test_compact_removes_stale_temp_from_earlier_crash(
        self, tmp_path: Path, layout: bool
    ) -> None:
        # What a compact killed mid-copy leaves: its marked staging
        # directory, the temp and the temp's .wal. All of it goes, except a
        # Windows sibling temp's .wal, which no claim covers (R4-F1): that
        # stays byte for byte, for removal by hand.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        stale = _stale_staging(path)
        tmp = workspace_module._staging_temp(stale)
        wal = tmp.with_name(tmp.name + ".wal")
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert not stale.exists()
        assert not tmp.exists()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        if layout:
            assert leftovers == [wal.name]
            assert wal.read_bytes() == b"garbage wal"
        else:
            assert leftovers == []

    def test_compact_leaves_entries_it_cannot_prove_its_own_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Nothing beside the workspace is removed unless it provably is a
        # staging directory of this workspace's compact (R2-F1): not what
        # sits at an earlier version's fixed scratch names, not a directory
        # at a staging name without the marker, with another workspace's
        # marker, or holding anything a compact does not put there, and not
        # a file at a staging name.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        (tmp_path / "ws.duckdb.compacting").write_bytes(b"someone else's file")
        (tmp_path / "ws.duckdb.compacting.wal").write_bytes(b"someone else's file")
        (tmp_path / "ws.duckdb.compacting.new").mkdir()
        (tmp_path / "ws.duckdb.compacting.new" / "ws.duckdb").write_bytes(b"theirs")
        unmarked = tmp_path / ("remora-compact-" + "1" * 16)
        unmarked.mkdir()
        (unmarked / "compact.duckdb").write_bytes(b"theirs")
        foreign = workspace_module._make_staging(tmp_path / "other.duckdb")
        (foreign / "compact.duckdb").write_bytes(b"theirs")
        crowded = workspace_module._make_staging(path)
        (crowded / "notes.txt").write_bytes(b"put here by hand")
        (tmp_path / ("remora-compact-" + "3" * 16)).write_bytes(b"a file")
        before = _snapshot(tmp_path, but=path.name)

        def boom(src: Path, dst: Path) -> None:
            raise OSError("simulated failure at the swap")

        with Workspace(path, mode="rw") as ws:
            # A failed compact's cleanup removes only its own artifacts ...
            monkeypatch.setattr(workspace_module, "replace_file", boom)
            with pytest.raises(OSError, match="simulated failure"):
                ws.compact()
            monkeypatch.undo()
            assert _snapshot(tmp_path, but=path.name) == before
            # ... and so does a successful one, stale-debris pass included.
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert _snapshot(tmp_path, but=path.name) == before

    def test_staging_name_taken_by_anything_is_skipped_not_reused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The staging name is fresh: when the drawn name is taken, here by
        # someone else's directory, another is drawn and the entry is left
        # alone.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        taken = tmp_path / ("remora-compact-" + "5" * 16)
        taken.mkdir()
        (taken / "compact.duckdb").write_bytes(b"theirs")
        tokens = iter(["5" * 16, "6" * 16])
        monkeypatch.setattr("secrets.token_hex", lambda n: next(tokens))
        before = _snapshot(tmp_path, but=path.name)
        used: list[Path] = []
        real_copy = copy_permissions

        def note(src: Path, dst: Path) -> None:
            used.append(dst)
            real_copy(src, dst)

        monkeypatch.setattr(workspace_module, "copy_permissions", note)
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert [p.name for p in used] == [
            "remora-compact-" + "6" * 16 + ".tmp"
            if workspace_module._TEMP_BESIDE_STAGING
            else "compact.duckdb"
        ]
        assert _snapshot(tmp_path, but=path.name) == before

    @pytest.mark.parametrize("taken_name", [".tmp", ".tmp.wal"])
    @pytest.mark.usefixtures("windows_layout")
    def test_windows_temp_name_taken_is_refused_not_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, taken_name: str
    ) -> None:
        # On Windows the temp is the staging directory's sibling, outside it.
        # Something already at its name or its .wal's is not this compact's,
        # so compact refuses rather than attach it or remove it.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        taken = tmp_path / ("remora-compact-" + "7" * 16 + taken_name)
        taken.write_bytes(b"theirs")
        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                m.setattr("secrets.token_hex", lambda n: "7" * 16)
                with pytest.raises(WorkspaceError, match="did not create"):
                    ws.compact()
            ws.compact()
        assert taken.read_bytes() == b"theirs"
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, taken.name])

    @pytest.mark.parametrize("layout", ["native", "windows"])
    @pytest.mark.parametrize(
        "name", ["remora-compact", "compact.duckdb", "temp-claim", "remora-compact-" + "8" * 16]
    )
    def test_workspace_named_like_compact_staging_compacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, layout: str
    ) -> None:
        # R3-F2: no workspace name can collide with what compact puts in or
        # beside its staging directory, the marker included.
        if layout == "windows":
            monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)
        path = tmp_path / name
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            ws.compact()
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == [name]

    @pytest.mark.skipif(
        sys.platform == "win32", reason="a 251-character name exceeds MAX_PATH under tmp_path"
    )
    @pytest.mark.parametrize("layout", ["native", "windows"])
    def test_workspace_name_at_the_component_limit_compacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
    ) -> None:
        # R3-F3: the longest name a workspace can have is the one whose .wal
        # still fits a 255-byte component. Staging names do not grow with it.
        if layout == "windows":
            monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)
        name = "w" * (255 - len(".wal") - len(".duckdb")) + ".duckdb"
        assert len(os.fsencode(name + ".wal")) == 255
        path = tmp_path / name
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == [name]

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_sibling_never_claimed_is_left_alone(self, tmp_path: Path) -> None:
        # R3-F1: a compact killed after writing its marker but before it
        # checked the temp's name (or between creating the temp there and
        # claiming it) wrote no claim, so whatever is at the sibling names may be anyone's.
        # The marked directory goes; the siblings stay byte for byte.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        stale = workspace_module._make_staging(path)
        tmp = workspace_module._staging_temp(stale)
        tmp.write_bytes(b"someone else's file")
        tmp.with_name(tmp.name + ".wal").write_bytes(b"someone else's wal")
        before = _snapshot(tmp_path, but=path.name)
        del before[stale.name], before[f"{stale.name}/remora-compact"]
        with Workspace(path, mode="rw") as ws:
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert not stale.exists()
        assert _snapshot(tmp_path, but=path.name) == before

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_claim_naming_another_file_leaves_the_siblings_alone(
        self, tmp_path: Path
    ) -> None:
        # R3-F1: a claim covers the very file it recorded, not its name. A
        # regular file now at the name, here one replacing the claimed temp,
        # is not removed, and neither is a .wal beside it.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        stale = _stale_staging(path)
        tmp = workspace_module._staging_temp(stale)
        # Written beside it first, so the new file cannot take a freed inode.
        theirs = tmp_path / "theirs"
        theirs.write_bytes(b"someone else's file")
        os.replace(theirs, tmp)
        before = _snapshot(tmp_path, but=path.name)
        for entry in ("", "/remora-compact", "/temp-claim"):
            del before[stale.name + entry]
        assert workspace_module._stale_temp_files(stale) == ()
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert not stale.exists()
        assert _snapshot(tmp_path, but=path.name) == before

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_layout_post_swap_collision_is_left_alone(self, tmp_path: Path) -> None:
        # R3-F1: a compact killed just after its swap leaves its marked and
        # claimed staging directory, but the claimed temp is the workspace
        # now. Files that then appear at the temp's and its .wal's names are
        # someone else's: the next compact removes the directory and leaves
        # them byte for byte.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        proc = subprocess.Popen(
            [sys.executable, "-c", _beside(_BLOCK_AFTER_SWAP), str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "SWAPPED"
            proc.kill()  # the staging directory is never removed
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        (staging,) = _stagings(path)
        assert sorted(p.name for p in staging.iterdir()) == ["remora-compact", "temp-claim"]
        tmp = staging.with_name(staging.name + ".tmp")
        assert not tmp.exists()
        tmp.write_bytes(b"someone else's file")
        tmp.with_name(tmp.name + ".wal").write_bytes(b"someone else's wal")
        before = _snapshot(tmp_path, but=path.name)
        for entry in ("", "/remora-compact", "/temp-claim"):
            del before[staging.name + entry]
        with Workspace(path, mode="rw") as ws:
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert not staging.exists()
        assert _snapshot(tmp_path, but=path.name) == before

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_layout_kill_at_swap_removes_the_claimed_temp_not_a_file_at_its_wal(
        self, tmp_path: Path
    ) -> None:
        # The other side of R3-F1: the temp a killed compact claimed is still
        # removed. R4-F1: killed after DETACH deleted the temp's .wal, the
        # compact leaves the .wal's name free for anyone; a file created
        # there is not the temp's, claim or no claim, and stays byte for byte.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        proc = subprocess.Popen(
            [sys.executable, "-c", _beside(_BLOCK_AT_SWAP), str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "SWAP"
            proc.kill()
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        (staging,) = _stagings(path)
        tmp = workspace_module._staging_temp(staging)
        assert tmp.is_file()
        assert sorted(p.name for p in staging.iterdir()) == ["remora-compact", "temp-claim"]
        wal = tmp.with_name(tmp.name + ".wal")
        assert not wal.exists()
        wal.write_bytes(b"someone else's file")
        with Workspace(path, mode="rw") as ws:
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, wal.name])
        assert wal.read_bytes() == b"someone else's file"

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_failed_compact_leaves_a_file_at_its_temps_wal_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # R4-F1, in flight: once DETACH has deleted the temp's .wal, a file
        # that appears at its name before the swap fails is not the temp's.
        # The failing compact removes its claimed temp and its staging
        # directory and leaves that file byte for byte.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        monkeypatch.setattr("secrets.token_hex", lambda n: "5" * 16)
        wal = tmp_path / ("remora-compact-" + "5" * 16 + ".tmp.wal")

        def collide_then_fail(src: Path, dst: Path) -> None:
            assert not wal.exists()
            wal.write_bytes(b"someone else's file")
            raise OSError("swap refused")

        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                m.setattr(workspace_module, "replace_file", collide_then_fail)
                with pytest.raises(OSError, match="swap refused"):
                    ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, wal.name])
        assert wal.read_bytes() == b"someone else's file"

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_stale_wal_beside_a_claimed_temp_is_left_alone(self, tmp_path: Path) -> None:
        # R4-F1: a claim covers the temp, not a file at the temp's .wal name,
        # whoever made it. The claimed temp and the staging directory go; the
        # .wal stays for removal by hand.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        stale = _stale_staging(path)
        tmp = workspace_module._staging_temp(stale)
        wal = tmp.with_name(tmp.name + ".wal")
        assert workspace_module._stale_temp_files(stale) == (tmp,)
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, wal.name])
        assert wal.read_bytes() == b"garbage wal"

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_temp_name_taken_after_the_check_is_refused_not_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # R5-F1: a name found free proves nothing. A file another program
        # creates at the temp's name after compact checked it makes the
        # exclusive create fail; compact refuses and leaves the file alone.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        monkeypatch.setattr("secrets.token_hex", lambda n: "6" * 16)
        theirs = tmp_path / ("remora-compact-" + "6" * 16 + ".tmp")
        real_image = workspace_module._empty_database_image

        def collide() -> bytes:
            theirs.write_bytes(b"someone else's file")
            return real_image()

        monkeypatch.setattr(workspace_module, "_empty_database_image", collide)
        with (
            Workspace(path, mode="rw") as ws,
            pytest.raises(WorkspaceError, match="did not create"),
        ):
            ws.compact()
        assert theirs.read_bytes() == b"someone else's file"
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, theirs.name])

    @pytest.mark.parametrize(
        "when", ["SELECT current_database()", "ATTACH", "COPY FROM DATABASE", "DETACH"]
    )
    @pytest.mark.parametrize("theirs_kind", ["file", "database"])
    @pytest.mark.usefixtures("windows_layout")
    def test_windows_temp_replaced_in_flight_is_never_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str, theirs_kind: str
    ) -> None:
        # R5-F1: the temp compact created can be replaced at its name by
        # another program's file before ATTACH, while compact works, or
        # before the swap. Whatever then fails, here a raise at the next
        # statement or compact's own refusal, the failing compact removes
        # only the file it created and claimed: the other file stays byte for
        # byte and is neither attached into, nor swapped in, nor removed.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws, ws.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
            )
        monkeypatch.setattr("secrets.token_hex", lambda n: "7" * 16)
        tmp = tmp_path / ("remora-compact-" + "7" * 16 + ".tmp")
        # Made beside it first, so the replacement cannot take a freed inode.
        theirs = tmp_path / "theirs"
        if theirs_kind == "database":
            with Workspace(theirs, mode="rw") as other, other.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (99, TIMESTAMP '2024-01-01 00:00:00')"
                )
        else:
            theirs.write_bytes(b"someone else's file")
        content = theirs.read_bytes()
        mode = stat.S_IMODE(os.lstat(theirs).st_mode)
        real_connect = workspace_module._connect
        replaced: list[str] = []

        class _Probe:
            def __init__(self, real: Any) -> None:
                self._real = real

            def execute(self, sql: str, *args: object) -> object:
                if sql.startswith(when) and not replaced:
                    if when == "DETACH":
                        result = self._real.execute(sql, *args)
                        replace_file(theirs, tmp)
                        replaced.append(sql)
                        return result
                    # replace_file, not os.replace: at COPY the temp is
                    # attached, and on Windows only a POSIX-semantics
                    # rename can replace a file DuckDB holds open.
                    replace_file(theirs, tmp)
                    replaced.append(sql)
                    if when != "ATTACH":
                        raise RuntimeError("simulated failure after the replacement")
                return self._real.execute(sql, *args)

            def close(self) -> None:
                self._real.close()

        def probed_connect(path_: str, *, read_only: bool) -> Any:
            return _Probe(real_connect(path_, read_only=read_only))

        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                m.setattr(workspace_module, "_connect", probed_connect)
                with pytest.raises(Exception) as excinfo:
                    ws.compact()
            assert replaced
            if when in ("ATTACH", "DETACH") and theirs_kind == "database":
                # Attached or about to be swapped in, it is refused.
                assert isinstance(excinfo.value, WorkspaceError)
                assert "replaced by a file it did not create" in str(excinfo.value)
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        assert tmp.read_bytes() == content
        assert stat.S_IMODE(os.lstat(tmp).st_mode) == mode
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([path.name, tmp.name])

    @pytest.mark.usefixtures("windows_layout")
    def test_windows_failed_attach_removes_the_temp_compact_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The other side of R5-F1: the temp compact created and claimed is
        # its own, so a failure at ATTACH removes it with the staging
        # directory and leaves nothing behind.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            pass
        real_connect = workspace_module._connect
        seen: list[Path] = []

        class _Probe:
            def __init__(self, real: Any) -> None:
                self._real = real

            def execute(self, sql: str, *args: object) -> object:
                if sql.startswith("ATTACH"):
                    (staging,) = _stagings(path)
                    seen.append(workspace_module._staging_temp(staging))
                    assert seen[0].is_file()
                    assert (staging / "temp-claim").is_file()
                    raise RuntimeError("simulated failure at ATTACH")
                return self._real.execute(sql, *args)

            def close(self) -> None:
                self._real.close()

        def probed_connect(path_: str, *, read_only: bool) -> Any:
            return _Probe(real_connect(path_, read_only=read_only))

        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                m.setattr(workspace_module, "_connect", probed_connect)
                with pytest.raises(RuntimeError, match="at ATTACH"):
                    ws.compact()
            ws.compact()
        assert len(seen) == 1
        assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]

    def test_compact_leaves_other_workspaces_at_colliding_names_alone(self, tmp_path: Path) -> None:
        # Workspaces named like an older remora's temp, like the marker, and
        # like a staging directory, one of them open and one mid-compact in
        # another process, are neither removed nor disturbed.
        path = tmp_path / "ws.duckdb"
        others = [
            tmp_path / "ws.duckdb.compacting",
            tmp_path / "remora-compact",
            tmp_path / ("remora-compact-" + "4" * 16),
        ]
        for i, p in enumerate([path, *others]):
            with Workspace(p, mode="rw") as ws, ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    f"VALUES ({i}, TIMESTAMP '2024-01-01 00:00:00')"
                )
        proc = subprocess.Popen(
            [sys.executable, "-c", _HOLD_AND_PARK_COMPACT, str(others[0]), str(others[2])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdin is not None
            # others[0] is open read-write in the child, and others[2]'s
            # compact is parked with its temp in its own staging directory.
            assert proc.stdout.readline().strip() == "PARKED"
            (their_staging,) = _stagings(others[2])
            assert _compact_temp(others[2]).exists()
            with Workspace(path, mode="rw") as ws:
                ws.compact()
                with ws.read() as con:
                    rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(0,)]
            assert _stagings(others[2]) == [their_staging]
            assert _compact_temp(others[2]).exists()
            proc.stdin.write("go\n")
            proc.stdin.close()
            assert proc.stdout.readline().strip() == "DONE"
            assert proc.wait(timeout=60) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        for i, p in enumerate(others, start=1):
            with Workspace(p) as ws, ws.read() as con:
                assert con.execute("SELECT frame_number FROM pkts").fetchall() == [(i,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted(p.name for p in [path, *others])

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
            real_replace = replace_file
            probed: list[bytes] = []

            def probing_replace(src: Path, dst: Path) -> None:
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
                if sys.platform == "win32":
                    # "The process cannot access the file ... File is already open in ..."
                    assert b"already open in" in result.stderr.lower()
                else:
                    assert b"lock" in result.stderr.lower()
                probed.append(result.stderr)
                real_replace(src, dst)

            monkeypatch.setattr(workspace_module, "replace_file", probing_replace)
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
            real_replace = replace_file
            probed: list[str] = []

            def probing_replace(src: Path, dst: Path) -> None:
                real_replace(src, dst)
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

            monkeypatch.setattr(workspace_module, "replace_file", probing_replace)
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
            real_replace = replace_file
            probed: list[str] = []

            def probing_replace(src: Path, dst: Path) -> None:
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
                real_replace(src, dst)

            monkeypatch.setattr(workspace_module, "replace_file", probing_replace)
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
            real_replace = replace_file
            probed: list[str] = []

            def swapping_replace(src: Path, dst: Path) -> None:
                real_replace(src, dst)
                # Past the swap the path stats to the *new* inode, so a
                # registry keyed only on the pre-swap identity has no entry
                # for it and admits this writer — which then joins the
                # pre-swap DuckDB instance (its cache keys on the path, and
                # compact's source connection still holds it open) and
                # commits into the file replace_file has already discarded.
                with pytest.raises(WorkspaceError, match="compact"), ws2.write() as con:
                    con.execute(
                        "INSERT INTO pkts (frame_number, frame_time) "
                        "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                    )
                probed.append("rejected")

            monkeypatch.setattr(workspace_module, "replace_file", swapping_replace)
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

        Installed as the ``replace_file`` hook: at that point the temp is
        written but the source has not been replaced yet, so an alias still
        resolves to compact's inode and the rejection is deterministic.
        """
        real_replace = replace_file

        def probing_replace(src: Path, dst: Path) -> None:
            with pytest.raises(WorkspaceError, match="compact"), ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (2, TIMESTAMP '2024-01-01 00:00:01')"
                )
            probed.append("rejected")
            real_replace(src, dst)

        monkeypatch.setattr(workspace_module, "replace_file", probing_replace)

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
            real_replace = replace_file
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

            def probing_replace(src: Path, dst: Path) -> None:
                # The registry guards threads, not just Workspace objects:
                # a writer on another thread must be refused for compact's
                # whole duration exactly as a second process is.
                thread = threading.Thread(target=attempt_write)
                thread.start()
                thread.join(timeout=60)
                assert not thread.is_alive()
                real_replace(src, dst)

            monkeypatch.setattr(workspace_module, "replace_file", probing_replace)
            ws1.compact()
            monkeypatch.undo()
            assert len(outcome) == 1
            failure = outcome[0]
            assert isinstance(failure, WorkspaceError)
            assert "compact" in str(failure)
            with ws1.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(1,)]

    @pytest.mark.skipif(
        os.name != "posix",
        reason="mode bits are a POSIX concept; Windows has only the read-only attribute",
    )
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
            real_replace = replace_file
            probed: list[str] = []

            def probing_replace(src: Path, dst: Path) -> None:
                with pytest.raises(WorkspaceError, match="already in progress"):
                    ws2.compact()
                probed.append("rejected")
                real_replace(src, dst)

            monkeypatch.setattr(workspace_module, "replace_file", probing_replace)
            ws1.compact()
            monkeypatch.undo()
            assert probed == ["rejected"]
            # Both instances can compact again, one after the other.
            ws2.compact()

    def test_lock_conflicted_compact_modifies_nothing(self, tmp_path: Path, layout: bool) -> None:
        path = tmp_path / "ws.duckdb"
        sentinel = b"other compaction in flight"
        sentinel_wal = b"other compaction wal in flight"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            # Stand in for another process's in-flight compaction.
            staging = workspace_module._make_staging(path)
            decoy = workspace_module._staging_temp(staging)
            decoy_wal = decoy.with_name(decoy.name + ".wal")
            decoy.write_bytes(sentinel)
            decoy_wal.write_bytes(sentinel_wal)
            if layout:
                workspace_module._claim_temp(staging)
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
            # With the lock free, compaction runs and reclaims the debris:
            # all of it on POSIX, where it is inside the private staging
            # directory. In the Windows layout the claimed temp goes but its
            # .wal, which no claim covers, stays byte for byte (R4-F1, R5-F2).
            ws.compact()
        assert not staging.exists()
        assert not decoy.exists()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        if layout:
            assert decoy_wal.read_bytes() == sentinel_wal
            assert leftovers == [decoy_wal.name]
        else:
            assert not decoy_wal.exists()
            assert leftovers == []

    def test_swap_refusal_leaves_original_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )

            def refused(src: Path, dst: Path) -> None:
                # What replace_file raises on Windows for a handle without
                # delete sharing (duckdb < 1.5.0, a scanner) or a volume
                # without POSIX rename semantics; see tests/test_workspace_swap.py.
                raise WorkspaceError("simulated swap refusal")

            monkeypatch.setattr(workspace_module, "replace_file", refused)
            with pytest.raises(WorkspaceError, match="simulated swap refusal"):
                ws.compact()
            monkeypatch.undo()
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
            ws.compact()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    @pytest.mark.skipif(
        sys.platform != "win32", reason="exercises the Windows rename refusal through compact()"
    )
    def test_real_swap_refusal_leaves_original_intact(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            # No monkeypatching: the real POSIX-semantics rename is refused
            # while a handle without delete sharing is open on the workspace.
            with _held_without_delete_sharing(path):  # noqa: SIM117
                with pytest.raises(WorkspaceError, match="delete sharing"):
                    ws.compact()
            assert _stagings(path) == []
            with ws.read() as con:
                row = con.execute("SELECT count(*) FROM pkts").fetchone()
                assert row is not None
                assert row[0] == 1
            ws.compact()  # succeeds once the holder is gone
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
        try:
            os.symlink(real, alias)
        except OSError as exc:  # Windows without Developer Mode / SeCreateSymbolicLinkPrivilege
            pytest.skip(f"cannot create a symlink here: {exc}")
        with Workspace(alias, mode="rw") as ws:
            ws.compact()
            # Compaction happened at the resolved target, so the alias is
            # still a symlink to it rather than an independent regular file
            # left over from renaming the temp onto the link itself.
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
        assert alias.is_symlink()
        if sys.platform == "win32":
            # os.readlink may hand back a \\?\-prefixed path here.
            assert os.path.samefile(alias, real)
        else:
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

    def test_failed_compact_cleans_up_before_releasing_the_lock(self, tmp_path: Path) -> None:
        # A failed compact removes its own temp and staging directory while
        # it still holds the source's exclusive lock (R1-F1), and another
        # process's compact, locked out meanwhile, touches none of it.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
            proc = subprocess.Popen(
                [sys.executable, "-c", _FAIL_AND_BLOCK_IN_CLEANUP, str(path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert proc.stdout is not None
                assert proc.stdin is not None
                # The child's compact has failed after creating its temp and
                # is about to remove it.
                assert proc.stdout.readline().strip() == "CLEANUP"
                (staging,) = _stagings(path)
                assert _compact_temp(path).exists()
                with pytest.raises(WorkspaceError, match="sole access"):
                    ws.compact()
                # Locked out, so this compact touched none of the child's
                # artifacts either.
                assert _stagings(path) == [staging]
                assert _compact_temp(path).exists()
                proc.stdin.write("go\n")
                proc.stdin.close()
                assert proc.stdout.readline().strip() == "RAISED WorkspaceError"
                assert proc.wait(timeout=60) == 0
            finally:
                if proc.poll() is None:
                    proc.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=30)
            leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
            assert leftovers == []
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file locks and renames")
    def test_compact_removes_only_its_own_staging_after_its_swap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: bool
    ) -> None:
        # The swap installs an inode the finishing compact's lock does not
        # cover, so another process's compact may start at once and create
        # its staging directory. The finishing compact must not remove it:
        # here it resumes exactly between the successor's mkdir and its
        # ATTACH, and the successor must still succeed (R1-F1). The
        # successor, holding the new file's lock, may itself remove the
        # finishing compact's staging directory, which by then holds only
        # its marker.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:  # noqa: SIM117
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        script = _beside(_BLOCK_AFTER_SWAP) if layout else _BLOCK_AFTER_SWAP
        proc = subprocess.Popen(
            [sys.executable, "-c", script, str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdin is not None
            assert proc.stdout.readline().strip() == "SWAPPED"
            # The first compact's staging directory, holding only its marker,
            # and in the Windows layout the claim on its swapped-in temp.
            (first,) = _stagings(path)
            assert sorted(p.name for p in first.iterdir()) == (
                ["remora-compact", "temp-claim"] if layout else ["remora-compact"]
            )
            stdin, stdout = proc.stdin, proc.stdout
            finished: list[str] = []
            successor: list[Path] = []

            def finish_first_compact() -> None:
                # The successor has just created its staging directory.
                (mine,) = (p for p in _stagings(path) if p != first)
                successor.append(mine)
                stdin.write("go\n")
                stdin.close()
                finished.append(stdout.readline().strip())
                assert proc.wait(timeout=60) == 0
                assert _stagings(path) == [mine]
                assert _compact_temp(path) == workspace_module._staging_temp(mine)

            real_connect = workspace_module._connect

            class _Probe:
                def __init__(self, real: Any) -> None:
                    self._real = real

                def execute(self, sql: str, *args: object) -> object:
                    if sql.startswith("SELECT current_database()") and not finished:
                        finish_first_compact()
                    return self._real.execute(sql, *args)

                def close(self) -> None:
                    self._real.close()

            def probed_connect(path_: str, *, read_only: bool) -> Any:
                return _Probe(real_connect(path_, read_only=read_only))

            monkeypatch.setattr(workspace_module, "_connect", probed_connect)
            with Workspace(path, mode="rw") as ws:
                ws.compact()
                monkeypatch.undo()
                with ws.read() as con:
                    rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert finished == ["DONE"]
            assert len(successor) == 1
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        assert rows == [(7,)]
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    def test_hard_killed_compact_leaves_original_and_next_compact_recovers(
        self, tmp_path: Path, layout: bool
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:  # noqa: SIM117
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _beside(_BLOCK_AT_SWAP) if layout else _BLOCK_AT_SWAP,
                str(path),
            ],
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
        # The original was never replaced, and the kill left the finished
        # temp behind, with the workspace's own mode, beside the marked
        # staging directory the next compact recognizes as its own.
        (staging,) = _stagings(path)
        ready = _compact_temp(path)
        assert ready.is_file()
        assert (staging / "remora-compact").is_file()
        if not layout:
            assert ready.parent == staging
        if sys.platform != "win32":
            assert stat.S_IMODE(os.lstat(ready).st_mode) == stat.S_IMODE(os.lstat(path).st_mode)
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

    def test_compact_hard_killed_after_its_swap_leaves_debris_the_next_one_removes(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:  # noqa: SIM117
            with ws.write() as con:
                con.execute(
                    "INSERT INTO pkts (frame_number, frame_time) "
                    "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
                )
        proc = subprocess.Popen(
            [sys.executable, "-c", _BLOCK_AFTER_SWAP, str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            assert proc.stdout.readline().strip() == "SWAPPED"
            proc.kill()  # SIGKILL: the staging directory is never removed
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=30)
        # The compacted file is in place; its staging directory holds only
        # the marker, and on Windows the claim on the temp that is now the
        # workspace (R4-F2).
        (staging,) = _stagings(path)
        assert sorted(p.name for p in staging.iterdir()) == (
            ["remora-compact", "temp-claim"]
            if workspace_module._TEMP_BESIDE_STAGING
            else ["remora-compact"]
        )
        with Workspace(path, mode="rw") as ws:
            ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert rows == [(7,)]
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
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
