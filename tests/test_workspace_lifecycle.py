"""Workspace lifecycle, lock discipline, and compact() tests (issue #28)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from remora.workspace.errors import SchemaVersionError, WorkspaceError
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
