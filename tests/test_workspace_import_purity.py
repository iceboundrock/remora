"""Import-purity and optional-dependency contract tests (issue #28).

Deliberately no ``pytest.importorskip("duckdb")``: these tests assert that
importing the workspace package pulls in neither duckdb nor any open file
handle, and that a missing duckdb raises a helpful :class:`ImportError` — so
they must run precisely where duckdb is *absent*.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from remora.workspace.workspace import Workspace


class TestNoModuleLevelConnection:
    def test_import_does_not_import_duckdb(self) -> None:
        # A module-level connection is impossible without the duckdb module:
        # importing the package in a fresh interpreter must not pull it in,
        # nor leave any file handle open (checked where /proc exists).
        code = (
            "import os, sys\n"
            "fds_before = None\n"
            "if sys.platform == 'linux':\n"
            "    fds_before = set(os.listdir('/proc/self/fd'))\n"
            "import remora.workspace, remora.workspace.workspace, remora.workspace.query, "
            "remora.workspace.attach\n"
            "assert 'duckdb' not in sys.modules, 'duckdb imported at module level'\n"
            "if fds_before is not None:\n"
            "    new = set(os.listdir('/proc/self/fd')) - fds_before\n"
            "    targets = []\n"
            "    for fd in new:\n"
            "        try:\n"
            "            targets.append(os.readlink('/proc/self/fd/' + fd))\n"
            "        except OSError:\n"
            "            pass\n"
            "    assert not targets, f'import left handles open: {targets}'\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True, timeout=60)

    def test_constructing_workspace_opens_nothing(self, tmp_path: Path) -> None:
        # Constructing (not entering) a Workspace must not touch the file.
        path = tmp_path / "ws.duckdb"
        Workspace(path, mode="rw")
        assert not path.exists()

    def test_missing_duckdb_raises_helpful_importerror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A None entry in sys.modules makes `import duckdb` raise, which is
        # what an uninstalled extra looks like from inside the helper.
        monkeypatch.setitem(sys.modules, "duckdb", None)
        with pytest.raises(ImportError, match=r"remora\[workspace\]"):
            Workspace(tmp_path / "ws.duckdb", mode="rw").open()
