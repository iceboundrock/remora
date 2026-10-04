"""replace_file, the compact() swap primitive, on each platform (issue #85)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import duckdb_shares_delete
from remora.workspace.errors import WorkspaceError
from remora.workspace.swap import explain_rename_error, replace_file

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows rename semantics")


def test_replace_file_renames_over_the_destination(tmp_path: Path) -> None:
    src = tmp_path / "new"
    dst = tmp_path / "old"
    src.write_bytes(b"new")
    dst.write_bytes(b"old")
    replace_file(src, dst)
    assert dst.read_bytes() == b"new"
    assert not src.exists()


class TestExplainRenameError:
    @pytest.mark.parametrize("code", [5, 32])
    def test_no_delete_sharing_names_duckdb_floor_and_retry(
        self, code: int, tmp_path: Path
    ) -> None:
        message = explain_rename_error(code, tmp_path / "ws.duckdb")
        assert message is not None
        assert "delete sharing" in message
        assert "1.5.0" in message
        assert "retry" in message
        assert "ws.duckdb" in message

    @pytest.mark.parametrize("code", [50, 87])
    def test_unsupported_names_the_platform_requirement(self, code: int, tmp_path: Path) -> None:
        message = explain_rename_error(code, tmp_path / "ws.duckdb")
        assert message is not None
        assert "POSIX" in message
        assert "NTFS" in message

    @pytest.mark.parametrize("code", [None, 2, 3, 112])
    def test_everything_else_is_not_explained(self, code: int | None, tmp_path: Path) -> None:
        assert explain_rename_error(code, tmp_path / "ws.duckdb") is None


@windows_only
class TestWindowsRename:
    @pytest.mark.skipif(
        not duckdb_shares_delete(), reason="needs duckdb >= 1.5.0 (opens with FILE_SHARE_DELETE)"
    )
    def test_replaces_file_held_open_by_duckdb(self, tmp_path: Path) -> None:
        duckdb = pytest.importorskip("duckdb")
        target = tmp_path / "ws.duckdb"
        tmp = tmp_path / "ws.duckdb.compacting"
        con = duckdb.connect(str(target), read_only=False)
        con.execute("CREATE TABLE t AS SELECT 1 AS x")
        other = duckdb.connect(str(tmp))
        other.execute("CREATE TABLE t AS SELECT 2 AS x")
        other.close()
        # The point of #85: the swap lands while the exclusive connection is open.
        replace_file(tmp, target)
        assert not tmp.exists()
        # The superseded file lives on, unnamed, under the old handle ...
        assert con.execute("SELECT x FROM t").fetchall() == [(1,)]
        con.close()
        # ... and the path now holds the new file, intact after the old close.
        check = duckdb.connect(str(target), read_only=True)
        try:
            assert check.execute("SELECT x FROM t").fetchall() == [(2,)]
        finally:
            check.close()

    def test_target_without_delete_sharing_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "held"
        tmp = tmp_path / "new"
        target.write_bytes(b"old")
        tmp.write_bytes(b"new")
        # A CRT open() shares read and write but not delete — what a DuckDB
        # older than 1.5.0, or a scanner, looks like to the rename.
        with open(target, "rb"), pytest.raises(WorkspaceError, match="delete sharing"):
            replace_file(tmp, target)
        assert target.read_bytes() == b"old"
        assert tmp.read_bytes() == b"new"

    def test_temp_without_delete_sharing_is_not_classified(self, tmp_path: Path) -> None:
        target = tmp_path / "ws.duckdb"
        tmp = tmp_path / "ws.duckdb.compacting"
        target.write_bytes(b"old")
        tmp.write_bytes(b"new")
        # Held here is the SOURCE: opening it for the rename fails, and that
        # is not a refusal on the workspace file, so it must not be explained
        # as one. It propagates as the OSError it is, naming the temp.
        with open(tmp, "rb"), pytest.raises(OSError) as excinfo:
            replace_file(tmp, target)
        assert not isinstance(excinfo.value, WorkspaceError)
        # getattr: typeshed declares OSError.winerror only for win32.
        assert getattr(excinfo.value, "winerror", None) == 32  # ERROR_SHARING_VIOLATION
        assert os.path.normcase(excinfo.value.filename) == os.path.normcase(os.path.abspath(tmp))
        assert target.read_bytes() == b"old"
        assert tmp.read_bytes() == b"new"

    @pytest.mark.skipif(
        not duckdb_shares_delete(), reason="needs duckdb >= 1.5.0 (opens with FILE_SHARE_DELETE)"
    )
    def test_os_replace_cannot_replace_an_open_file(self, tmp_path: Path) -> None:
        # Pins why swap.py exists: the stdlib rename is the legacy MoveFileExW,
        # which refuses a target with any open handle — even one opened with
        # FILE_SHARE_DELETE. If a future CPython makes this pass, replace_file
        # can go back to os.replace.
        duckdb = pytest.importorskip("duckdb")
        target = tmp_path / "ws.duckdb"
        tmp = tmp_path / "ws.duckdb.compacting"
        con = duckdb.connect(str(target), read_only=False)
        other = duckdb.connect(str(tmp))
        other.close()
        try:
            with pytest.raises(PermissionError):
                os.replace(tmp, target)
        finally:
            con.close()

    @pytest.mark.skipif(
        not duckdb_shares_delete(), reason="needs duckdb >= 1.5.0 (opens with FILE_SHARE_DELETE)"
    )
    def test_replace_file_with_non_bmp_directory_name(self, tmp_path: Path) -> None:
        # FileNameLength must count UTF-16 units, not code points. A non-BMP
        # character (an emoji in a directory name) has one more UTF-16 unit
        # than code points. Test that the swap completes correctly.
        duckdb = pytest.importorskip("duckdb")
        data_dir = tmp_path / "data-😀"
        data_dir.mkdir()
        target = data_dir / "ws.duckdb"
        tmp = data_dir / "ws.duckdb.compacting"
        con = duckdb.connect(str(target), read_only=False)
        con.execute("CREATE TABLE t AS SELECT 1 AS x")
        other = duckdb.connect(str(tmp))
        other.execute("CREATE TABLE t AS SELECT 2 AS x")
        other.close()
        # The swap must complete correctly with non-BMP characters in the path.
        replace_file(tmp, target)
        assert not tmp.exists()
        assert con.execute("SELECT x FROM t").fetchall() == [(1,)]
        con.close()
        # The path now holds the new file.
        check = duckdb.connect(str(target), read_only=True)
        try:
            assert check.execute("SELECT x FROM t").fetchall() == [(2,)]
        finally:
            check.close()

    def test_replace_file_with_lone_surrogate_directory_name(self, tmp_path: Path) -> None:
        # NTFS names are arbitrary UTF-16, so a directory may hold an unpaired
        # surrogate. FileNameLength must count it as the one unit ctypes
        # stores, not refuse to encode it.
        data_dir = tmp_path / "data-\udcff"
        data_dir.mkdir()
        target = data_dir / "old"
        tmp = data_dir / "new"
        target.write_bytes(b"old")
        tmp.write_bytes(b"new")
        replace_file(tmp, target)
        assert not tmp.exists()
        assert target.read_bytes() == b"new"
