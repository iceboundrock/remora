"""replace_file, the compact() swap primitive, on each platform (issue #85)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

import remora.workspace.swap as swap_module
from conftest import duckdb_shares_delete
from remora.workspace.errors import WorkspaceError
from remora.workspace.swap import (
    SourceReplacedError,
    explain_rename_error,
    remove_file,
    replace_file,
    stat_unfollowed,
)

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows rename semantics")


def test_replace_file_renames_over_the_destination(tmp_path: Path) -> None:
    src = tmp_path / "new"
    dst = tmp_path / "old"
    src.write_bytes(b"new")
    dst.write_bytes(b"old")
    replace_file(src, dst)
    assert dst.read_bytes() == b"new"
    assert not src.exists()


def _identity(st: os.stat_result) -> tuple[int, int]:
    return (st.st_dev, st.st_ino)


def _replace_quietly(src: Path, dst: Path) -> bool:
    """Try to put ``src`` at ``dst``, as another program would; whether it landed."""
    try:
        os.replace(src, dst)
    except OSError:
        return False
    return True


class TestVerifiedReplaceAndRemove:
    """The check and the act concern one file (#147, R7-F1, R7-F2).

    Another program replacing the file at the name *after* the check must
    change nothing about which file is renamed or removed. On Windows the
    handle the check and the act share does not share deletion, so the
    replacement fails; on POSIX the file was taken into the private holding
    directory before the check, so the replacement lands at a free name and
    is left alone.
    """

    @staticmethod
    def _setup(tmp_path: Path) -> tuple[Path, Path, Path, tuple[int, int]]:
        holding = tmp_path / "holding"
        holding.mkdir(mode=0o700)
        ours = tmp_path / "ours"
        ours.write_bytes(b"ours")
        theirs = tmp_path / "theirs"
        theirs.write_bytes(b"theirs")
        return holding, ours, theirs, _identity(stat_unfollowed(ours))

    def test_stat_unfollowed_agrees_with_the_creating_descriptor(self, tmp_path: Path) -> None:
        path = tmp_path / "f"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            created = os.fstat(fd)
        finally:
            os.close(fd)
        assert _identity(stat_unfollowed(path)) == _identity(created)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_stat_unfollowed_does_not_follow_a_link(self, tmp_path: Path) -> None:
        (tmp_path / "target").write_bytes(b"x")
        (tmp_path / "link").symlink_to(tmp_path / "target")
        assert stat.S_ISLNK(stat_unfollowed(tmp_path / "link").st_mode)

    def test_replace_renames_the_checked_file_despite_a_later_replacement(
        self, tmp_path: Path
    ) -> None:
        holding, ours, theirs, mine = self._setup(tmp_path)
        dst = tmp_path / "dst"
        dst.write_bytes(b"old")
        landed: list[bool] = []

        def verify(st: os.stat_result) -> bool:
            ok = _identity(st) == mine
            landed.append(_replace_quietly(theirs, ours))
            return ok

        replace_file(ours, dst, verify=verify, holding=holding)
        assert dst.read_bytes() == b"ours"
        assert landed == [sys.platform != "win32"]
        assert (ours if landed[0] else theirs).read_bytes() == b"theirs"
        assert list(holding.iterdir()) == []

    def test_replace_refuses_a_file_verify_rejects(self, tmp_path: Path) -> None:
        holding, ours, theirs, _ = self._setup(tmp_path)
        os.replace(theirs, ours)
        before = _identity(os.lstat(ours))
        dst = tmp_path / "dst"
        dst.write_bytes(b"old")
        with pytest.raises(SourceReplacedError):
            replace_file(ours, dst, verify=lambda st: False, holding=holding)
        assert dst.read_bytes() == b"old"
        assert ours.read_bytes() == b"theirs"
        assert _identity(os.lstat(ours)) == before
        assert list(holding.iterdir()) == []

    def test_replace_refuses_a_missing_source(self, tmp_path: Path) -> None:
        holding, _, _, _ = self._setup(tmp_path)
        dst = tmp_path / "dst"
        dst.write_bytes(b"old")
        with pytest.raises(SourceReplacedError):
            replace_file(tmp_path / "gone", dst, verify=lambda st: True, holding=holding)
        assert dst.read_bytes() == b"old"

    def test_remove_removes_the_checked_file_despite_a_later_replacement(
        self, tmp_path: Path
    ) -> None:
        holding, ours, theirs, mine = self._setup(tmp_path)
        landed: list[bool] = []

        def verify(st: os.stat_result) -> bool:
            ok = _identity(st) == mine
            landed.append(_replace_quietly(theirs, ours))
            return ok

        assert remove_file(ours, verify, holding=holding)
        assert landed == [sys.platform != "win32"]
        if landed[0]:
            assert ours.read_bytes() == b"theirs"
        else:
            assert not ours.exists()
            assert theirs.read_bytes() == b"theirs"
        assert list(holding.iterdir()) == []

    def test_remove_leaves_a_file_verify_rejects(self, tmp_path: Path) -> None:
        holding, ours, theirs, mine = self._setup(tmp_path)
        os.replace(theirs, ours)
        before = _identity(os.lstat(ours))
        assert not remove_file(ours, lambda st: _identity(st) == mine, holding=holding)
        assert ours.read_bytes() == b"theirs"
        assert _identity(os.lstat(ours)) == before
        assert list(holding.iterdir()) == []

    def test_remove_of_a_missing_file_removes_nothing(self, tmp_path: Path) -> None:
        holding, _, _, _ = self._setup(tmp_path)
        assert not remove_file(tmp_path / "gone", lambda st: True, holding=holding)


class TestExplainRenameError:
    def test_no_delete_sharing_names_duckdb_floor_and_retry(self, tmp_path: Path) -> None:
        message = explain_rename_error(32, tmp_path / "ws.duckdb")
        assert message is not None
        assert "delete sharing" in message
        assert "1.5.0" in message
        assert "retry" in message
        assert "ws.duckdb" in message

    def test_access_denied_is_not_diagnosed_as_a_sharing_conflict(self, tmp_path: Path) -> None:
        # ERROR_ACCESS_DENIED can mean missing delete rights on the target
        # and its directory. Preserve the OS error rather than advise a retry
        # or DuckDB upgrade that cannot fix those permissions.
        assert explain_rename_error(5, tmp_path / "ws.duckdb") is None

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
    def test_access_denied_from_rename_propagates_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if sys.platform != "win32":
            pytest.fail("Windows rename semantics only")
        import ctypes

        target = tmp_path / "old"
        tmp = tmp_path / "new"
        target.write_bytes(b"old")
        tmp.write_bytes(b"new")
        error = ctypes.WinError(5)
        error.filename = str(target)

        def denied(handle: int, dst: Path) -> None:
            assert dst == target
            raise error

        # Inject only the rename's OS error: opening and closing the source
        # handle still use the real Windows implementation.
        with monkeypatch.context() as patch:
            patch.setattr(swap_module, "_rename_handle", denied)
            with pytest.raises(PermissionError) as excinfo:
                replace_file(tmp, target)
        assert excinfo.value is error
        assert excinfo.value.winerror == 5
        assert excinfo.value.filename == str(target)
        assert target.read_bytes() == b"old"
        assert tmp.read_bytes() == b"new"
        replace_file(tmp, target)
        assert target.read_bytes() == b"new"
        assert not tmp.exists()

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
