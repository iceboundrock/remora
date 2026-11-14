"""copy_permissions, compact()'s use of it, and what the directory protects (#85, #132, #147).

compact() swaps in a temp file that DuckDB created with this process's
defaults. These tests pin three things. The temp has the workspace file's
restrictions before any row is copied into it, and the compacted file keeps
them. On POSIX the temp and its ``.wal`` sit inside an owner-only directory
for as long as they hold rows, because a mode set after DuckDB creates a file
cannot revoke a descriptor opened before it, and the ``.wal`` never gets one.
And the workspace's own ``.wal`` is created with the process defaults, a
known DuckDB limitation pinned so a fixed DuckDB is noticed. A restricted
workspace in a directory whose defaults are wider is the case that fails
without all that: ``0o600`` under umask ``022``, or a Windows file made
private inside a folder every user may read.
"""

from __future__ import annotations

import csv
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, NamedTuple

import pytest

import remora.workspace.workspace as workspace_module
from remora.workspace.errors import WorkspaceError
from remora.workspace.permissions import copy_permissions
from remora.workspace.swap import replace_file
from remora.workspace.workspace import Workspace

duckdb = pytest.importorskip("duckdb")

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")

_EVERYONE = "S-1-1-0"
_GUESTS = "S-1-5-32-546"


class _Dacl(NamedTuple):
    """A DACL as access checks see it: whether it inherits, and its ordered entries."""

    protected: bool
    entries: tuple[str, ...]


def _dacl(path: Path) -> _Dacl:
    """Read ``path``'s DACL as SDDL, independently of remora.workspace.permissions."""
    if sys.platform != "win32":
        raise NotImplementedError("Windows ACLs only")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
    )
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    se_file_object, dacl_information, sddl_revision_1 = 1, 0x4, 1

    descriptor = ctypes.c_void_p()
    code = advapi32.GetNamedSecurityInfoW(
        str(path),
        se_file_object,
        dacl_information,
        None,
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if code:
        raise ctypes.WinError(code)
    text = wintypes.LPWSTR()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, sddl_revision_1, dacl_information, ctypes.byref(text), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = text.value or ""
    finally:
        kernel32.LocalFree(text)
        kernel32.LocalFree(descriptor)
    # "D:PAI(A;;FA;;;SY)(A;ID;0x1200a9;;;WD)": control flags, then the entries.
    # Only P(rotected) affects access; AI/AR are bookkeeping and are dropped.
    flags, _, _ = sddl.removeprefix("D:").partition("(")
    return _Dacl(protected="P" in flags, entries=tuple(re.findall(r"\(([^)]*)\)", sddl)))


def _read_open_error(path: Path) -> int:
    """Open ``path`` for reading as any other reader would; return the Win32 error, 0 if it opened.

    Python's ``open()`` goes through the CRT, which folds a sharing violation
    and an access denial into the same ``errno`` 13 and drops the Win32 code,
    so the code is taken from ``CreateFileW`` itself. The probe shares
    everything, so only the holder's share mode can refuse it.
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
    generic_read, share_all, open_existing, attribute_normal = 0x80000000, 0x7, 3, 0x80
    handle = kernel32.CreateFileW(
        str(path), generic_read, share_all, None, open_existing, attribute_normal, None
    )
    if handle == wintypes.HANDLE(-1).value:
        return ctypes.get_last_error()
    kernel32.CloseHandle(handle)
    return 0


_ERROR_SHARING_VIOLATION = 32


def _icacls(path: Path, *args: str) -> None:
    if sys.platform != "win32":
        raise NotImplementedError("Windows ACLs only")
    result = subprocess.run(["icacls", str(path), *args], capture_output=True)
    output = (result.stdout + result.stderr).decode(errors="replace")
    assert result.returncode == 0, f"icacls {' '.join(args)} failed: {output}"


def _current_user_sid() -> str:
    output = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], check=True, capture_output=True, text=True
    ).stdout
    return next(csv.reader([output.strip()]))[-1]


def _access(path: Path) -> object:
    """What other users may do with ``path``: its DACL on Windows, its mode bits on POSIX."""
    if sys.platform == "win32":
        return _dacl(path)
    return stat.S_IMODE(os.stat(path).st_mode)


def _restrict(path: Path, restriction: str) -> None:
    """Narrow ``path`` below what its directory gives a new file."""
    if restriction == "private":
        if sys.platform == "win32":
            # Inheritance off, and only this user: a file made private in a
            # shared folder (what `icacls key /inheritance:r /grant:r` does).
            _icacls(path, "/inheritance:r", "/grant:r", f"*{_current_user_sid()}:(F)")
        else:
            os.chmod(path, 0o600)
    elif restriction == "deny-guests":
        # Inheritance stays on; one explicit entry narrows what it hands down.
        _icacls(path, "/deny", f"*{_GUESTS}:(R)")
    else:
        raise AssertionError(restriction)


def _fresh_access(directory: Path) -> object:
    """The access a file newly created in ``directory`` gets."""
    probe = directory / "fresh-probe"
    probe.write_bytes(b"")
    try:
        return _access(probe)
    finally:
        probe.unlink()


@pytest.fixture
def shared_dir(tmp_path: Path) -> Iterator[Path]:
    """A directory whose defaults let other users read new files.

    On Windows every user may read what is created in it. On POSIX the umask
    is pinned to ``022`` for the test, so a new file is ``0o644`` whatever the
    developer's own umask is, and the directory itself is set to ``0o755``,
    since ``mkdir`` ran under that umask too.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    if sys.platform == "win32":
        _icacls(shared, "/grant", f"*{_EVERYONE}:(OI)(RX)")
        yield shared
        return
    os.chmod(shared, 0o755)
    previous = os.umask(0o022)
    try:
        yield shared
    finally:
        os.umask(previous)


RESTRICTIONS = ["private", pytest.param("deny-guests", marks=windows_only)]


class _ProbingConnection:
    """compact()'s source connection, running a probe as a statement starts."""

    def __init__(self, con: Any, probes: Mapping[str, Callable[[], None]]) -> None:
        self._con = con
        self._probes = probes

    def execute(self, query: str, *args: Any) -> Any:
        for prefix, probe in self._probes.items():
            if query.startswith(prefix):
                probe()
        return self._con.execute(query, *args)

    def close(self) -> None:
        self._con.close()


def _probe_compact(
    monkeypatch: pytest.MonkeyPatch, probes: Mapping[str, Callable[[], None]]
) -> None:
    real_connect = workspace_module._connect

    def connect(path: str, *, read_only: bool) -> Any:
        return _ProbingConnection(real_connect(path, read_only=read_only), probes)

    monkeypatch.setattr(workspace_module, "_connect", connect)


def _compact_temp(path: Path) -> Path:
    """Where compact() creates its temp database for the workspace at ``path``.

    On POSIX inside the private ``<name>.compacting`` directory, on Windows
    the file ``<name>.compacting`` beside the workspace.
    """
    scratch = path.with_name(path.name + ".compacting")
    return scratch if sys.platform == "win32" else scratch / path.name


def _insert_row(ws: Workspace) -> None:
    with ws.write() as con:
        con.execute(
            "INSERT INTO pkts (frame_number, frame_time) "
            "VALUES (7, TIMESTAMP '2024-01-01 00:00:00')"
        )


class TestCopyPermissions:
    @pytest.mark.parametrize("restriction", RESTRICTIONS)
    def test_fresh_file_gets_the_source_restrictions(
        self, shared_dir: Path, restriction: str
    ) -> None:
        src = shared_dir / "src"
        src.write_bytes(b"src")
        _restrict(src, restriction)
        dst = shared_dir / "dst"
        dst.write_bytes(b"dst")
        assert _access(dst) != _access(src)  # the directory's default is wider
        copy_permissions(src, dst)
        assert _access(dst) == _access(src)
        assert dst.read_bytes() == b"dst"

    @windows_only
    def test_inherited_entries_stay_inherited(self, shared_dir: Path) -> None:
        src = shared_dir / "src"
        src.write_bytes(b"src")
        _restrict(src, "deny-guests")
        dst = shared_dir / "dst"
        dst.write_bytes(b"dst")
        copy_permissions(src, dst)
        copied = _dacl(dst)
        # Still inheriting, so a later change to the directory reaches the
        # file; the directory's entries are flagged inherited, not frozen in.
        assert not copied.protected
        assert any(";ID;" in entry and entry.endswith(";WD") for entry in copied.entries)
        assert any(entry.startswith("D;") and entry.endswith(";BG") for entry in copied.entries)


class TestCompactPermissions:
    @pytest.mark.parametrize("restriction", RESTRICTIONS)
    def test_temp_is_restricted_before_any_row_is_copied(
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch, restriction: str
    ) -> None:
        path = shared_dir / "ws.duckdb"
        tmp = _compact_temp(path)
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        _restrict(path, restriction)
        restricted = _access(path)
        # Without the copy the temp would have this, which is wider.
        assert _fresh_access(shared_dir) != restricted
        seen: list[object] = []

        def at_copy() -> None:
            seen.append(_access(tmp))
            if sys.platform == "win32":
                # DuckDB holds the temp without read sharing, so nobody the
                # directory's ACL admits could open it before the DACL landed.
                assert _read_open_error(tmp) == _ERROR_SHARING_VIOLATION

        def at_detach() -> None:
            if sys.platform == "win32":
                # The temp's .wal, which copy_permissions does not reach, is
                # held the same way while it holds rows.
                wal = tmp.with_name(tmp.name + ".wal")
                assert wal.exists()
                assert _read_open_error(wal) == _ERROR_SHARING_VIOLATION

        with Workspace(path, mode="rw") as ws:
            _probe_compact(
                monkeypatch, {"COPY FROM DATABASE": at_copy, "DETACH compact_dst": at_detach}
            )
            ws.compact()
            monkeypatch.undo()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert seen == [restricted]
        assert _access(path) == restricted
        assert rows == [(7,)]

    def test_refuses_before_copying_when_restrictions_cannot_be_carried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        tmp = _compact_temp(path)
        error = PermissionError(13, "simulated: cannot set permissions", str(tmp))
        copies: list[str] = []

        def cannot_copy(src: Path, dst: Path) -> None:
            # Names only: compact works on the realpath, which may respell
            # the directory (macOS /private/var, Windows 8.3 short names).
            assert (src.name, dst.parent.name, dst.name) == (
                path.name,
                tmp.parent.name,
                tmp.name,
            )
            raise error

        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
            monkeypatch.setattr(workspace_module, "copy_permissions", cannot_copy)
            _probe_compact(monkeypatch, {"COPY FROM DATABASE": lambda: copies.append("copy")})
            with pytest.raises(WorkspaceError, match="access restrictions") as excinfo:
                ws.compact()
            monkeypatch.undo()
            assert excinfo.value.__cause__ is error
            assert "unchanged" in str(excinfo.value)
            assert copies == []
            assert not tmp.exists()
            assert not tmp.with_name(tmp.name + ".wal").exists()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
            ws.compact()  # the refusal released the lock and both identity flags
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX staging directory (#147)")
class TestCompactStaging:
    """On POSIX compact()'s temp and its .wal live in an owner-only directory (#147)."""

    def test_temp_and_wal_hold_rows_only_inside_a_private_directory(
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = shared_dir / "ws.duckdb"
        scratch = path.with_name(path.name + ".compacting")
        tmp = _compact_temp(path)
        tmp_wal = tmp.with_name(tmp.name + ".wal")
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        os.chmod(path, 0o600)
        # The directory everyone may enter: what the temp would sit in otherwise.
        assert _mode(shared_dir) & 0o005 == 0o005
        seen: dict[str, object] = {}

        def staged() -> dict[str, object]:
            return {
                "beside": sorted(p.name for p in shared_dir.iterdir()),
                "scratch_mode": _mode(scratch),
                "scratch_owner": os.lstat(scratch).st_uid,
                "inside": sorted(p.name for p in scratch.iterdir()),
            }

        def at_copy() -> None:
            seen["copy"] = staged()
            seen["tmp_mode"] = _mode(tmp)

        def at_detach() -> None:
            # COPY wrote rows into the temp's .wal, created with the umask's
            # 0o644; only the directory keeps other users from it.
            seen["detach"] = staged()
            seen["wal_mode"] = _mode(tmp_wal)
            seen["wal_size"] = tmp_wal.stat().st_size

        real_replace = replace_file

        def at_swap(src: Path, dst: Path) -> None:
            # Final, closed and without a .wal, the temp has left the
            # staging directory, which is already gone.
            seen["swap"] = sorted(p.name for p in shared_dir.iterdir())
            seen["swap_src"] = src.name
            seen["swap_mode"] = _mode(src)
            real_replace(src, dst)

        with Workspace(path, mode="rw") as ws:
            _probe_compact(
                monkeypatch, {"COPY FROM DATABASE": at_copy, "DETACH compact_dst": at_detach}
            )
            monkeypatch.setattr(workspace_module, "replace_file", at_swap)
            ws.compact()
            monkeypatch.undo()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        private = {
            "beside": ["ws.duckdb", "ws.duckdb.compacting"],
            "scratch_mode": 0o700,
            "scratch_owner": os.stat(path).st_uid,  # this process's user
        }
        assert seen["copy"] == {**private, "inside": ["ws.duckdb"]}
        assert seen["detach"] == {**private, "inside": ["ws.duckdb", "ws.duckdb.wal"]}
        assert seen["tmp_mode"] == 0o600
        assert seen["wal_mode"] == 0o644
        assert isinstance(seen["wal_size"], int)
        assert seen["wal_size"] > 0
        assert seen["swap"] == ["ws.duckdb", "ws.duckdb.compacting.new"]
        assert seen["swap_src"] == "ws.duckdb.compacting.new"
        assert seen["swap_mode"] == 0o600
        # The compacted file keeps the workspace's mode, and nothing of the
        # compact is left beside it.
        assert _mode(path) == 0o600
        assert rows == [(7,)]
        assert sorted(p.name for p in shared_dir.iterdir()) == ["ws.duckdb"]

    def test_staging_directory_is_private_under_a_permissive_umask(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        scratch = path.with_name(path.name + ".compacting")
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        modes: list[int] = []
        previous = os.umask(0)
        try:
            with Workspace(path, mode="rw") as ws:
                _probe_compact(
                    monkeypatch, {"COPY FROM DATABASE": lambda: modes.append(_mode(scratch))}
                )
                ws.compact()
        finally:
            os.umask(previous)
        assert modes == [0o700]

    @pytest.mark.parametrize("stale_mode", [0o755, 0o700, 0o500])
    def test_stale_staging_directory_is_removed_under_the_lock(
        self, tmp_path: Path, stale_mode: int
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        # What a compact killed mid-copy leaves, in whatever mode: the temp,
        # its .wal, and the pre-#147 name of a stale .wal beside them.
        scratch = path.with_name(path.name + ".compacting")
        scratch.mkdir()
        (scratch / "ws.duckdb").write_bytes(b"garbage from an interrupted compact")
        (scratch / "ws.duckdb.wal").write_bytes(b"garbage wal")
        (scratch / "nested").mkdir()
        (scratch / "nested" / "x").write_bytes(b"x")
        os.chmod(scratch, stale_mode)
        legacy_wal = path.with_name(path.name + ".compacting.wal")
        legacy_wal.write_bytes(b"pre-#147 garbage wal")
        try:
            with Workspace(path, mode="rw") as ws:
                if stale_mode == 0o500:
                    # Entries of a directory its owner cannot write cannot be
                    # removed (as root they can, so the test asks the kernel).
                    removable = os.access(scratch, os.W_OK)
                    if not removable:
                        with pytest.raises(WorkspaceError, match="remove it and retry"):
                            ws.compact()
                        assert (scratch / "ws.duckdb").exists()
                        os.chmod(scratch, 0o700)
                ws.compact()
                with ws.read() as con:
                    rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        finally:
            if scratch.exists():
                os.chmod(scratch, 0o700)
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["ws.duckdb"]

    def test_stale_symlink_is_removed_not_followed(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "keep").write_bytes(b"not compact's")
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        scratch = path.with_name(path.name + ".compacting")
        scratch.symlink_to(elsewhere, target_is_directory=True)
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert (elsewhere / "keep").read_bytes() == b"not compact's"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["elsewhere", "ws.duckdb"]

    def test_refuses_to_swap_when_the_temp_wal_outlives_detach(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        tmp = _compact_temp(path)
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        real_connect = workspace_module._connect

        class _WalLeftBehind(_ProbingConnection):
            def execute(self, query: str, *args: Any) -> Any:
                result = super().execute(query, *args)
                if query.startswith("DETACH compact_dst"):
                    # A DuckDB whose detach did not fold the .wal back in.
                    tmp.with_name(tmp.name + ".wal").write_bytes(b"rows not in the temp")
                return result

        def connect(path_: str, *, read_only: bool) -> Any:
            return _WalLeftBehind(real_connect(path_, read_only=read_only), {})

        swaps: list[Path] = []
        monkeypatch.setattr(workspace_module, "_connect", connect)
        monkeypatch.setattr(workspace_module, "replace_file", lambda src, dst: swaps.append(src))
        with Workspace(path, mode="rw") as ws:
            with pytest.raises(WorkspaceError, match="still present after detaching"):
                ws.compact()
            monkeypatch.undo()
            assert swaps == []
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
            ws.compact()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["ws.duckdb"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
class TestWorkspaceWal:
    """The workspace's own .wal: a DuckDB limitation, not something remora can fix (#147).

    DuckDB creates a database's ``.wal`` with the process defaults, not with
    the database file's mode, and a committed row sits in it until the next
    checkpoint. remora has no hook between DuckDB creating the file and
    writing to it, and neither a ``chmod`` after the fact (a descriptor opened
    before it stays usable) nor a process-wide ``umask`` change (not
    thread-safe) is a fix, so the directory is the documented boundary. The
    test states the behaviour remora would want and is a strict xfail: the day
    a DuckDB release creates the ``.wal`` with the database's mode it starts
    passing, the strict xfail fails the run, and the boundary in
    docs/workspace.md is due for a second look.
    """

    @pytest.mark.xfail(
        strict=True,
        reason="DuckDB creates the .wal with the process defaults, not the database's mode (#147)",
    )
    def test_committed_rows_wal_has_the_database_mode(
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = shared_dir / "ws.duckdb"
        wal = path.with_name(path.name + ".wal")
        with Workspace(path, mode="rw"):
            pass
        os.chmod(path, 0o600)
        observed: list[tuple[int, int]] = []
        real_connect = workspace_module._connect

        class _ProbeAtClose(_ProbingConnection):
            def close(self) -> None:
                # After write() committed, before the close checkpoints the
                # .wal away: the moment the committed row is in it.
                if wal.exists():
                    observed.append((_mode(wal), wal.stat().st_size))
                super().close()

        def connect(path_: str, *, read_only: bool) -> Any:
            return _ProbeAtClose(real_connect(path_, read_only=read_only), {})

        with Workspace(path, mode="rw") as ws:
            monkeypatch.setattr(workspace_module, "_connect", connect)
            _insert_row(ws)
            monkeypatch.undo()
        assert len(observed) == 1
        wal_mode, wal_size = observed[0]
        assert wal_size > 0  # the committed row is in it
        assert wal_mode == _mode(path)  # fails today: 0o644 beside 0o600
