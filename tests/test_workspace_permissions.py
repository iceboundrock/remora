"""copy_permissions, and compact()'s use of it (issues #85, #132).

compact() swaps in a temp file that DuckDB created with this process's
defaults. These tests pin two things. The temp has the workspace file's
restrictions before any row is copied into it, and the compacted file keeps
them. A restricted workspace in a directory whose defaults are wider is the
case that fails without that: ``0o600`` under umask ``022``, or a Windows file
made private inside a folder every user may read.
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
    developer's own umask is.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    if sys.platform == "win32":
        _icacls(shared, "/grant", f"*{_EVERYONE}:(OI)(RX)")
        yield shared
        return
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
        tmp = path.with_name(path.name + ".compacting")
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
                with pytest.raises(PermissionError) as excinfo, open(tmp, "rb"):
                    pass
                assert excinfo.value.winerror == 32  # ERROR_SHARING_VIOLATION

        def at_detach() -> None:
            if sys.platform == "win32":
                # The temp's .wal, which copy_permissions does not reach, is
                # held the same way while it holds rows.
                wal = tmp.with_name(tmp.name + ".wal")
                assert wal.exists()
                with pytest.raises(PermissionError) as excinfo, open(wal, "rb"):
                    pass
                assert excinfo.value.winerror == 32

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
        tmp = path.with_name(path.name + ".compacting")
        error = PermissionError(13, "simulated: cannot set permissions", str(tmp))
        copies: list[str] = []

        def cannot_copy(src: Path, dst: Path) -> None:
            # Names only: compact works on the realpath, which may respell
            # the directory (macOS /private/var, Windows 8.3 short names).
            assert (src.name, dst.name) == (path.name, tmp.name)
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
