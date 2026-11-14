"""copy_permissions, compact()'s use of it, and what the directory protects (#85, #132, #147).

compact() swaps in a temp file created with this process's defaults, by
DuckDB on POSIX and by compact itself on Windows. These tests pin three
things. The temp has the workspace file's restrictions before any row is
copied into it, and the compacted file keeps them. On POSIX the temp and its
``.wal`` sit inside an owner-only directory for as long as they hold rows,
because a mode set after DuckDB creates a file cannot revoke a descriptor
opened before it, and the ``.wal`` never gets one.
And the workspace's own ``.wal`` is created with the process defaults, a
known DuckDB limitation pinned so a fixed DuckDB is noticed. A restricted
workspace in a directory whose defaults are wider is the case that fails
without all that: ``0o600`` under umask ``022``, or a Windows file made
private inside a folder every user may read.
"""

from __future__ import annotations

import contextlib
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
from remora.workspace.permissions import copy_permissions, copy_permissions_to_descriptor
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


@pytest.fixture(params=["native", "windows"])
def layout(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Run compact() in this platform's layout and in the Windows one.

    Returns whether the temp is beside the staging directory, as on Windows,
    where compact creates it and sets its restrictions through the creating
    descriptor rather than by name.
    """
    if request.param == "windows":
        monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)
    return workspace_module._TEMP_BESIDE_STAGING


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
    """The temp database of the one compact in flight on the workspace at ``path``.

    On POSIX ``compact.duckdb`` inside its private staging directory, on
    Windows the staging directory's sibling ``<staging name>.tmp``.
    """
    (staging,) = _stagings(path)
    return workspace_module._staging_temp(staging)


def _stale_staging(path: Path) -> Path:
    """Leave what a compact of ``path`` killed mid-copy leaves: its marked
    staging directory, the temp and the temp's ``.wal``, and on Windows the
    claim recording the temp."""
    staging = workspace_module._make_staging(path)
    tmp = workspace_module._staging_temp(staging)
    tmp.write_bytes(b"garbage from an interrupted compact")
    tmp.with_name(tmp.name + ".wal").write_bytes(b"garbage wal")
    if workspace_module._TEMP_BESIDE_STAGING:
        workspace_module._claim_temp(staging)
    return staging


def _snapshot(root: Path, *, but: str | None = None) -> dict[str, tuple[str, object, int]]:
    """Everything under ``root`` without following links: kind, content and mode.

    ``but`` leaves out one top-level entry, such as the workspace a compact
    rewrites.
    """
    found: dict[str, tuple[str, object, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for entry in (*dirnames, *filenames):
            p = Path(dirpath) / entry
            rel = p.relative_to(root).as_posix()
            if rel == but:
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                found[rel] = ("link", os.readlink(p), 0)
            elif stat.S_ISDIR(st.st_mode):
                found[rel] = ("dir", None, stat.S_IMODE(st.st_mode))
            else:
                found[rel] = ("file", p.read_bytes(), stat.S_IMODE(st.st_mode))
    return found


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

    @pytest.mark.parametrize("restriction", RESTRICTIONS)
    def test_descriptor_gets_the_source_restrictions(
        self, shared_dir: Path, restriction: str
    ) -> None:
        src = shared_dir / "src"
        src.write_bytes(b"src")
        _restrict(src, restriction)
        dst = shared_dir / "dst"
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o666)
        try:
            assert _access(dst) != _access(src)  # the directory's default is wider
            copy_permissions_to_descriptor(src, fd, name=dst)
            os.write(fd, b"dst")  # the descriptor stays writable
        finally:
            os.close(fd)
        assert _access(dst) == _access(src)
        assert dst.read_bytes() == b"dst"

    @pytest.mark.skipif(sys.platform == "win32", reason="renames over an open CRT file")
    def test_descriptor_never_reaches_a_file_put_at_its_name(self, shared_dir: Path) -> None:
        # R8-F1: the restrictions go to the file the descriptor is open on,
        # not to whatever is at its name by then.
        src = shared_dir / "src"
        src.write_bytes(b"src")
        os.chmod(src, 0o600)
        dst = shared_dir / "dst"
        theirs = shared_dir / "theirs"
        theirs.write_bytes(b"someone else's file")
        os.chmod(theirs, 0o604)
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.replace(theirs, dst)
            copy_permissions_to_descriptor(src, fd, name=dst)
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        finally:
            os.close(fd)
        assert dst.read_bytes() == b"someone else's file"
        assert stat.S_IMODE(os.lstat(dst).st_mode) == 0o604

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
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch, restriction: str, layout: bool
    ) -> None:
        path = shared_dir / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        _restrict(path, restriction)
        restricted = _access(path)
        # Without the copy the temp would have this, which is wider.
        assert _fresh_access(shared_dir) != restricted
        seen: list[object] = []

        def at_copy() -> None:
            tmp = _compact_temp(path)
            seen.append(_access(tmp))
            if sys.platform == "win32":
                # DuckDB holds the temp without read sharing, so nobody the
                # directory's ACL admits could open it before the DACL landed.
                assert _read_open_error(tmp) == _ERROR_SHARING_VIOLATION

        def at_detach() -> None:
            if sys.platform == "win32":
                # The temp's .wal, which copy_permissions does not reach, is
                # held the same way while it holds rows.
                tmp = _compact_temp(path)
                wal = tmp.with_name(tmp.name + ".wal")
                assert wal.exists()
                assert _read_open_error(wal) == _ERROR_SHARING_VIOLATION

        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                _probe_compact(m, {"COPY FROM DATABASE": at_copy, "DETACH compact_dst": at_detach})
                ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert seen == [restricted]
        assert _access(path) == restricted
        assert rows == [(7,)]

    def test_refuses_before_copying_when_restrictions_cannot_be_carried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: bool
    ) -> None:
        path = tmp_path / "ws.duckdb"
        error = PermissionError(13, "simulated: cannot set permissions", "the temp")
        copies: list[str] = []
        attaches: list[str] = []
        temps: list[Path] = []

        def check(src: Path, dst: Path) -> None:
            # Names only: compact works on the realpath, which may respell
            # the directory (macOS /private/var, Windows 8.3 short names).
            tmp = _compact_temp(path)
            assert (src.name, dst.parent.name, dst.name) == (
                path.name,
                tmp.parent.name,
                tmp.name,
            )
            temps.append(tmp)

        def cannot_copy(src: Path, dst: Path) -> None:
            assert not layout  # the Windows layout never sets them by name
            check(src, dst)
            raise error

        def cannot_copy_to_descriptor(src: Path, fd: int, *, name: Path | None = None) -> None:
            assert layout
            assert name is not None
            # Through the descriptor that created the temp, before ATTACH.
            assert os.path.samestat(os.fstat(fd), os.lstat(name))
            assert attaches == []
            check(src, name)
            raise error

        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
            with monkeypatch.context() as m:
                m.setattr(workspace_module, "copy_permissions", cannot_copy)
                m.setattr(
                    workspace_module, "copy_permissions_to_descriptor", cannot_copy_to_descriptor
                )
                _probe_compact(
                    m,
                    {
                        "ATTACH": lambda: attaches.append("attach"),
                        "COPY FROM DATABASE": lambda: copies.append("copy"),
                    },
                )
                with pytest.raises(WorkspaceError, match="access restrictions") as excinfo:
                    ws.compact()
            assert excinfo.value.__cause__ is error
            assert "unchanged" in str(excinfo.value)
            assert copies == []
            (tmp,) = temps
            assert not tmp.exists()
            assert not tmp.with_name(tmp.name + ".wal").exists()
            assert _stagings(path) == []
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
            assert rows == [(7,)]
            ws.compact()  # the refusal released the lock and both identity flags
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != path.name]
        assert leftovers == []

    @pytest.mark.parametrize("when", ["at ATTACH", "after the check"])
    def test_windows_temp_replaced_in_flight_keeps_its_own_permissions(
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch, when: str
    ) -> None:
        # R8-F1: in the Windows layout the temp's name is in the shared
        # directory, so another program can put its own file there at any
        # instant: as ATTACH starts, or right after compact's identity check
        # following it. The workspace's restrictions go to the temp through
        # the descriptor that created and claimed it, never by name, so the
        # other file keeps its own (narrower) permissions and its content;
        # compact refuses it, and the workspace keeps its rows and its own
        # restrictions.
        monkeypatch.setattr(workspace_module, "_TEMP_BESIDE_STAGING", True)
        path = shared_dir / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        workspace_access = _access(path)
        # Made beside it first, so the replacement cannot take a freed inode.
        theirs = shared_dir / "theirs"
        with Workspace(theirs, mode="rw") as other, other.write() as con:
            con.execute(
                "INSERT INTO pkts (frame_number, frame_time) "
                "VALUES (99, TIMESTAMP '2024-01-01 00:00:00')"
            )
        _restrict(theirs, "private")
        their_access = _access(theirs)
        # Given the workspace's restrictions, their file would be wider.
        assert their_access != workspace_access
        content = theirs.read_bytes()
        monkeypatch.setattr("secrets.token_hex", lambda n: "7" * 16)
        tmp = path.with_name("remora-compact-" + "7" * 16 + ".tmp")
        replaced: list[str] = []

        def replace() -> None:
            # replace_file, not os.replace: after ATTACH the temp is held by
            # DuckDB, and on Windows only a POSIX-semantics rename can
            # replace a file DuckDB holds open.
            replace_file(theirs, tmp)
            replaced.append(when)

        with Workspace(path, mode="rw") as ws:
            with monkeypatch.context() as m:
                if when == "at ATTACH":
                    _probe_compact(m, {"ATTACH": lambda: None if replaced else replace()})
                else:
                    real_same_file = workspace_module._same_file

                    def check_then_replace(p: Path, claim: bytes) -> bool:
                        ok = real_same_file(p, claim)
                        if ok and not replaced:
                            replace()
                        return ok

                    m.setattr(workspace_module, "_same_file", check_then_replace)
                with pytest.raises(WorkspaceError, match="replaced by a file it did not create"):
                    ws.compact()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        assert replaced == [when]
        assert rows == [(7,)]
        assert _access(path) == workspace_access
        assert tmp.read_bytes() == content
        assert _access(tmp) == their_access
        assert sorted(p.name for p in shared_dir.iterdir()) == sorted([path.name, tmp.name])


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX staging directory (#147)")
class TestCompactStaging:
    """On POSIX compact()'s temp and its .wal live in an owner-only directory (#147)."""

    def test_temp_and_wal_hold_rows_only_inside_a_private_directory(
        self, shared_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = shared_dir / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        os.chmod(path, 0o600)
        # The directory everyone may enter: what the temp would sit in otherwise.
        assert _mode(shared_dir) & 0o005 == 0o005
        seen: dict[str, object] = {}
        scratch: list[Path] = []

        def staged() -> dict[str, object]:
            (staging,) = _stagings(path)
            scratch.append(staging)
            return {
                "beside": sorted(p.name for p in shared_dir.iterdir()),
                "scratch_mode": _mode(staging),
                "scratch_owner": os.lstat(staging).st_uid,
                "inside": sorted(p.name for p in staging.iterdir()),
            }

        def at_copy() -> None:
            seen["copy"] = staged()
            seen["tmp_mode"] = _mode(_compact_temp(path))

        def at_detach() -> None:
            # COPY wrote rows into the temp's .wal, created with the umask's
            # 0o644; only the directory keeps other users from it.
            seen["detach"] = staged()
            tmp_wal = _compact_temp(path).with_name("compact.duckdb.wal")
            seen["wal_mode"] = _mode(tmp_wal)
            seen["wal_size"] = tmp_wal.stat().st_size

        real_replace = replace_file

        def at_swap(src: Path, dst: Path, **kwargs: Any) -> None:
            # Final, closed and without a .wal, the temp is swapped in from
            # inside the staging directory.
            seen["swap"] = staged()
            seen["swap_src"] = (src.parent.name, src.name)
            seen["swap_mode"] = _mode(src)
            real_replace(src, dst, **kwargs)

        with Workspace(path, mode="rw") as ws:
            _probe_compact(
                monkeypatch, {"COPY FROM DATABASE": at_copy, "DETACH compact_dst": at_detach}
            )
            monkeypatch.setattr(workspace_module, "replace_file", at_swap)
            ws.compact()
            monkeypatch.undo()
            with ws.read() as con:
                rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        # One staging directory, this compact's, throughout.
        assert len(set(scratch)) == 1
        name = scratch[0].name
        assert re.fullmatch(r"remora-compact-[0-9a-f]{16}", name)
        private = {
            "beside": sorted(["ws.duckdb", name]),
            "scratch_mode": 0o700,
            "scratch_owner": os.stat(path).st_uid,  # this process's user
        }
        assert seen["copy"] == {**private, "inside": ["compact.duckdb", "remora-compact"]}
        assert seen["detach"] == {
            **private,
            "inside": ["compact.duckdb", "compact.duckdb.wal", "remora-compact"],
        }
        assert seen["tmp_mode"] == 0o600
        assert seen["wal_mode"] == 0o644
        assert isinstance(seen["wal_size"], int)
        assert seen["wal_size"] > 0
        assert seen["swap"] == {**private, "inside": ["compact.duckdb", "remora-compact"]}
        assert seen["swap_src"] == (name, "compact.duckdb")
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
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        modes: list[int] = []
        previous = os.umask(0)
        try:
            with Workspace(path, mode="rw") as ws:
                _probe_compact(
                    monkeypatch,
                    {"COPY FROM DATABASE": lambda: modes.append(_mode(_compact_temp(path).parent))},
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
        # What a compact killed mid-copy leaves, in whatever mode.
        scratch = _stale_staging(path)
        os.chmod(scratch, stale_mode)
        try:
            with Workspace(path, mode="rw") as ws:
                if stale_mode == 0o500:
                    # Entries of a directory its owner cannot write cannot be
                    # removed (as root they can, so the test asks the kernel).
                    removable = os.access(scratch, os.W_OK)
                    if not removable:
                        with pytest.raises(WorkspaceError, match="remove it and retry"):
                            ws.compact()
                        assert (scratch / "compact.duckdb").exists()
                        os.chmod(scratch, 0o700)
                ws.compact()
                with ws.read() as con:
                    rows = con.execute("SELECT frame_number FROM pkts").fetchall()
        finally:
            if scratch.exists():
                os.chmod(scratch, 0o700)
        assert rows == [(7,)]
        assert sorted(p.name for p in tmp_path.iterdir()) == ["ws.duckdb"]

    def test_symlinks_at_staging_names_are_not_followed_or_removed(self, tmp_path: Path) -> None:
        # A symlink is never a compact's own staging, even one pointing at a
        # directory that would pass for it; neither it nor its target is
        # touched.
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        lookalike = _stale_staging(elsewhere / "ws.duckdb")
        (tmp_path / ("remora-compact-" + "0" * 16)).symlink_to(lookalike, target_is_directory=True)
        (tmp_path / "ws.duckdb.compacting").symlink_to(elsewhere, target_is_directory=True)
        before = _snapshot(tmp_path)
        with Workspace(path, mode="rw") as ws:
            ws.compact()
        assert _snapshot(tmp_path, but="ws.duckdb") == {
            k: v for k, v in before.items() if k != "ws.duckdb"
        }
        assert before["remora-compact-" + "0" * 16][0] == "link"

    def test_refuses_to_swap_when_the_temp_wal_outlives_detach(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as ws:
            _insert_row(ws)
        real_connect = workspace_module._connect

        class _WalLeftBehind(_ProbingConnection):
            def execute(self, query: str, *args: Any) -> Any:
                result = super().execute(query, *args)
                if query.startswith("DETACH compact_dst"):
                    # A DuckDB whose detach did not fold the .wal back in.
                    tmp = _compact_temp(path)
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
