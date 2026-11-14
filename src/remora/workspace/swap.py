"""Atomic rename-over of compact()'s temp file, on every platform (issue #85).

:meth:`remora.workspace.workspace.Workspace.compact` rewrites the workspace
into a sibling temp file and installs it over the original *while the
original's read-write DuckDB connection is still open*, so that one
exclusive lock covers both the snapshot and the swap and no commit can land
between them. On POSIX ``os.replace`` is that swap: renaming over an open
file is legal, and the superseded inode lives on, unnamed, until its last
descriptor closes.

Windows needs two things for the same effect. Every handle on the file
being replaced must have been opened with ``FILE_SHARE_DELETE``, which
DuckDB does from 1.5.0 on (duckdb/duckdb#19782) and did not before. And the
rename must ask for *POSIX semantics*: the legacy ``MoveFileExW`` behind
``os.replace`` refuses to replace a file that has any open handle at all,
while ``SetFileInformationByHandle(FileRenameInfoEx)`` with
``FILE_RENAME_FLAG_POSIX_SEMANTICS`` (Windows 10 1607 / Server 2016 and
later, on NTFS; ReFS is unverified) renames over it and leaves the
superseded file alive, unnamed, until its last handle closes — the POSIX
picture exactly.
:func:`replace_file` is that rename on Windows and ``os.replace`` elsewhere,
so compact has one swap primitive with one failure contract.

On Windows the temp sits beside the workspace, outside any directory only
its owner can enter, so its pathname proves nothing about which file is
there (#147). Checking a file by name and then renaming or removing
whatever is at that name leaves a window in which another program can put
its own file there. So :func:`replace_file` (given ``verify``) and
:func:`remove_file` check the file's identity and rename or remove it
through one handle: what they act on is the very file they checked. The
handle shares reading and writing but not deletion, so for its short life
nothing else can rename the file away or replace it at its name either.
:func:`stat_unfollowed` reads the identity the same way, so a recorded
identity and a later check always agree on how it is spelled.

The module is import-pure and never imports duckdb; the only Windows
dependencies are ``kernel32`` through :mod:`ctypes` and :mod:`msvcrt`, bound
at import under ``sys.platform == "win32"`` so other platforms never touch
them.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from remora.workspace.errors import WorkspaceError

__all__ = [
    "SourceReplacedError",
    "explain_rename_error",
    "remove_file",
    "replace_file",
    "stat_unfollowed",
]

# Win32 error codes the rename is expected to meet. Two environmental
# refusals get a WorkspaceError that says what to do; everything else
# propagates as the OSError it is.
_ERROR_SHARING_VIOLATION = 32
_ERROR_NOT_SUPPORTED = 50
_ERROR_INVALID_PARAMETER = 87

# Where a POSIX caller's private ``holding`` directory keeps a file between
# taking it from its name and acting on it (see _take).
_HELD = "held"


class SourceReplacedError(WorkspaceError):
    """The file at the source's name is not the one ``verify`` accepts.

    Nothing was renamed or removed: the file at the name is as it was.
    """


def _take(src: Path, holding: Path) -> Path | None:
    """Move whatever is at ``src`` into ``holding``; ``None`` if nothing is.

    POSIX has no rename or unlink through a descriptor. A rename into a
    directory only this user can enter does the same job: from then on
    nothing else can reach the file, so checking it there and acting on it
    there concern one file. ``src`` and ``holding`` are on one filesystem.
    """
    held = holding / _HELD
    if os.path.lexists(held):
        raise FileExistsError(f"{held} is already taken")
    try:
        os.rename(src, held)
    except FileNotFoundError:
        return None
    return held


def _put_back(held: Path, src: Path) -> None:
    """Return a taken file to ``src``, without replacing anything there now.

    A hard link fails on an existing entry, so a file that has appeared at
    ``src`` meanwhile is never replaced; the taken file then stays in the
    holding directory and the error propagates. What cannot be hard linked
    (a directory) goes back by rename, while ``src`` is free.
    """
    try:
        os.link(held, src, follow_symlinks=False)
    except (OSError, NotImplementedError):
        if os.path.lexists(src):
            raise
        os.rename(held, src)
        return
    os.unlink(held)


def explain_rename_error(winerror: int | None, dst: Path) -> str | None:
    """Return the :class:`WorkspaceError` message for a classified swap refusal.

    ``ERROR_SHARING_VIOLATION`` means a handle on ``dst`` was opened without
    delete sharing: a DuckDB older than 1.5.0, or a scanner that has the file
    for a moment. ``ERROR_INVALID_PARAMETER`` and ``ERROR_NOT_SUPPORTED``
    mean this Windows or volume cannot perform a
    POSIX-semantics rename at all. Both leave the workspace unchanged, and
    the message says so. Any other code — including ``None`` — returns
    ``None``, and the caller re-raises the original error. In particular,
    ``ERROR_ACCESS_DENIED`` (5) does not establish a sharing conflict: it can
    also mean missing delete permission on the file and its directory, so
    the original :class:`PermissionError` propagates unchanged.

    Args:
        winerror: The Win32 error code from the failed rename, or ``None``.
        dst: The workspace file the swap was going to replace.
    """
    if winerror == _ERROR_SHARING_VIOLATION:
        return (
            f"compact() could not swap the rewritten file over {dst}: the file is held "
            f"open by a handle without delete sharing (Windows error {winerror}). DuckDB "
            "opens its database with delete sharing only from 1.5.0 on, and an antivirus "
            "or indexer scan can hold a file briefly. The workspace is unchanged; retry, "
            "or upgrade duckdb"
        )
    if winerror in (_ERROR_NOT_SUPPORTED, _ERROR_INVALID_PARAMETER):
        return (
            f"compact() could not swap the rewritten file over {dst}: this Windows or "
            "volume does not support a POSIX-semantics rename (Windows error "
            f"{winerror}); compact needs Windows 10 1607 / Server 2016 or later on an "
            "NTFS volume. The workspace is unchanged"
        )
    return None


if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _DELETE = 0x00010000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _FILE_READ_ATTRIBUTES = 0x00000080
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # lets a directory open, to be refused
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # the link itself, never its target
    _FILE_DISPOSITION_INFO = 4  # FILE_INFO_BY_HANDLE_CLASS.FileDispositionInfo
    _FILE_RENAME_INFO_EX = 22  # FILE_INFO_BY_HANDLE_CLASS.FileRenameInfoEx
    _FILE_DISPOSITION_INFO_EX = 21  # FILE_INFO_BY_HANDLE_CLASS.FileDispositionInfoEx
    _FILE_RENAME_FLAG_REPLACE_IF_EXISTS = 0x00000001
    _FILE_RENAME_FLAG_POSIX_SEMANTICS = 0x00000002
    _FILE_DISPOSITION_FLAG_DELETE = 0x00000001
    _FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x00000002
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL

    def _open_for_rename(src: Path) -> int:
        """Open ``src`` for a rename and return the handle; raises ``OSError``."""
        src_abs = os.path.abspath(os.fspath(src))
        # DELETE is the access a rename needs on the file being moved; full
        # sharing so this handle never blocks anyone else for its short life.
        handle: int = _kernel32.CreateFileW(
            src_abs,
            _DELETE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.WinError(ctypes.get_last_error())
            err.filename = src_abs
            raise err
        return handle

    def _open_unfollowed(path: Path, access: int, share: int) -> int:
        """Open ``path`` itself, never a link's target, and return the handle.

        Raises ``OSError`` naming ``path``.
        """
        path_abs = os.path.abspath(os.fspath(path))
        handle: int = _kernel32.CreateFileW(
            path_abs,
            access,
            share,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.WinError(ctypes.get_last_error())
            err.filename = path_abs
            raise err
        return handle

    def _fd_for(handle: int) -> int:
        """A CRT descriptor that owns ``handle``, so :func:`os.fstat` can read it.

        Closing the descriptor closes the handle. On failure the handle is
        closed here.
        """
        try:
            return msvcrt.open_osfhandle(handle, os.O_RDONLY)
        except BaseException:
            _kernel32.CloseHandle(handle)
            raise

    def _delete_handle(handle: int) -> None:
        """Delete the file behind ``handle``; raises ``OSError``.

        POSIX semantics, so the name goes at once, where the volume offers
        them; otherwise delete-on-close, which this handle's close triggers.
        """

        class _DispositionInfoEx(ctypes.Structure):
            _fields_ = (("Flags", wintypes.ULONG),)

        class _DispositionInfo(ctypes.Structure):
            _fields_ = (("DeleteFile", wintypes.BOOLEAN),)

        ex = _DispositionInfoEx()
        ex.Flags = _FILE_DISPOSITION_FLAG_DELETE | _FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
        if _kernel32.SetFileInformationByHandle(
            handle, _FILE_DISPOSITION_INFO_EX, ctypes.byref(ex), ctypes.sizeof(ex)
        ):
            return
        code = ctypes.get_last_error()
        if code not in (_ERROR_INVALID_PARAMETER, _ERROR_NOT_SUPPORTED):
            raise ctypes.WinError(code)
        legacy = _DispositionInfo()
        legacy.DeleteFile = 1
        if not _kernel32.SetFileInformationByHandle(
            handle, _FILE_DISPOSITION_INFO, ctypes.byref(legacy), ctypes.sizeof(legacy)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def _rename_handle(handle: int, dst: Path) -> None:
        """Rename the file behind ``handle`` over ``dst`` with POSIX semantics.

        Raises ``OSError`` naming ``dst``. The caller owns ``handle``.
        """
        dst_abs = os.path.abspath(os.fspath(dst))
        # FILE_RENAME_INFO with the Flags member of its leading union and
        # the name inline, sized for this one target. FileName is UTF-16.
        # NTFS names are arbitrary UTF-16 and may hold an unpaired surrogate;
        # ctypes stores it as one unit, so count it as one.
        encoded = dst_abs.encode("utf-16-le", "surrogatepass")
        units = len(encoded) // 2  # UTF-16 code units, excluding the NUL

        class _FileRenameInfo(ctypes.Structure):
            _fields_ = (
                ("Flags", wintypes.DWORD),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", wintypes.WCHAR * (units + 1)),
            )

        info = _FileRenameInfo()
        info.Flags = _FILE_RENAME_FLAG_REPLACE_IF_EXISTS | _FILE_RENAME_FLAG_POSIX_SEMANTICS
        info.RootDirectory = None
        info.FileNameLength = len(encoded)  # bytes, excluding the NUL
        info.FileName = dst_abs
        ok = _kernel32.SetFileInformationByHandle(
            handle, _FILE_RENAME_INFO_EX, ctypes.byref(info), ctypes.sizeof(info)
        )
        if not ok:
            err = ctypes.WinError(ctypes.get_last_error())
            err.filename = dst_abs
            raise err

    def _rename_classified(handle: int, dst: Path) -> None:
        """Rename the file behind ``handle`` over ``dst``, classifying refusals."""
        try:
            _rename_handle(handle, dst)
        except OSError as exc:
            message = explain_rename_error(exc.winerror, dst)
            if message is None:
                raise
            raise WorkspaceError(message) from exc


def stat_unfollowed(path: Path) -> os.stat_result:
    """``path``'s own status, a link's rather than its target's.

    :func:`os.lstat` on POSIX. On Windows :func:`os.fstat` of a handle opened
    on the entry itself, which asks for attributes only and so never
    conflicts with a share mode: the same reading :func:`replace_file` and
    :func:`remove_file` make of their handle, so an identity recorded from
    it matches theirs. Raises ``OSError``.
    """
    if sys.platform == "win32":
        share = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
        fd = _fd_for(_open_unfollowed(path, _FILE_READ_ATTRIBUTES, share))
        try:
            return os.fstat(fd)
        finally:
            os.close(fd)
    return os.lstat(path)


def replace_file(
    src: Path,
    dst: Path,
    *,
    verify: Callable[[os.stat_result], bool] | None = None,
    holding: Path | None = None,
) -> None:
    """Rename ``src`` over ``dst`` atomically, even while ``dst`` is held open.

    ``os.replace`` everywhere but Windows. On Windows a POSIX-semantics
    rename, which succeeds while ``dst`` is open provided every handle on it
    has delete sharing — true of DuckDB 1.5.0 and later. ``dst`` is replaced
    whole or not at all; on failure both files are as they were.

    This primitive is intended for compact's freshly created regular temp
    file, not as a general replacement for ``os.replace``. If ``src`` is a
    symlink, Windows follows it and renames its target, whereas POSIX renames
    the link itself. Compact never passes a source symlink.

    With ``verify``, only the file ``verify`` accepts is renamed, judged by
    its status as :func:`stat_unfollowed` reads it, and the check and the
    rename concern one file: on Windows both go through one handle, opened
    on the entry itself, that does not share deletion; on POSIX the file is
    first moved into ``holding``, a directory only this user can enter on
    ``src``'s filesystem, then checked and renamed from there. A file
    ``verify`` refuses is left as it was (on POSIX, put back at ``src``).

    Raises:
        SourceReplacedError: With ``verify``, when nothing is at ``src`` or
            ``verify`` refuses what is; nothing was renamed.
        WorkspaceError: On Windows, when ``dst`` is held by a handle without
            delete sharing (a DuckDB older than 1.5.0, or a scanner that has
            the file for a moment), or when this Windows or volume cannot
            perform a POSIX-semantics rename. See :func:`explain_rename_error`.
        OSError: On Windows, when ``src`` cannot be opened for the rename:
            the error as the system reported it, naming ``src``, unclassified,
            with both files unchanged. Unclassified rename errors also
            propagate unchanged, including :class:`PermissionError` for
            access denied (Windows error 5), which may mean missing delete
            permission rather than a sharing conflict.
    """
    refused = f"{src} is not the file to rename; nothing was renamed"
    if sys.platform == "win32":
        if verify is None:
            # Opening the temp is outside the classifying try: its failure
            # is about src, and explain_rename_error only describes refusals
            # on dst.
            handle = _open_for_rename(src)
            try:
                _rename_classified(handle, dst)
            finally:
                _kernel32.CloseHandle(handle)
            return
        try:
            handle = _open_unfollowed(
                src, _DELETE | _FILE_READ_ATTRIBUTES, _FILE_SHARE_READ | _FILE_SHARE_WRITE
            )
        except FileNotFoundError as exc:
            raise SourceReplacedError(refused) from exc
        fd = _fd_for(handle)
        try:
            if not verify(os.fstat(fd)):
                raise SourceReplacedError(refused)
            _rename_classified(handle, dst)
        finally:
            os.close(fd)
        return
    if verify is None:
        os.replace(src, dst)
        return
    if holding is None:
        raise ValueError("replace_file(verify=...) needs a holding directory on POSIX")
    held = _take(src, holding)
    if held is None:
        raise SourceReplacedError(refused)
    try:
        if not verify(os.lstat(held)):
            raise SourceReplacedError(refused)
        os.replace(held, dst)
    except BaseException:
        _put_back(held, src)
        raise


def remove_file(path: Path, verify: Callable[[os.stat_result], bool], *, holding: Path) -> bool:
    """Remove ``path`` only if it is the file ``verify`` accepts.

    ``verify`` judges the file's status as :func:`stat_unfollowed` reads it,
    and the check and the removal concern one file, exactly as in
    :func:`replace_file`: one handle that does not share deletion on
    Windows (``holding`` is unused there), a move into the private
    ``holding`` directory on POSIX. Whatever ``verify`` refuses is left as it
    was (on POSIX, put back at ``path``).

    Returns:
        Whether a file was removed: ``False`` when nothing is at ``path`` or
        ``verify`` refuses it.

    Raises:
        OSError: The file could not be opened, removed or put back.
    """
    if sys.platform == "win32":
        try:
            handle = _open_unfollowed(
                path, _DELETE | _FILE_READ_ATTRIBUTES, _FILE_SHARE_READ | _FILE_SHARE_WRITE
            )
        except FileNotFoundError:
            return False
        fd = _fd_for(handle)
        try:
            if not verify(os.fstat(fd)):
                return False
            _delete_handle(handle)
        finally:
            os.close(fd)
        return True
    held = _take(path, holding)
    if held is None:
        return False
    try:
        ok = verify(os.lstat(held))
    except BaseException:
        _put_back(held, path)
        raise
    if not ok:
        _put_back(held, path)
        return False
    os.unlink(held)
    return True
