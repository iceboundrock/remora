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

The module is import-pure and never imports duckdb; the only Windows
dependency is ``kernel32`` through :mod:`ctypes`, bound at import under
``sys.platform == "win32"`` so other platforms never touch it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from remora.workspace.errors import WorkspaceError

__all__ = ["explain_rename_error", "replace_file"]

# Win32 error codes the rename is expected to meet. Two environmental
# refusals get a WorkspaceError that says what to do; everything else
# propagates as the OSError it is.
_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_ERROR_NOT_SUPPORTED = 50
_ERROR_INVALID_PARAMETER = 87


def explain_rename_error(winerror: int | None, dst: Path) -> str | None:
    """Return the :class:`WorkspaceError` message for a classified swap refusal.

    ``ERROR_ACCESS_DENIED`` and ``ERROR_SHARING_VIOLATION`` mean a handle on
    ``dst`` was opened without delete sharing: a DuckDB older than 1.5.0, or
    a scanner that has the file for a moment. ``ERROR_INVALID_PARAMETER``
    and ``ERROR_NOT_SUPPORTED`` mean this Windows or volume cannot perform a
    POSIX-semantics rename at all. Both leave the workspace unchanged, and
    the message says so. Any other code — including ``None`` — returns
    ``None``, and the caller re-raises the original error.

    Args:
        winerror: The Win32 error code from the failed rename, or ``None``.
        dst: The workspace file the swap was going to replace.
    """
    if winerror in (_ERROR_ACCESS_DENIED, _ERROR_SHARING_VIOLATION):
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
    from ctypes import wintypes

    _DELETE = 0x00010000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_RENAME_INFO_EX = 22  # FILE_INFO_BY_HANDLE_CLASS.FileRenameInfoEx
    _FILE_RENAME_FLAG_REPLACE_IF_EXISTS = 0x00000001
    _FILE_RENAME_FLAG_POSIX_SEMANTICS = 0x00000002
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


def replace_file(src: Path, dst: Path) -> None:
    """Rename ``src`` over ``dst`` atomically, even while ``dst`` is held open.

    ``os.replace`` everywhere but Windows. On Windows a POSIX-semantics
    rename, which succeeds while ``dst`` is open provided every handle on it
    has delete sharing — true of DuckDB 1.5.0 and later. ``dst`` is replaced
    whole or not at all; on failure both files are as they were.

    Raises:
        WorkspaceError: On Windows, when ``dst`` is held by a handle without
            delete sharing (a DuckDB older than 1.5.0, or a scanner that has
            the file for a moment), or when this Windows or volume cannot
            perform a POSIX-semantics rename. See :func:`explain_rename_error`.
        OSError: On Windows, when ``src`` cannot be opened for the rename:
            the error as the system reported it, naming ``src``, unclassified,
            with both files unchanged. Anything else the rename reports,
            unchanged.
    """
    if sys.platform == "win32":
        # Opening the temp is outside the classifying try: its failure is
        # about src, and explain_rename_error only describes refusals on dst.
        handle = _open_for_rename(src)
        try:
            try:
                _rename_handle(handle, dst)
            except OSError as exc:
                message = explain_rename_error(exc.winerror, dst)
                if message is None:
                    raise
                raise WorkspaceError(message) from exc
        finally:
            _kernel32.CloseHandle(handle)
    else:
        os.replace(src, dst)
