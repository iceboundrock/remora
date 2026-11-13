"""Give compact()'s temp file the workspace file's access restrictions (#85, #132).

:meth:`remora.workspace.workspace.Workspace.compact` copies the workspace into
a sibling temp file that DuckDB creates, and swaps it in. A file DuckDB creates
gets its platform's defaults: the process umask on POSIX, and on Windows the
access control list the directory hands down to new files. Swapped in as it is,
the temp would replace a workspace whose own file was restricted (``0o600``,
say, or a Windows DACL that leaves out other users of a shared directory) with
a file those users can open. :func:`copy_permissions` gives the temp the
source's restrictions. Compact calls it as soon as DuckDB has created the temp,
while the temp is still an empty database, so no row is ever written into the
temp while it is more open than the workspace.

On Windows that order closes the gap completely. DuckDB opens a read-write
database file without sharing read or write access, so from the moment the
temp exists until the DACL is applied no other handle can open it for data. From
then on the temp has the workspace's own DACL. POSIX has no share modes, so a
descriptor that another user opens in the short interval between DuckDB
creating the temp and this call stays usable afterwards.

DuckDB's ``.wal`` sidecars, the temp's included, are created with the defaults
on both platforms. On POSIX a ``0o600`` database's ``.wal`` is ``0o644`` and
holds committed rows until the next checkpoint. On Windows DuckDB holds the
``.wal`` without read sharing and deletes it on a clean close, so only a crash
leaves one behind. This module does not reach them, and the directory's
permissions are what protect a workspace's data (#147).

The module is import-pure and never imports duckdb. Its only Windows
dependencies are ``advapi32`` and ``kernel32`` through :mod:`ctypes`, bound at
import under ``sys.platform == "win32"`` so other platforms never touch them.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

__all__ = ["copy_permissions"]


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _SE_FILE_OBJECT = 1  # SE_OBJECT_TYPE
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
    _SE_DACL_PROTECTED = 0x1000  # SECURITY_DESCRIPTOR_CONTROL

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetSecurityDescriptorControl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    _advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _advapi32.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    _advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _win_error(code: int, filename: str) -> OSError:
        err = ctypes.WinError(code)
        err.filename = filename
        return err

    def _copy_dacl(src: Path, dst: Path) -> None:
        """Set ``dst``'s DACL to ``src``'s, including whether it inherits.

        A protected DACL (inheritance disabled, the usual shape of a file
        made private) is applied as it is. An unprotected one is applied as
        unprotected, so its explicit entries are copied and its inherited
        entries are derived again from ``dst``'s parent. For compact's temp
        that parent is ``src``'s own directory, so the result equals the
        source. Neither call opens a file for data access, so a DuckDB
        connection that holds either file without read or write sharing does
        not block them; the Windows compact tests run exactly that case.
        """
        src_abs = os.path.abspath(os.fspath(src))
        dst_abs = os.path.abspath(os.fspath(dst))
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        code = _advapi32.GetNamedSecurityInfoW(
            src_abs,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if code:
            raise _win_error(code, src_abs)
        try:
            if not dacl.value:
                # No DACL at all grants everyone full access, so the source
                # has no restriction for the temp to lack.
                return
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise _win_error(ctypes.get_last_error(), src_abs)
            if control.value & _SE_DACL_PROTECTED:
                inheritance = _PROTECTED_DACL_SECURITY_INFORMATION
            else:
                inheritance = _UNPROTECTED_DACL_SECURITY_INFORMATION
            code = _advapi32.SetNamedSecurityInfoW(
                dst_abs,
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION | inheritance,
                None,
                None,
                dacl,
                None,
            )
            if code:
                raise _win_error(code, dst_abs)
        finally:
            _kernel32.LocalFree(descriptor)


def copy_permissions(src: Path, dst: Path) -> None:
    """Give ``dst`` the access restrictions of ``src``.

    On POSIX these are the permission bits. On Windows they are the
    read-only attribute (the one bit :func:`os.chmod` sets there) and the
    discretionary ACL, together with whether that ACL inherits from the
    directory. Inherited entries are derived from ``dst``'s own parent, so
    the copy is exact when both files share a directory, as compact's temp
    and the workspace do. Ownership, the group, and the Windows owner and
    audit entries stay as ``dst`` has them, because changing those needs
    privileges.

    Args:
        src: The file whose restrictions are copied.
        dst: The file that receives them. The caller must be allowed to
            change its permissions, which the owner of a newly created file
            always is.

    Raises:
        OSError: If ``src``'s restrictions cannot be read or ``dst``'s cannot
            be set. The error names the file the failed step was working on.
    """
    os.chmod(dst, stat.S_IMODE(os.stat(src).st_mode))
    if sys.platform == "win32":
        _copy_dacl(src, dst)
