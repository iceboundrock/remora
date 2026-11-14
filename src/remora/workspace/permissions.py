"""Give compact()'s temp file the workspace file's access restrictions (#85, #132).

:meth:`remora.workspace.workspace.Workspace.compact` copies the workspace into
a temp file, and swaps it in. On POSIX DuckDB creates the temp when compact
attaches it; on Windows compact creates it itself, exclusively, as an empty
database, before attaching it. Either way it gets its platform's defaults: the
process umask on POSIX, and on Windows the access control list the directory
hands down to new files. Swapped in as it is, the temp would replace a
workspace whose own file was restricted (``0o600``, say, or a Windows DACL that
leaves out other users of a shared directory) with a file those users can open.
This module gives the temp the source's restrictions while it is still an
empty database, so no row is ever written into it while it is more open than
the workspace.

Where the temp is, decides how. On Windows it sits beside the workspace, where
another program can put its own file at its name at any instant, so a change
made by pathname could land on that file instead and widen it (R8-F1).
Compact therefore applies the restrictions there with
:func:`copy_permissions_to_descriptor`, through the very descriptor it created
the temp with and read the temp's claimed identity from, before closing it and
before ``ATTACH``: what is changed is the file compact created, whatever is at
its name by then. On POSIX the temp is inside compact's owner-only staging
directory, where no other user can put anything, so :func:`copy_permissions`
sets its mode by name right after ``ATTACH``.

On Windows the rows are then kept from others completely. DuckDB opens a
read-write database file without sharing read or write access, so from
``ATTACH`` on no other handle can open the temp for data, and a handle another
program opened on it before ``ATTACH``, while it held only an empty database,
makes the ``ATTACH`` fail with a sharing violation instead of staying open on
rows. POSIX has no share modes, so a descriptor that another user opens in the
short interval between DuckDB creating the temp and its mode being set would
stay usable afterwards. That is why compact creates the temp on POSIX inside
an owner-only directory, where no other user can reach it at all (#147); this
module then only decides the compacted file's own mode.

DuckDB's ``.wal`` sidecars, the temp's included, are created with the defaults
on both platforms, and this module does not reach them. The temp's lives in
compact's private directory on POSIX and is held without read sharing on
Windows. The workspace's own ``.wal`` is outside anything remora can do: on
POSIX a ``0o600`` database's ``.wal`` is ``0o644`` and holds committed rows
until the next checkpoint, so the directory's permissions are what protect a
workspace's data (#147).

The module is import-pure and never imports duckdb. Its only Windows
dependencies are ``advapi32`` and ``kernel32`` through :mod:`ctypes` and
:mod:`msvcrt`, bound at import under ``sys.platform == "win32"`` so other
platforms never touch them.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path

__all__ = ["copy_permissions", "copy_permissions_to_descriptor"]


if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _SE_FILE_OBJECT = 1  # SE_OBJECT_TYPE
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
    _SE_DACL_PROTECTED = 0x1000  # SECURITY_DESCRIPTOR_CONTROL
    _READ_CONTROL = 0x00020000
    _WRITE_DAC = 0x00040000
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_WRITE_ATTRIBUTES = 0x00000100
    _FILE_SHARE_ALL = 0x00000007  # read, write and delete
    _FILE_BASIC_INFO = 0  # FILE_INFO_BY_HANDLE_CLASS.FileBasicInfo
    _FILE_ATTRIBUTE_READONLY = 0x00000001
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

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
    _advapi32.SetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    _advapi32.SetSecurityInfo.restype = wintypes.DWORD
    _kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.ReOpenFile.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    _kernel32.ReOpenFile.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _kernel32.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = (
            ("CreationTime", wintypes.LARGE_INTEGER),
            ("LastAccessTime", wintypes.LARGE_INTEGER),
            ("LastWriteTime", wintypes.LARGE_INTEGER),
            ("ChangeTime", wintypes.LARGE_INTEGER),
            ("FileAttributes", wintypes.DWORD),
        )

    def _win_error(code: int, filename: str | None) -> OSError:
        err = ctypes.WinError(code)
        err.filename = filename
        return err

    def _copy_dacl(
        src: Path, set_dacl: Callable[[ctypes.c_void_p, int], int], dst: str | None
    ) -> None:
        """Give a file ``src``'s DACL, including whether it inherits.

        ``set_dacl(dacl, information)`` applies the DACL with the
        ``SECURITY_INFORMATION`` flags given and returns the Win32 error code,
        0 on success; ``dst`` names the file it sets, for the error.

        A protected DACL (inheritance disabled, the usual shape of a file
        made private) is applied as it is. An unprotected one is applied as
        unprotected, so its explicit entries are copied and its inherited
        entries are derived again from the file's parent. For compact's temp
        that parent is ``src``'s own directory, so the result equals the
        source. Reading ``src``'s DACL does not open it for data access, so a
        DuckDB connection that holds it without read or write sharing does
        not block it; the Windows compact tests run exactly that case.
        """
        src_abs = os.path.abspath(os.fspath(src))
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
            code = set_dacl(dacl, _DACL_SECURITY_INFORMATION | inheritance)
            if code:
                raise _win_error(code, dst)
        finally:
            _kernel32.LocalFree(descriptor)

    def _copy_dacl_by_name(src: Path, dst: Path) -> None:
        dst_abs = os.path.abspath(os.fspath(dst))

        def set_dacl(dacl: ctypes.c_void_p, information: int) -> int:
            code: int = _advapi32.SetNamedSecurityInfoW(
                dst_abs, _SE_FILE_OBJECT, information, None, None, dacl, None
            )
            return code

        _copy_dacl(src, set_dacl, dst_abs)

    def _copy_to_handle(src: Path, mode: int, handle: int, name: str | None) -> None:
        """Give the file behind ``handle`` ``mode``'s read-only bit and ``src``'s DACL.

        Both go through a handle reopened from ``handle`` (``ReOpenFile``,
        which opens the same file object, not a name) for just the access
        they need: attributes and the DACL, neither of which a share mode
        governs. ``name`` only labels an error.
        """
        reopened: int = _kernel32.ReOpenFile(
            handle,
            _READ_CONTROL | _WRITE_DAC | _FILE_READ_ATTRIBUTES | _FILE_WRITE_ATTRIBUTES,
            _FILE_SHARE_ALL,
            0,
        )
        if reopened == _INVALID_HANDLE_VALUE or not reopened:
            raise _win_error(ctypes.get_last_error(), name)
        try:
            # The read-only attribute, the one bit os.chmod sets on Windows.
            # Zero times leave the file's times as they are.
            info = _FileBasicInfo()
            if not _kernel32.GetFileInformationByHandleEx(
                reopened, _FILE_BASIC_INFO, ctypes.byref(info), ctypes.sizeof(info)
            ):
                raise _win_error(ctypes.get_last_error(), name)
            attributes = info.FileAttributes
            if mode & stat.S_IWRITE:
                wanted = attributes & ~_FILE_ATTRIBUTE_READONLY
            else:
                wanted = attributes | _FILE_ATTRIBUTE_READONLY
            if wanted != attributes:
                info = _FileBasicInfo()
                # Zero would mean "unchanged", not "no attributes".
                info.FileAttributes = wanted or _FILE_ATTRIBUTE_NORMAL
                if not _kernel32.SetFileInformationByHandle(
                    reopened, _FILE_BASIC_INFO, ctypes.byref(info), ctypes.sizeof(info)
                ):
                    raise _win_error(ctypes.get_last_error(), name)

            def set_dacl(dacl: ctypes.c_void_p, information: int) -> int:
                code: int = _advapi32.SetSecurityInfo(
                    reopened, _SE_FILE_OBJECT, information, None, None, dacl, None
                )
                return code

            _copy_dacl(src, set_dacl, name)
        finally:
            _kernel32.CloseHandle(reopened)


def copy_permissions(src: Path, dst: Path) -> None:
    """Give ``dst`` the access restrictions of ``src``.

    On POSIX these are the permission bits. On Windows they are the
    read-only attribute (the one bit :func:`os.chmod` sets there) and the
    discretionary ACL, together with whether that ACL inherits from the
    directory. Inherited entries are derived from ``dst``'s own parent, so
    the copy is exact when both files share a directory, as compact's temp
    and the workspace do on Windows. Ownership, the group, and the Windows
    owner and audit entries stay as ``dst`` has them, because changing those
    needs privileges.

    ``dst`` is reached by name, so whatever is at that name when each step
    runs is what changes. Use it only where nobody else can put a file at
    that name, as inside compact's private staging directory on POSIX;
    elsewhere set the restrictions through a descriptor with
    :func:`copy_permissions_to_descriptor`.

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
        _copy_dacl_by_name(src, dst)


def copy_permissions_to_descriptor(src: Path, fd: int, *, name: Path | None = None) -> None:
    """Give the file open as ``fd`` the access restrictions of ``src``.

    The same restrictions as :func:`copy_permissions`, set through ``fd``
    rather than by name: :func:`os.fchmod` on POSIX, and on Windows the
    read-only attribute and the DACL through a handle reopened from ``fd``'s
    own. So they reach exactly the file ``fd`` is open on, even if another
    file has taken its name meanwhile, and nothing at the name is touched.
    Inherited DACL entries are derived from that file's parent, as in
    :func:`copy_permissions`.

    Args:
        src: The file whose restrictions are copied, read by name.
        fd: A descriptor open on the file that receives them, which the
            caller must be allowed to change the permissions of (the owner of
            a newly created file always is).
        name: The file's pathname, used only to name it in an error, never
            to reach it.

    Raises:
        OSError: If ``src``'s restrictions cannot be read or the file's cannot
            be set.
    """
    mode = stat.S_IMODE(os.stat(src).st_mode)
    if sys.platform == "win32":
        label = None if name is None else os.path.abspath(os.fspath(name))
        _copy_to_handle(src, mode, msvcrt.get_osfhandle(fd), label)
        return
    try:
        os.fchmod(fd, mode)
    except OSError as exc:
        if name is not None and exc.filename is None:
            exc.filename = os.fspath(name)
        raise
