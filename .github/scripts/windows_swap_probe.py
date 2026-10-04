"""Issue #85 probe: can a file DuckDB holds open on Windows be renamed over?

Prints one line per question; never asserts, so a run always shows every
answer. Temporary: deleted once the answers are recorded on #85.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
from ctypes import wintypes

import duckdb

DELETE = 0x00010000
SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_RENAME_INFO_EX = 22
REPLACE_IF_EXISTS = 0x1
POSIX_SEMANTICS = 0x2

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.SetFileInformationByHandle.restype = wintypes.BOOL


def posix_rename(src: str, dst: str) -> None:
    h = k32.CreateFileW(src, DELETE, SHARE_ALL, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:

        class Info(ctypes.Structure):
            _fields_ = (
                ("Flags", wintypes.DWORD),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", wintypes.WCHAR * (len(dst) + 1)),
            )

        info = Info(
            Flags=REPLACE_IF_EXISTS | POSIX_SEMANTICS,
            RootDirectory=None,
            FileNameLength=len(dst) * 2,
            FileName=dst,
        )
        if not k32.SetFileInformationByHandle(
            h, FILE_RENAME_INFO_EX, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(h)


def attempt(label: str, fn, *args) -> bool:
    try:
        fn(*args)
    except OSError as exc:
        print(f"{label}: FAIL {type(exc).__name__} winerror={exc.winerror} {exc}")
        return False
    print(f"{label}: OK")
    return True


def fresh(d: str, name: str, value: int) -> str:
    path = os.path.join(d, name)
    con = duckdb.connect(path)
    con.execute(f"CREATE TABLE t AS SELECT {value} AS x")
    con.close()
    return path


def main() -> None:
    print(
        "python",
        sys.version.split()[0],
        "duckdb",
        duckdb.__version__,
        "windows",
        sys.getwindowsversion(),
    )
    d = tempfile.mkdtemp()

    # Q2: os.replace over a file DuckDB holds open read-write.
    target = fresh(d, "q2.duckdb", 1)
    tmp = fresh(d, "q2.duckdb.compacting", 2)
    con = duckdb.connect(target, read_only=False)
    if attempt("Q2 os.replace over open duckdb rw handle", os.replace, tmp, target):
        print("Q2 old handle reads", con.execute("SELECT x FROM t").fetchall())
    con.close()
    print(
        "Q2 after close, path holds",
        duckdb.connect(target, read_only=True).execute("SELECT x FROM t").fetchall(),
    )

    # Q3: POSIX-semantics rename over a file DuckDB holds open read-write.
    target = fresh(d, "q3.duckdb", 1)
    tmp = fresh(d, "q3.duckdb.compacting", 2)
    con = duckdb.connect(target, read_only=False)
    if attempt("Q3 posix-semantics rename over open duckdb rw handle", posix_rename, tmp, target):
        print("Q3 old handle reads", con.execute("SELECT x FROM t").fetchall())
    con.close()
    print(
        "Q3 after close, path holds",
        duckdb.connect(target, read_only=True).execute("SELECT x FROM t").fetchall(),
    )
    print("Q3 dir after:", sorted(os.listdir(d)))

    # Q5: POSIX-semantics rename over a file held by a CRT open() (no FILE_SHARE_DELETE).
    target = os.path.join(d, "q5.txt")
    tmp = os.path.join(d, "q5.new")
    with open(target, "w") as f:
        f.write("old")
    with open(tmp, "w") as f:
        f.write("new")
    with open(target):
        attempt("Q5 posix-semantics rename over CRT open() handle", posix_rename, tmp, target)
        with open(tmp, "w") as f:
            f.write("new")
        attempt("Q5 os.replace over CRT open() handle", os.replace, tmp, target)

    # Q6: what a second process sees while an rw connection is open (lock error text).
    target = fresh(d, "q6.duckdb", 1)
    con = duckdb.connect(target, read_only=False)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import duckdb, sys; duckdb.connect(sys.argv[1], read_only=False)",
            target,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode == 0:
        print("Q6 second-process rw connect while rw handle open: returncode=0 (no error)")
    else:
        stderr_tail = result.stderr[-400:] if result.stderr else ""
        print(
            f"Q6 second-process rw connect while rw handle open: returncode={result.returncode}"
            f" stderr={stderr_tail!r}"
        )
    con.close()


if __name__ == "__main__":
    main()
