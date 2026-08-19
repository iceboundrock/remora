"""Import-purity test for the SQL backend (issue #29).

Deliberately no ``pytest.importorskip("duckdb")``: this test asserts that
importing the sql compiler pulls in neither duckdb nor any other optional
dependency, and that a missing duckdb raises a helpful :class:`ImportError` —
so it must run precisely where duckdb is *absent*.
"""

from __future__ import annotations

import subprocess
import sys


def test_importing_the_backend_does_not_import_duckdb() -> None:
    # The compiler emits plain strings and plain Python values; importing it
    # must not pull the optional dependency in, even where it is installed.
    code = (
        "import sys\n"
        "import remora.compile.sql\n"
        "assert 'duckdb' not in sys.modules, 'duckdb imported by the sql backend'\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], check=False, timeout=60, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
