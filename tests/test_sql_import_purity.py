"""Import-purity test for the SQL backend (issue #29).

Deliberately no ``pytest.importorskip("duckdb")``: this test asserts that
importing the sql compiler does not pull in duckdb. The assertion is meaningful
both where duckdb is installed (it must stay unimported) and where it is absent
(the import must still succeed) — which is why the module carries no importorskip.
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
