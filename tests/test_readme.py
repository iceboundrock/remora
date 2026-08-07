"""README code fences are CI-checked so the quickstart can never rot (issue #24).

Marker contract: an HTML comment line immediately before a ```python fence
in README.md opts that fence into CI:

- ``<!-- ci:typecheck -->`` — the fence must pass ``mypy --strict`` as a
  standalone module.
- ``<!-- ci:run -->`` — typechecked AND executed against a real tshark
  (integration) with ``capture.pcap`` (a copy of ``tests/data/sample.pcap``)
  in the working directory.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
SAMPLE_PCAP = REPO_ROOT / "tests" / "data" / "sample.pcap"

_MARKED_FENCE = re.compile(
    r"<!-- ci:(?P<mode>run|typecheck) -->\n```python\n(?P<code>.*?)```",
    re.DOTALL,
)


def _snippets() -> list[tuple[str, str]]:
    """(mode, code) for every marked python fence, in README order."""
    text = README.read_text(encoding="utf-8")
    return [(m["mode"], m["code"]) for m in _MARKED_FENCE.finditer(text)]


def test_readme_has_marked_snippets() -> None:
    modes = [mode for mode, _ in _snippets()]
    assert "run" in modes, "README must keep a <!-- ci:run --> quickstart fence"
    assert "typecheck" in modes, "README must keep <!-- ci:typecheck --> fences"


@pytest.mark.parametrize(("index", "snippet"), list(enumerate(_snippets())))
def test_marked_snippet_typechecks(tmp_path: Path, index: int, snippet: tuple[str, str]) -> None:
    _, code = snippet
    source = tmp_path / f"readme_snippet_{index}.py"
    source.write_text(code, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", source.name],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"snippet {index}:\n{code}\n{result.stdout}"


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which(os.environ.get("TSHARK") or "tshark") is None
    and not os.environ.get("REMORA_REQUIRE_TSHARK"),
    reason="tshark not installed; skipping integration tests",
)
def test_quickstart_runs_against_sample_pcap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_snippets = [code for mode, code in _snippets() if mode == "run"]
    assert run_snippets
    shutil.copy(SAMPLE_PCAP, tmp_path / "capture.pcap")
    monkeypatch.chdir(tmp_path)
    for code in run_snippets:
        exec(compile(code, "<README quickstart>", "exec"), {"__name__": "__main__"})
    out = capsys.readouterr().out
    assert "10.0.0.1 443" in out
