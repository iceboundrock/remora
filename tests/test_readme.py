"""README code fences are CI-checked so the quickstart can never rot (issue #24).

Marker contract: an HTML comment line immediately before a ```python fence
in README.md opts that fence into CI. Every marked fence is typechecked; the
mode says what else happens to it.

- ``<!-- ci:typecheck -->`` — ``mypy --strict`` only. The weakest mode, and
  the fallback for a snippet that must not execute.
- ``<!-- ci:exec -->`` — typechecked AND executed in-process, with no tshark
  and no capture file. This is what catches protocol and field rot:
  ``ProtocolMeta.__getattr__`` types any attribute as ``Any`` and
  ``remora.proto.__getattr__`` returns ``object``, so mypy accepts
  ``IP.no_such_field`` and ``from remora.proto import NOSUCHPROTO`` — only
  running the snippet raises ``AttributeError``/``ImportError``.
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

# The mypy floor the package supports (pyproject requires-python >= 3.10). The
# snippet subprocess runs from a tmp dir, so [tool.mypy] never loads — pin it here.
PYTHON_VERSION = "3.10"

MODES = ("run", "exec", "typecheck")

# Trailing spaces/CRLF on a marker line must not silently drop its fence, so
# both patterns tolerate them — and _MARKER_LINE stays deliberately loose about
# the mode so a typo'd mode is counted and reported rather than ignored.
_MARKED_FENCE = re.compile(
    r"<!-- ci:(?P<mode>" + "|".join(MODES) + r") -->[ \t]*\r?\n"
    r"```python[ \t]*\r?\n(?P<code>.*?)```",
    re.DOTALL,
)
#: Every marker line, valid mode or not. Counted against _MARKED_FENCE so a
#: marker that stops being followed by a fence fails loudly instead of
#: silently dropping its snippet out of CI.
_MARKER_LINE = re.compile(r"^<!-- ci:.*-->[ \t]*\r?$", re.MULTILINE)


def _snippets() -> list[tuple[str, str]]:
    """(mode, code) for every marked python fence, in README order."""
    text = README.read_text(encoding="utf-8")
    return [(m["mode"], m["code"]) for m in _MARKED_FENCE.finditer(text)]


def _snippets_for(mode: str) -> list[tuple[int, str]]:
    """(README-order index, code) for every fence in *mode*."""
    return [(i, code) for i, (m, code) in enumerate(_snippets()) if m == mode]


def test_readme_has_marked_snippets() -> None:
    modes = [mode for mode, _ in _snippets()]
    assert "run" in modes, "README must keep a <!-- ci:run --> quickstart fence"
    assert "exec" in modes, "README must keep <!-- ci:exec --> fences"


def test_every_marker_line_is_extracted() -> None:
    markers = _MARKER_LINE.findall(README.read_text(encoding="utf-8"))
    assert len(_snippets()) == len(markers), (
        f"{len(markers)} ci: marker line(s) in README.md but "
        f"{len(_snippets())} extracted snippet(s) — a marker must sit on its own "
        "line immediately above a ```python fence, and its mode must be one of "
        f"{', '.join(MODES)}"
    )


@pytest.mark.parametrize(("index", "snippet"), list(enumerate(_snippets())))
def test_marked_snippet_typechecks(tmp_path: Path, index: int, snippet: tuple[str, str]) -> None:
    _, code = snippet
    source = tmp_path / f"readme_snippet_{index}.py"
    source.write_text(code, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--strict",
            "--python-version",
            PYTHON_VERSION,
            source.name,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"snippet {index}:\n{code}\n{result.stdout}"


@pytest.mark.parametrize(
    ("index", "code"),
    _snippets_for("exec"),
    ids=[f"snippet{index}" for index, _ in _snippets_for("exec")],
)
def test_exec_snippet_runs(index: int, code: str) -> None:
    """Executing an expression-building fence is what catches renamed fields.

    mypy cannot: ``ProtocolMeta.__getattr__`` types every protocol attribute as
    ``Any`` and ``remora.proto.__getattr__`` returns ``object``, so a stale
    field or protocol name typechecks clean and only fails at runtime.
    """
    exec(compile(code, f"<README ci:exec snippet {index}>", "exec"), {"__name__": "__main__"})


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
