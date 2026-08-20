"""Shared machinery for the CI-checked code fences in Markdown docs (issues #24, #39).

Extracted from ``tests/test_readme.py`` when ``docs/workspace.md`` gained fences
of its own: one marker contract, one extractor, one mypy runner, so a second
document cannot drift into a second dialect.

Marker contract: an HTML comment line immediately before a ```python fence opts
that fence into CI. Every marked fence is typechecked; the mode says what else
happens to it.

- ``<!-- ci:typecheck -->`` — ``mypy --strict`` only. The weakest mode, and the
  fallback for a snippet that must not execute.
- ``<!-- ci:exec -->`` — typechecked AND executed in-process, with no tshark and
  no capture file. This is what catches protocol and field rot:
  ``ProtocolMeta.__getattr__`` types any attribute as ``Any`` and
  ``remora.proto.__getattr__`` returns ``object``, so mypy accepts
  ``IP.no_such_field`` and ``from remora.proto import NOSUCHPROTO`` — only
  running the snippet raises ``AttributeError``/``ImportError``.
- ``<!-- ci:run -->`` — typechecked AND executed against a real tshark
  (integration) with ``capture.pcap`` (a copy of ``tests/data/sample.pcap``) in
  the working directory.

``tests/`` is not a package, so importing this is ``from docs_snippets import
...`` — the style ``tests/test_semantics_docs.py`` already uses for
``test_semantics_table``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
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

#: Skip condition for the ``ci:run`` mode: no tshark, and no demand for one.
#: ``REMORA_REQUIRE_TSHARK`` turns the skip into a failure, so a CI job that is
#: supposed to have tshark cannot quietly stop exercising these fences.
NO_TSHARK = shutil.which(os.environ.get("TSHARK") or "tshark") is None and not os.environ.get(
    "REMORA_REQUIRE_TSHARK"
)

requires_tshark = pytest.mark.skipif(NO_TSHARK, reason="tshark not installed; skipping")


def snippets(doc: Path) -> list[tuple[str, str]]:
    """(mode, code) for every marked python fence, in document order."""
    text = doc.read_text(encoding="utf-8")
    return [(m["mode"], m["code"]) for m in _MARKED_FENCE.finditer(text)]


def snippets_for(doc: Path, mode: str) -> list[tuple[int, str]]:
    """(document-order index, code) for every fence in *mode*."""
    return [(i, code) for i, (m, code) in enumerate(snippets(doc)) if m == mode]


def marker_lines(doc: Path) -> list[str]:
    """Every ``<!-- ci:... -->`` line, whether or not it names a valid mode."""
    return _MARKER_LINE.findall(doc.read_text(encoding="utf-8"))


def check_every_marker_is_extracted(doc: Path) -> None:
    """Assert each marker line produced a snippet, so a stale marker fails loudly."""
    markers = marker_lines(doc)
    extracted = snippets(doc)
    name = doc.relative_to(REPO_ROOT).as_posix()
    assert len(extracted) == len(markers), (
        f"{len(markers)} ci: marker line(s) in {name} but "
        f"{len(extracted)} extracted snippet(s) — a marker must sit on its own "
        "line immediately above a ```python fence, and its mode must be one of "
        f"{', '.join(MODES)}"
    )


def typecheck_snippet(tmp_path: Path, stem: str, index: int, code: str) -> None:
    """Run ``mypy --strict`` over one snippet in an isolated directory."""
    source = tmp_path / f"{stem}_snippet_{index}.py"
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


def exec_snippet(code: str, label: str) -> None:
    """Execute one snippet in a fresh ``__main__``-flavoured namespace."""
    exec(compile(code, label, "exec"), {"__name__": "__main__"})


def needs_workspace(code: str) -> bool:
    """True when a fence drives the DuckDB workspace, so it needs the extra.

    ``ci:run`` fences otherwise need only tshark, and duckdb is optional
    (``remora[workspace]``) — a checkout without it must still exercise the
    fences that never touch it, so the two are selected apart rather than
    gated together.
    """
    return "remora.workspace" in code


def run_snippets_in(
    tmp_path: Path,
    doc: Path,
    label: str,
    *,
    where: Callable[[str], bool] | None = None,
) -> None:
    """Execute the ``ci:run`` fences in *doc* with a capture in the working dir.

    The caller is responsible for ``monkeypatch.chdir(tmp_path)``; this copies
    ``sample.pcap`` in as ``capture.pcap`` and runs the fences in document
    order, sharing no namespace between them. *where* selects a subset by code
    text (see :func:`needs_workspace`); omitting it runs every ``ci:run`` fence.
    """
    run_snippets = [
        code for mode, code in snippets(doc) if mode == "run" and (where is None or where(code))
    ]
    assert run_snippets, f"{doc.name} must keep a <!-- ci:run --> fence"
    shutil.copy(SAMPLE_PCAP, tmp_path / "capture.pcap")
    for code in run_snippets:
        exec_snippet(code, label)
