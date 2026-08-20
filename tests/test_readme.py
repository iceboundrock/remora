"""README code fences are CI-checked so the quickstart can never rot (issue #24).

The marker contract, the extractor and the runners live in
``tests/docs_snippets.py`` since issue #39, shared with
``tests/test_workspace_docs.py``; this file is what applies them to README.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from docs_snippets import (
    REPO_ROOT,
    check_every_marker_is_extracted,
    exec_snippet,
    requires_tshark,
    run_snippets_in,
    snippets,
    snippets_for,
    typecheck_snippet,
)

README = REPO_ROOT / "README.md"


def _snippets() -> list[tuple[str, str]]:
    return snippets(README)


def _snippets_for(mode: str) -> list[tuple[int, str]]:
    return snippets_for(README, mode)


def test_readme_has_marked_snippets() -> None:
    modes = [mode for mode, _ in _snippets()]
    assert "run" in modes, "README must keep a <!-- ci:run --> quickstart fence"
    assert "exec" in modes, "README must keep <!-- ci:exec --> fences"


def test_every_marker_line_is_extracted() -> None:
    check_every_marker_is_extracted(README)


@pytest.mark.parametrize(("index", "snippet"), list(enumerate(_snippets())))
def test_marked_snippet_typechecks(tmp_path: Path, index: int, snippet: tuple[str, str]) -> None:
    _, code = snippet
    typecheck_snippet(tmp_path, "readme", index, code)


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
    exec_snippet(code, f"<README ci:exec snippet {index}>")


@pytest.mark.integration
@requires_tshark
def test_quickstart_runs_against_sample_pcap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    run_snippets_in(tmp_path, README, "<README quickstart>")
    out = capsys.readouterr().out
    assert "10.0.0.1 443" in out
