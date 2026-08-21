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
    needs_workspace,
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
    """The tshark-only ``ci:run`` fences, which need no optional extra."""
    monkeypatch.chdir(tmp_path)
    run_snippets_in(
        tmp_path, README, "<README quickstart>", where=lambda code: not needs_workspace(code)
    )
    out = capsys.readouterr().out
    assert "10.0.0.1 443" in out


@pytest.mark.integration
@requires_tshark
def test_workspace_snippet_runs_against_sample_pcap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The workspace teaser is executed, not merely typechecked.

    ``ci:typecheck`` proves type-correctness and nothing else, which is one
    guarantee short of what this fence needs: an earlier draft called
    ``build_streams()`` after materializing three of its nine prerequisite
    fields — accepted by mypy, refused at runtime with
    ``MissingStreamFieldsError``, and copy-pasteable straight out of the
    README. Running it is what catches that class of rot.
    """
    pytest.importorskip("duckdb", reason="duckdb not installed; pip install 'remora[workspace]'")
    monkeypatch.chdir(tmp_path)
    run_snippets_in(tmp_path, README, "<README workspace>", where=needs_workspace)
    out = capsys.readouterr().out
    assert "10.0.0.1" in out
    exported = tmp_path / "pkts.parquet"
    assert exported.is_file()
    assert exported.read_bytes()[:4] == b"PAR1"
