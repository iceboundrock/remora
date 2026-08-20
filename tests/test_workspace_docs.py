"""docs/workspace.md's fences are CI-checked, and its constants come from the code.

The guide states rules the workspace enforces, so the parts that are lists —
the exportable tables, sessionization's prerequisite fields, the argv options
that invalidate a cache key — are checked against the code rather than trusted
to stay in sync by hand, the same treatment tests/test_semantics_docs.py gives
docs/semantics.md. The fence machinery is shared with tests/test_readme.py
(tests/docs_snippets.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

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
from remora import IP
from remora.compile.sql import compile_sql
from remora.fields import FieldRef
from remora.workspace import EXPORTABLE_TABLES, PROBE_BYTES, REQUIRED_FIELDS
from test_semantics_table import EMPTY, NULL_TRUTH_CASES

DOC = REPO_ROOT / "docs" / "workspace.md"


def _snippets() -> list[tuple[str, str]]:
    return snippets(DOC)


def _snippets_for(mode: str) -> list[tuple[int, str]]:
    return snippets_for(DOC, mode)


def test_the_doc_exists() -> None:
    assert DOC.is_file()


def test_doc_has_marked_snippets() -> None:
    modes = [mode for mode, _ in _snippets()]
    assert "run" in modes, "the guide must keep a <!-- ci:run --> quickstart fence"
    assert "exec" in modes, "the guide must keep <!-- ci:exec --> fences"


def test_every_marker_line_is_extracted() -> None:
    check_every_marker_is_extracted(DOC)


@pytest.mark.parametrize(("index", "snippet"), list(enumerate(_snippets())))
def test_marked_snippet_typechecks(tmp_path: Path, index: int, snippet: tuple[str, str]) -> None:
    _, code = snippet
    typecheck_snippet(tmp_path, "workspace_doc", index, code)


@pytest.mark.parametrize(
    ("index", "code"),
    _snippets_for("exec"),
    ids=[f"snippet{index}" for index, _ in _snippets_for("exec")],
)
def test_exec_snippet_runs(index: int, code: str) -> None:
    """Executing an expression-building fence is what catches renamed fields.

    mypy cannot: ``ProtocolMeta.__getattr__`` types every protocol attribute as
    ``Any``, so a stale field name typechecks clean and only fails at runtime.
    """
    exec_snippet(code, f"<docs/workspace.md ci:exec snippet {index}>")


@pytest.mark.integration
@requires_tshark
def test_quickstart_materializes_queries_and_exports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The quickstart runs end to end against a real tshark and a real DuckDB."""
    pytest.importorskip("duckdb")
    monkeypatch.chdir(tmp_path)
    run_snippets_in(tmp_path, DOC, "<docs/workspace.md quickstart>")
    out = capsys.readouterr().out
    # An empty run must not pass: sample.pcap holds three frames, one of which
    # is the 10.0.0.1 -> 10.0.0.2:443 SYN the query selects.
    assert "materialized 3 rows" in out
    assert "10.0.0.1" in out
    assert "51234" in out and "443" in out
    # The export is a real file, not just a returned path.
    exported = tmp_path / "pkts.parquet"
    assert exported.is_file() and exported.stat().st_size > 0
    # ...and it is Parquet, not a workspace file written to the wrong place.
    assert exported.read_bytes()[:4] == b"PAR1"


def test_the_doc_names_every_exportable_table() -> None:
    text = DOC.read_text(encoding="utf-8")
    for table in EXPORTABLE_TABLES:
        assert f'"{table}"' in text, table


def test_the_stream_prerequisite_fence_lists_exactly_the_required_fields() -> None:
    """The guide's ``STREAM_FIELDS`` fence must be the real prerequisite set.

    Not a substring check: the fence is executed and its field refs compared
    against :data:`REQUIRED_FIELDS`, so a field added to sessionization cannot
    leave the fence a step behind.
    """
    fences = [code for _, code in _snippets() if "STREAM_FIELDS" in code]
    assert len(fences) == 1, "exactly one fence should build the prerequisite set"
    namespace: dict[str, object] = {"__name__": "__main__"}
    exec(compile(fences[0], "<docs/workspace.md STREAM_FIELDS>", "exec"), namespace)
    fields = namespace["STREAM_FIELDS"]
    assert isinstance(fields, list)
    refs = cast("list[FieldRef[Any]]", fields)
    assert sorted(ref.name for ref in refs) == sorted(REQUIRED_FIELDS)


def test_the_doc_calls_out_the_easy_to_miss_cache_invalidators() -> None:
    # Issue #39's acceptance criterion: the argv options that change dissection
    # without changing the capture are the ones a reader has to be warned about.
    text = DOC.read_text(encoding="utf-8")
    for option in ("-X lua_script:", "`-d`", "`-o`"):
        assert option in text, option


def test_the_doc_states_the_real_fingerprint_probe_size() -> None:
    assert f"{PROBE_BYTES // 1024} KiB" in DOC.read_text(encoding="utf-8")


def test_the_doc_defers_to_the_enforced_semantics_document() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "docs/semantics.md" in text or "(semantics.md)" in text
    # The truth table has one home; duplicating it here would fork the contract.
    assert "absent scalar" not in text


def _flowed() -> str:
    """The guide with its line wrapping collapsed, for matching whole sentences."""
    return " ".join(DOC.read_text(encoding="utf-8").split())


def test_the_absence_summary_still_describes_the_enforced_truth_table() -> None:
    """The guide paraphrases the table it deliberately does not restate.

    Deferring to ``docs/semantics.md`` is guarded by the link and by the absent
    header, but the one sentence that *summarizes* the table is prose, and prose
    cannot be parsed against it. What is pinned instead is the shape the sentence
    claims: if the enforced truth table ever stops being uniform, this fails and
    the sentence has to be rewritten rather than quietly becoming false.
    """
    claim = "Every positive operator is False on an absent field and every negated one is True"
    assert claim in _flowed()
    for case in NULL_TRUTH_CASES:
        packet, hit = case.rows[-1]
        assert packet is EMPTY, case.id
        assert hit is case.id.startswith("not-"), case.id


def test_the_coalesce_claim_is_what_the_sql_backend_emits() -> None:
    """The doc describes the NULL harmonization; the emitter is asked to confirm it.

    Two halves, both stated in the guide and both checked here rather than
    trusted: the wrap happens **only** beneath a ``Not`` (a positive leaf keeps
    DuckDB's scan-level filter pushdown), and it happens **at the leaf** rather
    than over the subtree (a subtree wrap gets nested negation wrong). Derived
    from the real backend the way ``tests/test_semantics_docs.py`` derives its
    expected guard fragment from ``sql.py``'s own emitter.
    """
    positive = compile_sql(IP.src == "10.0.0.1")
    negated = compile_sql(~(IP.src == "10.0.0.1"))
    assert "coalesce" not in positive.sql
    assert negated.sql == f"NOT (coalesce({positive.sql}, FALSE))"
    assert "coalesce(<leaf>, FALSE)" in _flowed()


def test_the_doc_names_where_each_rule_is_enforced() -> None:
    text = DOC.read_text(encoding="utf-8")
    for path in (
        "docs/semantics.md",
        "tests/test_workspace_cachekey.py",
        "tests/test_workspace_cache.py",
        "tests/test_workspace_lifecycle.py",
        "tests/test_workspace_export.py",
        "tests/test_workspace_query.py",
        "tests/integration/test_query_parity.py",
        "tests/test_workspace_docs.py",
    ):
        assert path in text, path
        # Substring-only would leave the doc pointing at a renamed file.
        assert (REPO_ROOT / path).is_file(), path
