# psdsl gen CLI Implementation Plan (issue #21)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `psdsl` console script whose `gen` subcommand runs the full dump → parse → emit → fingerprint pipeline against the *local* tshark (no version pin, no codegen.toml), writing importable, fingerprinted `.py`/`.pyi` pairs to a user-chosen directory.

**Architecture:** A thin new module `src/remora/codegen/cli.py` reuses everything from `remora.codegen.fingerprint`: `find_tshark`, `parse_tshark_version`, the `_tshark_version_output`/`_tshark_dumps` subprocess seams, `_environment_error_message`, and `generate_artifacts` (driven by an ad-hoc `CodegenConfig` built from CLI args, with `tshark_version` taken from the installed binary instead of a pin). Errors print `error: …` to stderr and exit 2 — never a traceback. The output directory is a plain (namespace-)package directory: `.pyi` beside `.py` gives IDE stub resolution for free once the parent directory is on the import path.

**Tech Stack:** Python stdlib `argparse` (subparsers so `psdsl` can grow more subcommands), hatchling `[project.scripts]` entry point, pytest with `monkeypatch` seams (no tshark needed except one integration-marked test).

## Global Constraints

- CI gate must pass: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest`.
- Python ≥3.10; no new runtime dependencies (`tomli` is already declared for py3.10).
- One PR, branch `feat/issue-21-psdsl-gen-cli`, body includes `Closes #21`.
- `cli.py` must call the subprocess seams *through the module* (`fingerprint._tshark_dumps(tshark)`, not a `from … import`), so the existing monkeypatch seams in `remora.codegen.fingerprint` govern the CLI too.
- ```python fences in docs get ruff-formatted; keep any README python fences format-clean (see memory: ruff-doc-fences-pyi-pitfall).
- Out of scope (per issue): packaging/extras layout, publishing, web service, `--multi` curation flag.

## File Structure

- Create `src/remora/codegen/cli.py` — the `psdsl` entry point; owns argv parsing and the `gen` command only.
- Create `tests/test_codegen_cli.py` — in-process smoke tests (seam-monkeypatched, no tshark) + entry-point declaration test + temp-dir import test.
- Create `tests/integration/test_psdsl_gen.py` — one end-to-end run against a real local tshark (integration-marked).
- Modify `pyproject.toml` — add `[project.scripts] psdsl = …`.
- Modify `README.md` — document `psdsl gen` and the import mechanism for generated output.

---

### Task 1: `psdsl gen` command core (`cli.py` + smoke tests)

**Files:**
- Create: `src/remora/codegen/cli.py`
- Test: `tests/test_codegen_cli.py`

**Interfaces:**
- Consumes (all from `remora.codegen.fingerprint`): `find_tshark(explicit: str | None) -> str`, `parse_tshark_version(str) -> str`, `_tshark_version_output(tshark: str) -> str`, `_tshark_dumps(tshark: str) -> tuple[str, str]`, `_environment_error_message(Exception) -> str`, `CodegenConfig`, `generate_artifacts(config, dump, *, plugins_dump) -> tuple[tuple[Artifact, ...], tuple[ParseWarning | EmitWarning, ...]]`.
- Produces: `main(argv: Sequence[str] | None = None) -> int` in `remora.codegen.cli` — Task 2's entry point target; Tasks 3–4 drive it in-process.

- [ ] **Step 1: Write the failing smoke tests**

Create `tests/test_codegen_cli.py`. Follow the seam-monkeypatch pattern of `tests/test_codegen_fingerprint.py::TestMain` exactly — the seams live in `remora.codegen.fingerprint`, and `cli.py` will call them through the module:

```python
"""Tests for the ``psdsl`` CLI (issue #21). No tshark needed outside integration."""

from __future__ import annotations

from pathlib import Path

import pytest

import remora.codegen.fingerprint as fingerprint_module
from remora.codegen.cli import main
from remora.codegen.fingerprint import parse_header

SAMPLE_DUMP = (
    "P\tUser Datagram Protocol\tudp\n"
    "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
    "F\tStream index\tudp.stream\tFT_UINT32\tudp\tBASE_DEC\t0x0\t\n"
)


@pytest.fixture
def fake_tshark(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fingerprint_module,
        "_tshark_version_output",
        lambda tshark: "TShark (Wireshark) 4.6.7 (Git).",
    )
    monkeypatch.setattr(fingerprint_module, "_tshark_dumps", lambda tshark: (SAMPLE_DUMP, ""))
    monkeypatch.setenv("TSHARK", "/usr/bin/true")


class TestGen:
    def test_writes_fingerprinted_pair(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        py = (out / "udp.py").read_text(encoding="utf-8")
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        for source in (py, pyi):
            fingerprint = parse_header(source)
            assert fingerprint is not None
            assert fingerprint.tshark_version == "4.6.7"
        captured = capsys.readouterr()
        assert "2 artifact(s)" in captured.out

    def test_creates_missing_out_dir_parents(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "a" / "b" / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        assert (out / "udp.py").is_file()

    def test_duplicate_protocols_deduplicated(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "udp", "--out", str(out)]) == 0
        assert "2 artifact(s)" in capsys.readouterr().out

    def test_unknown_protocol_exits_2(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["gen", "--protocols", "nonsense", "--out", str(tmp_path / "gen")]) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "nonsense" in captured.err
        assert not (tmp_path / "gen").exists()

    def test_missing_tshark_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = str(tmp_path / "nonexistent" / "tshark")
        argv = ["gen", "--protocols", "udp", "--out", str(tmp_path / "gen"), "--tshark", missing]
        assert main(argv) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "tshark not found" in captured.err

    def test_parse_warnings_printed_without_failing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dump = SAMPLE_DUMP + "X\tbogus record\n"
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_version_output",
            lambda tshark: "TShark (Wireshark) 4.6.7 (Git).",
        )
        monkeypatch.setattr(fingerprint_module, "_tshark_dumps", lambda tshark: (dump, ""))
        monkeypatch.setenv("TSHARK", "/usr/bin/true")
        assert main(["gen", "--protocols", "udp", "--out", str(tmp_path / "gen")]) == 0
        assert "warning:" in capsys.readouterr().err


class TestHelp:
    def test_gen_help_documents_every_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["gen", "--help"])
        assert excinfo.value.code == 0
        message = capsys.readouterr().out
        for flag in ("--tshark", "--protocols", "--out"):
            assert flag in message

    def test_top_level_help_lists_gen(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        assert "gen" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_cli.py -v`
Expected: FAIL at import time with `ModuleNotFoundError: No module named 'remora.codegen.cli'`.

- [ ] **Step 3: Implement `src/remora/codegen/cli.py`**

```python
"""The ``psdsl`` console script: local generation against the user's tshark.

Published packages can only cover protocols a stock tshark knows. Users with
plugins, Lua dissectors, or unusual protocols regenerate locally instead:
``psdsl gen`` runs the same dump → parse → emit → fingerprint pipeline as
``python -m remora.codegen write``, but against whatever tshark is installed
(no version pin, no ``codegen.toml``) and into a directory of the user's
choosing. The output directory is a plain package directory — each ``.pyi``
sits beside its ``.py``, so IDEs resolve stubs as soon as the parent directory
is on the import path (see README "Local generation").

All subprocess access goes through the seams in
:mod:`remora.codegen.fingerprint` (``_tshark_version_output``,
``_tshark_dumps``) so tests drive this CLI without a tshark binary.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from remora.codegen import fingerprint
from remora.codegen.fingerprint import (
    CodegenConfig,
    find_tshark,
    generate_artifacts,
    parse_tshark_version,
)
from remora.codegen.parse import ParseWarning


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psdsl",
        description="Remora code generation against the locally installed tshark.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    gen = subparsers.add_parser(
        "gen",
        help="generate protocol modules from the local tshark",
        description=(
            "Run the dump → parse → emit → fingerprint pipeline against the local "
            "tshark and write importable .py/.pyi pairs to the output directory."
        ),
    )
    gen.add_argument(
        "--tshark",
        default=None,
        metavar="PATH",
        help="path to the tshark binary (default: $TSHARK, then PATH, then Homebrew)",
    )
    gen.add_argument(
        "--protocols",
        nargs="+",
        required=True,
        metavar="NAME",
        help="tshark protocol abbrevs to generate (e.g. udp dns)",
    )
    gen.add_argument(
        "--out",
        default="gen",
        metavar="DIR",
        help="output directory, created if missing (default: ./gen)",
    )
    return parser


def _cmd_gen(options: argparse.Namespace) -> int:
    try:
        tshark = find_tshark(options.tshark)
        version = parse_tshark_version(fingerprint._tshark_version_output(tshark))
        fields_dump, plugins_dump = fingerprint._tshark_dumps(tshark)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {fingerprint._environment_error_message(error)}", file=sys.stderr)
        return 2

    config = CodegenConfig(
        tshark_version=version,
        protocols=tuple(dict.fromkeys(options.protocols)),
        multi=frozenset(),
    )
    try:
        artifacts, warnings = generate_artifacts(config, fields_dump, plugins_dump=plugins_dump)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        if isinstance(warning, ParseWarning):
            print(f"warning: -G fields line {warning.line_no}: {warning.message}", file=sys.stderr)
        else:
            print(f"warning: {warning.abbrev}: {warning.message}", file=sys.stderr)

    out_dir = Path(options.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        (out_dir / artifact.name).write_text(artifact.content, encoding="utf-8")
        print(f"wrote {out_dir / artifact.name}")
    print(f"wrote {len(artifacts)} artifact(s) under tshark {version}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``psdsl`` console script."""
    options = _build_parser().parse_args(argv)
    assert options.command == "gen"  # the only subcommand so far
    return _cmd_gen(options)


if __name__ == "__main__":
    raise SystemExit(main())
```

Implementation notes (why, for the reviewer):
- `fingerprint._tshark_version_output` / `fingerprint._tshark_dumps` are called *through the module* so the established monkeypatch seams work for this CLI unchanged.
- No version pin: the installed tshark's parsed version goes straight into the fingerprint header — that is the local-generation architecture decision from the issue.
- `dict.fromkeys` dedups repeated `--protocols` while preserving order; otherwise `generate_artifacts` raises a confusing "module name collides" error for `udp udp`.
- The out dir is only created after generation succeeds, so a failed run leaves nothing behind.
- The `assert` on `options.command` is unreachable (`required=True`); mypy-friendly and honest about the single subcommand.

- [ ] **Step 4: Run the tests, lint, typecheck**

Run: `uv run pytest tests/test_codegen_cli.py -v && uv run mypy --strict src tests && uv run ruff check . && uv run ruff format .`
Expected: all PASS/clean. If mypy flags the private-member accesses (`fingerprint._tshark_dumps`), they are module-internal seams used deliberately — silence is *not* needed; mypy does not flag underscore access. If ruff SLF-style rules complain (SLF is not enabled here), do not add ignores.

- [ ] **Step 5: Commit**

```bash
git add src/remora/codegen/cli.py tests/test_codegen_cli.py
git commit -m "feat(codegen): add psdsl gen CLI core for local generation"
```

---

### Task 2: `psdsl` console-script entry point

**Files:**
- Modify: `pyproject.toml` (add `[project.scripts]` after `[project.urls]`)
- Test: `tests/test_codegen_cli.py` (append)

**Interfaces:**
- Consumes: `remora.codegen.cli:main` from Task 1.
- Produces: an installed `psdsl` executable (`uv run psdsl …`).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_codegen_cli.py` (mirrors `test_pyproject_declares_tomli_as_a_runtime_dependency` in `tests/test_codegen_fingerprint.py`; add the needed imports at the top of the file: `import sys`, and the `tomllib`/`tomli` conditional import exactly as in that file):

```python
def test_pyproject_declares_psdsl_console_script() -> None:
    """The psdsl entry point must target cli.main (issue #21)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    assert data["project"]["scripts"]["psdsl"] == "remora.codegen.cli:main"
```

The conditional import block to add near the top (copy verbatim from `tests/test_codegen_fingerprint.py`):

```python
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_codegen_cli.py::test_pyproject_declares_psdsl_console_script -v`
Expected: FAIL with `KeyError: 'scripts'`.

- [ ] **Step 3: Add the entry point**

In `pyproject.toml`, after the `[project.urls]` table:

```toml
[project.scripts]
psdsl = "remora.codegen.cli:main"
```

Then re-install so the script materializes: `uv sync`.

- [ ] **Step 4: Verify test passes and the script actually runs**

Run: `uv run pytest tests/test_codegen_cli.py::test_pyproject_declares_psdsl_console_script -v`
Expected: PASS.

Run: `uv run psdsl gen --help`
Expected: exit 0, usage text listing `--tshark`, `--protocols`, `--out`.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/test_codegen_cli.py uv.lock
git commit -m "feat(codegen): register psdsl console script"
```

(Only add `uv.lock` if `uv sync` changed it.)

---

### Task 3: Import mechanism — test + README documentation

**Files:**
- Test: `tests/test_codegen_cli.py` (append)
- Modify: `README.md` (extend the codegen section around lines 60–68)

**Interfaces:**
- Consumes: `main` from Task 1; generated modules import `remora.proto._meta.ProtocolBase` at runtime.
- Produces: the documented import contract — out dir is a namespace-package directory; importable once its *parent* is on `sys.path`.

- [ ] **Step 1: Write the failing import test**

Append to `tests/test_codegen_cli.py` (add `import importlib` to the top-of-file imports; `FieldRef` comes from `remora.fields`):

```python
class TestGeneratedOutputImport:
    def test_import_from_temp_out_dir(
        self, tmp_path: Path, fake_tshark: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The documented mechanism: out dir = package dir, parent on sys.path."""
        out = tmp_path / "genproto"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        monkeypatch.syspath_prepend(str(tmp_path))
        try:
            module = importlib.import_module("genproto.udp")
            udp = module.UDP
            ref = udp.srcport == 53
            assert type(ref).__name__ == "Comparison"
            assert udp._table_["srcport"] == ("udp.srcport", "FT_UINT16", 0)
            assert (out / "udp.pyi").is_file()  # stub sits beside the module
        finally:
            sys.modules.pop("genproto.udp", None)
            sys.modules.pop("genproto", None)
```

Note: `udp.srcport == 53` builds an `Expr` via class access (`FieldRef.__eq__`); asserting the node type name avoids importing compile internals. The `finally` cleanup keeps `sys.modules` pristine for other tests (namespace package `genproto` would otherwise leak).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_codegen_cli.py::TestGeneratedOutputImport -v`
Expected: PASS is actually likely if Task 1 is correct — this test pins the *contract*, not new code. If it passes immediately, that is acceptable here (the deliverable is the pinned contract + docs); continue.

- [ ] **Step 3: Document the mechanism in README.md**

In the codegen section of `README.md` (after the `python -m remora.codegen write` paragraph, before whatever follows), add:

````markdown
### Local generation (`psdsl gen`)

The committed protocol modules only cover what a stock tshark knows. If your
tshark has plugins, Lua dissectors, or unusual protocols, generate modules
locally against *your* binary:

    uv run psdsl gen --protocols udp dns --out ./gen

`psdsl gen` runs the same dump → parse → emit → fingerprint pipeline as the
committed artifacts, but against the locally installed tshark (resolved from
`--tshark`, then `$TSHARK`, then `PATH`, then Homebrew) with no version pin —
the fingerprint header records whatever version generated the files. A missing
binary or unknown protocol name exits nonzero with a one-line error.

**Importing the output.** The output directory is a plain package directory:
each `.pyi` stub sits beside its `.py` module, so type checkers and IDEs
resolve the stubs with no extra configuration. Generate into a directory
inside your project (say `./gen`) and import it as a package — Python ≥3.3
namespace packages need no `__init__.py`:

```python
from gen.udp import UDP

query = UDP.srcport == 53
```

This works as long as the *parent* of the output directory is on the import
path — true automatically when `gen/` sits in your project root and you run
Python from there. For mypy, the same layout just works; if you generate
outside the project tree, add the parent directory to `mypy_path` (or
`MYPYPATH`) and to `sys.path` at runtime.
````

Check the python fence stays ruff-format-clean (`uv run ruff format --check .` covers docs fences in `docs/`; README fences are not auto-formatted, but keep the style consistent anyway).

- [ ] **Step 4: Run the full local gate for the files touched**

Run: `uv run pytest tests/test_codegen_cli.py -v && uv run mypy --strict src tests && uv run ruff check . && uv run ruff format --check .`
Expected: all clean.

- [ ] **Step 5: Commit**

```bash
git add tests/test_codegen_cli.py README.md
git commit -m "docs(codegen): document psdsl gen output import mechanism, pin it with a test"
```

---

### Task 4: Integration test against a real tshark

**Files:**
- Create: `tests/integration/test_psdsl_gen.py`

**Interfaces:**
- Consumes: `main` from Task 1; the skip/require pattern from `tests/integration/test_end_to_end.py` (`REMORA_REQUIRE_TSHARK` turns a skip into a hard failure in CI).

- [ ] **Step 1: Write the integration test**

```python
"""End-to-end ``psdsl gen`` against a real local tshark (issue #21)."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from pathlib import Path

import pytest

from remora.codegen.cli import main
from remora.codegen.fingerprint import parse_header

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


def test_gen_udp_produces_importable_fingerprinted_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "genproto"
    assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
    py_source = (out / "udp.py").read_text(encoding="utf-8")
    pyi_source = (out / "udp.pyi").read_text(encoding="utf-8")
    for source in (py_source, pyi_source):
        fingerprint = parse_header(source)
        assert fingerprint is not None
        assert fingerprint.dump_sha256 != ""
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        module = importlib.import_module("genproto.udp")
        assert "srcport" in module.UDP._table_
    finally:
        sys.modules.pop("genproto.udp", None)
        sys.modules.pop("genproto", None)


def test_gen_unknown_protocol_fails_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["gen", "--protocols", "remora-no-such-proto", "--out", str(tmp_path / "gen")]
    )
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "remora-no-such-proto" in captured.err
```

- [ ] **Step 2: Run it (needs local tshark; skips gracefully otherwise)**

Run: `uv run pytest tests/integration/test_psdsl_gen.py -v`
Expected: PASS with a real tshark installed (this machine has one — the dfilter validation suite uses it), or SKIP without.

- [ ] **Step 3: Run the whole suite fast path to check nothing regressed**

Run: `uv run pytest -m "not integration"` then `uv run pytest`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_psdsl_gen.py
git commit -m "test(codegen): psdsl gen integration run against real tshark"
```

---

### Task 5: Final gate + PR

- [ ] **Step 1: Full CI gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all four clean.

- [ ] **Step 2: Push branch and open PR**

```bash
git push -u origin feat/issue-21-psdsl-gen-cli
gh pr create --title "codegen: implement psdsl gen CLI for local generation" --body "$(cat <<'EOF'
Closes #21

## Summary
- `psdsl` console script (`[project.scripts]`) with a `gen` subcommand: full dump → parse → emit → fingerprint pipeline against the *local* tshark — no version pin, no codegen.toml
- reuses the `remora.codegen.fingerprint` machinery (`find_tshark`, version parsing, subprocess seams, `generate_artifacts`); errors exit 2 with a one-line `error:` message, never a traceback
- output dir is a plain namespace-package directory (`.pyi` beside `.py` → IDE stub resolution for free); mechanism documented in README and pinned by a temp-dir import test
- in-process smoke tests via the established monkeypatch seams; one integration-marked end-to-end test against a real tshark

## Test plan
- [ ] `uv run pytest` (includes `tests/test_codegen_cli.py`, `tests/integration/test_psdsl_gen.py`)
- [ ] `uv run mypy --strict src tests`, `uv run ruff check .`, `uv run ruff format --check .`
- [ ] `uv run psdsl gen --protocols udp --out /tmp/gen-check` by hand

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Notes

- **AC 1** (importable fingerprinted pair from local tshark): Task 1 smoke + Task 4 integration.
- **AC 2** (missing tshark / unknown protocol → nonzero, no traceback): Task 1 `test_missing_tshark_exits_2`, `test_unknown_protocol_exits_2`; Task 4 real-tshark unknown-protocol test.
- **AC 3** (`--help` documents every flag; in-process smoke test): Task 1 `TestHelp` + `TestGen` (all drive `main()` in-process).
- **AC 4** (import mechanism documented + temp-dir import test): Task 3.
- Type consistency: `main(argv: Sequence[str] | None = None) -> int` is used identically in Tasks 1–4; seams are always accessed as `fingerprint.<name>`.
