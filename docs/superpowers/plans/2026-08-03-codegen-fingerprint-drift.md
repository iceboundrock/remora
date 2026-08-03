# Codegen Fingerprint + CI Drift Check Implementation Plan (issue #16)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every generated protocol artifact carries a provenance fingerprint header, one documented command verifies committed artifacts against a pinned-toolchain regeneration, and a CI job fails with a readable diff on drift.

**Architecture:** `src/remora/codegen/fingerprint.py` gets four layers, each pure and unit-testable with synthetic inputs: (1) the `Fingerprint` value + header render/parse/attach, (2) `codegen.toml` config loading (the single source of truth for the pinned tshark version, the generated protocol list, and the multi-field set), (3) `generate_artifacts`/`check_artifacts` composing the existing `parse_fields_dump` + `emit_protocol` pipeline with headers and diffing against `src/remora/proto/`, (4) a `python -m remora.codegen.fingerprint {check,write}` driver that is the only place tshark subprocesses are spawned. A new CI job installs tshark from the wireshark-dev/stable PPA and runs `check`; the check command itself enforces the version pin.

**Tech Stack:** Python stdlib (`hashlib`, `difflib`, `argparse`, `tomllib` with `tomli` backport for 3.10), existing `remora.codegen` modules, GitHub Actions.

## Global Constraints

- CI gate before every commit claim of "done": `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest -m "not integration"` (full `uv run pytest` before the PR).
- Ruff line length is 100; `E`/`W` are selected, so no emitted or source line may exceed 100 chars (the 64-hex sha256 must sit on its own header line).
- Python floor is 3.10: `tomllib` is 3.11+, so use the `tomli` backport behind a `sys.version_info` guard; add `tomli>=2.0; python_version < '3.11'` to the `dev` dependency group.
- Pinned tshark version is **4.6.6** (what ppa:wireshark-dev/stable ships for ubuntu-latest/noble as of 2026-08; local Homebrew tshark is 4.6.7, so the local `check` command will correctly refuse with a version-mismatch message — that is by design, not a bug).
- `codegen.toml` at the repo root is the ONLY place the pinned version appears (CI consumes it through the check command; docs point at the file). Do not hardcode 4.6.6 anywhere else — not in ci.yml, not in README prose.
- `emit.py` stays pure and untouched; headers are attached by `fingerprint.py`.
- Seed modules under `src/remora/proto/` carry no fingerprint header and must be ignored by the checker (they are replaced by #19, not by this issue).
- With `protocols = []` in `codegen.toml` (the state this PR lands in), `check` must exit 0 reporting zero artifacts checked.
- Branch `feat/issue-16-fingerprint-drift`, one PR, body includes `Closes #16`. TDD: write the failing test first for every behavior.
- All tests in `tests/test_codegen_fingerprint.py` must run without any tshark binary (synthetic inputs; subprocess calls monkeypatched).

---

### Task 1: Fingerprint value + header render/parse/attach

**Files:**
- Create: `src/remora/codegen/fingerprint.py`
- Test: `tests/test_codegen_fingerprint.py`
- Branch setup: `git checkout -b feat/issue-16-fingerprint-drift` (from up-to-date `main`)

**Interfaces:**
- Consumes: `remora.__version__` (exists, `"0.1.0"`).
- Produces (later tasks rely on these exact names):
  - `GENERATOR: str` — `f"remora {__version__}"`
  - `@dataclass(frozen=True) Fingerprint(tshark_version: str, dump_sha256: str, env: str, generator: str)`
  - `summarize_env(plugins_dump: str) -> str`
  - `make_fingerprint(dump: str, *, tshark_version: str, plugins_dump: str = "", generator: str = GENERATOR) -> Fingerprint`
  - `render_header(fp: Fingerprint) -> str` (five `#` lines, `\n`-joined, trailing `\n`)
  - `parse_header(source: str) -> Fingerprint | None`
  - `add_header(source: str, fp: Fingerprint) -> str`

The header format (frozen, version-tagged):

```
# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: <64 lowercase hex>
# env: plugins=none
# generator: remora 0.1.0
```

`add_header` prepends the header plus one blank line, so a generated `.py` starts with the header block, a blank line, then its module docstring (comments before a docstring are legal; the docstring stays the first *statement*).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_codegen_fingerprint.py`:

```python
"""Tests for the fingerprint header + drift check (issue #16). No tshark needed."""

from __future__ import annotations

from remora.codegen.fingerprint import (
    Fingerprint,
    add_header,
    make_fingerprint,
    parse_header,
    render_header,
    summarize_env,
)

SAMPLE_DUMP = (
    "P\tUser Datagram Protocol\tudp\n"
    "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
    "F\tStream index\tudp.stream\tFT_UINT32\tudp\tBASE_DEC\t0x0\t\n"
)


def fp(**overrides: str) -> Fingerprint:
    base: dict[str, str] = {
        "tshark_version": "4.6.6",
        "dump_sha256": "ab" * 32,
        "env": "plugins=none",
        "generator": "remora 0.1.0",
    }
    base.update(overrides)
    return Fingerprint(**base)


class TestFingerprintValue:
    def test_make_fingerprint_hashes_dump(self) -> None:
        import hashlib

        result = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        assert result.tshark_version == "4.6.6"
        assert result.dump_sha256 == hashlib.sha256(SAMPLE_DUMP.encode()).hexdigest()
        assert result.env == "plugins=none"
        assert result.generator.startswith("remora ")

    def test_changes_when_dump_changes(self) -> None:
        a = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        b = make_fingerprint(SAMPLE_DUMP + "X", tshark_version="4.6.6")
        assert a != b
        assert render_header(a) != render_header(b)

    def test_changes_when_tshark_version_changes(self) -> None:
        a = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        b = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.7")
        assert a != b
        assert render_header(a) != render_header(b)

    def test_env_summary(self) -> None:
        assert summarize_env("") == "plugins=none"
        assert summarize_env("   \n") == "plugins=none"
        hashed = summarize_env("mate 1.0 codec\n")
        assert hashed.startswith("plugins=sha256:")
        assert len(hashed) == len("plugins=sha256:") + 12
        assert summarize_env("other\n") != hashed


class TestHeader:
    def test_render_shape(self) -> None:
        header = render_header(fp())
        lines = header.splitlines()
        assert lines[0] == "# remora-fingerprint: v1"
        assert lines[1] == "# tshark: 4.6.6"
        assert lines[2] == f"# dump-sha256: {'ab' * 32}"
        assert lines[3] == "# env: plugins=none"
        assert lines[4] == "# generator: remora 0.1.0"
        assert header.endswith("\n")
        assert all(len(line) <= 100 for line in lines)

    def test_parse_round_trip(self) -> None:
        original = fp()
        source = add_header('"""Doc."""\n\nX = 1\n', original)
        assert parse_header(source) == original

    def test_add_header_keeps_source_and_blank_line(self) -> None:
        source = add_header('"""Doc."""\n\nX = 1\n', fp())
        assert source.endswith('"""Doc."""\n\nX = 1\n')
        lines = source.splitlines()
        assert lines[5] == ""
        assert lines[6] == '"""Doc."""'

    def test_parse_header_absent(self) -> None:
        assert parse_header('"""A seed module without a header."""\n') is None
        assert parse_header("") is None

    def test_parse_header_malformed(self) -> None:
        broken = "# remora-fingerprint: v1\n# tshark: 4.6.6\n"
        assert parse_header(broken) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: FAIL at import — `ModuleNotFoundError: No module named 'remora.codegen.fingerprint'`

- [ ] **Step 3: Write the implementation**

Create `src/remora/codegen/fingerprint.py`:

```python
"""Fingerprint headers for generated artifacts and the drift check (issue #16).

The field dictionary is a function of the local tshark build, enabled
plugins, and Lua scripts. Generated artifacts are committed to VCS, so every
generated file carries a provenance header:

    # remora-fingerprint: v1
    # tshark: 4.6.6
    # dump-sha256: <sha256 of the ``tshark -G fields`` dump, 64 hex>
    # env: plugins=none | plugins=sha256:<12 hex of the -G plugins dump>
    # generator: remora <version>

``python -m remora.codegen.fingerprint check`` regenerates everything named
by ``codegen.toml`` under the pinned tshark and diffs against the committed
files; ``write`` regenerates in place. Seed modules carry no header and are
ignored. Only :func:`main` spawns tshark — everything else is pure and takes
dump text, so tests need no tshark binary.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from remora import __version__

GENERATOR = f"remora {__version__}"

_HEADER_VERSION_LINE = "# remora-fingerprint: v1"
_HEADER_FIELDS = ("tshark", "dump-sha256", "env", "generator")


@dataclass(frozen=True)
class Fingerprint:
    """Provenance of one generated artifact (see module docs for the header)."""

    tshark_version: str
    dump_sha256: str
    env: str
    generator: str


def summarize_env(plugins_dump: str) -> str:
    """Summarize a ``tshark -G plugins`` dump: ``plugins=none`` or a short hash."""
    stripped = plugins_dump.strip()
    if not stripped:
        return "plugins=none"
    digest = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:12]
    return f"plugins=sha256:{digest}"


def make_fingerprint(
    dump: str,
    *,
    tshark_version: str,
    plugins_dump: str = "",
    generator: str = GENERATOR,
) -> Fingerprint:
    """Fingerprint a ``tshark -G fields`` dump plus its toolchain environment."""
    return Fingerprint(
        tshark_version=tshark_version,
        dump_sha256=hashlib.sha256(dump.encode("utf-8")).hexdigest(),
        env=summarize_env(plugins_dump),
        generator=generator,
    )


def render_header(fp: Fingerprint) -> str:
    """Render the five-line comment header, trailing newline included."""
    return (
        f"{_HEADER_VERSION_LINE}\n"
        f"# tshark: {fp.tshark_version}\n"
        f"# dump-sha256: {fp.dump_sha256}\n"
        f"# env: {fp.env}\n"
        f"# generator: {fp.generator}\n"
    )


def add_header(source: str, fp: Fingerprint) -> str:
    """Prepend the fingerprint header (plus a blank separator line) to a source."""
    return f"{render_header(fp)}\n{source}"


def parse_header(source: str) -> Fingerprint | None:
    """Read a fingerprint back out of a generated file; None if absent/malformed."""
    lines = source.splitlines()
    if len(lines) < 5 or lines[0] != _HEADER_VERSION_LINE:
        return None
    values: list[str] = []
    for name, line in zip(_HEADER_FIELDS, lines[1:5]):
        prefix = f"# {name}: "
        if not line.startswith(prefix):
            return None
        values.append(line[len(prefix) :])
    return Fingerprint(
        tshark_version=values[0], dump_sha256=values[1], env=values[2], generator=values[3]
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean. (If `ruff format --check` complains about the new files, run `uv run ruff format src/remora/codegen/fingerprint.py tests/test_codegen_fingerprint.py` and re-check.)

- [ ] **Step 6: Commit**

```bash
git add src/remora/codegen/fingerprint.py tests/test_codegen_fingerprint.py
git commit -m "codegen: add fingerprint value and generated-file header (#16)"
```

---

### Task 2: `codegen.toml` + config loader

**Files:**
- Create: `codegen.toml` (repo root)
- Modify: `src/remora/codegen/fingerprint.py` (append config section)
- Modify: `pyproject.toml` (dev group: add `tomli>=2.0; python_version < '3.11'`)
- Test: `tests/test_codegen_fingerprint.py` (append)

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) CodegenConfig(tshark_version: str, protocols: tuple[str, ...], multi: frozenset[str])`
  - `load_config(path: Path) -> CodegenConfig` — raises `ValueError` with a readable message on missing keys or wrong types; `FileNotFoundError` propagates naturally.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_codegen_fingerprint.py` (add `from pathlib import Path` and `import pytest` to the imports, plus `CodegenConfig` and `load_config` to the `fingerprint` import list):

```python
class TestLoadConfig:
    def test_load(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n\n'
            '[generate]\nprotocols = ["udp", "dns"]\nmulti = ["dns.qry.name"]\n',
            encoding="utf-8",
        )
        config = load_config(config_file)
        assert config == CodegenConfig(
            tshark_version="4.6.6", protocols=("udp", "dns"), multi=frozenset({"dns.qry.name"})
        )

    def test_missing_version_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text('[generate]\nprotocols = []\nmulti = []\n', encoding="utf-8")
        with pytest.raises(ValueError, match=r"\[tshark\] version"):
            load_config(config_file)

    def test_wrong_type_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = "udp"\nmulti = []\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="protocols"):
            load_config(config_file)

    def test_repo_config_is_loadable_and_empty(self) -> None:
        config = load_config(Path(__file__).parent.parent / "codegen.toml")
        assert config.tshark_version
        assert config.protocols == ()
        assert config.multi == frozenset()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: new tests FAIL with ImportError (`CodegenConfig`).

- [ ] **Step 3: Add the tomli dev dependency**

In `pyproject.toml`, `[dependency-groups]` dev list, add the line `"tomli>=2.0; python_version < '3.11'",` then run `uv sync`.

- [ ] **Step 4: Write the implementation**

Append to `src/remora/codegen/fingerprint.py`. Extend the module imports: `import sys`, `from pathlib import Path`, and the guarded toml import right after the stdlib imports:

```python
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
```

Then the config section:

```python
@dataclass(frozen=True)
class CodegenConfig:
    """Parsed ``codegen.toml``: the one place the generation toolchain is pinned."""

    tshark_version: str
    protocols: tuple[str, ...]
    multi: frozenset[str]


def _str_list(raw: object, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"codegen.toml: {where} must be a list of strings")
    return tuple(raw)


def load_config(path: Path) -> CodegenConfig:
    """Load ``codegen.toml``; raise ValueError with a readable message if invalid."""
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    version = data.get("tshark", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("codegen.toml: [tshark] version must be a non-empty string")
    generate = data.get("generate", {})
    return CodegenConfig(
        tshark_version=version,
        protocols=_str_list(generate.get("protocols", []), "[generate] protocols"),
        multi=frozenset(_str_list(generate.get("multi", []), "[generate] multi")),
    )
```

Create `codegen.toml` at the repo root:

```toml
# Single source of truth for the generated-artifact toolchain (issue #16).
#
# CI consumes this file through `python -m remora.codegen.fingerprint check`;
# docs point here. The pinned tshark version appears nowhere else.

[tshark]
# Pinned tshark: the version ppa:wireshark-dev/stable ships for ubuntu-latest.
# Bumping it requires regenerating all committed artifacts (`... fingerprint write`).
version = "4.6.6"

[generate]
# tshark protocol abbrevs generated and committed under src/remora/proto/.
# Populated by issue #19; empty means the drift check trivially passes.
protocols = []
# tshark field abbrevs that are multi-valued (`-G fields` has no multiplicity
# signal, so this set is curated by hand).
multi = []
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean. mypy on 3.10 settings type-checks the `tomli` branch — `uv sync` from Step 3 must have installed it.

- [ ] **Step 7: Commit**

```bash
git add codegen.toml pyproject.toml uv.lock src/remora/codegen/fingerprint.py tests/test_codegen_fingerprint.py
git commit -m "codegen: add codegen.toml pinned-toolchain config and loader (#16)"
```

---

### Task 3: `generate_artifacts` + `check_artifacts`

**Files:**
- Modify: `src/remora/codegen/fingerprint.py` (append)
- Test: `tests/test_codegen_fingerprint.py` (append)

**Interfaces:**
- Consumes: `parse_fields_dump` (from `remora.codegen.parse`), `emit_protocol` (from `remora.codegen.emit`), Task 1's `make_fingerprint`/`add_header`/`parse_header`, Task 2's `CodegenConfig`.
- Produces:
  - `@dataclass(frozen=True) Artifact(name: str, content: str)` — `name` is the bare filename (`udp.py` / `udp.pyi`) under the proto dir.
  - `generate_artifacts(config: CodegenConfig, dump: str, *, plugins_dump: str = "") -> tuple[tuple[Artifact, ...], tuple[EmitWarning, ...]]` — raises `ValueError` naming any config protocol absent from the dump; fingerprint's `tshark_version` comes from `config.tshark_version`.
  - `check_artifacts(artifacts: Sequence[Artifact], proto_dir: Path) -> CheckReport` with `@dataclass(frozen=True) CheckReport(ok: bool, messages: tuple[str, ...])` — messages carry missing-file notices, unified diffs for drifted files, and orphan notices (fingerprinted files on disk not produced by the current config); headerless files (seeds, `_meta.py`, `__init__.py`) are ignored.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_codegen_fingerprint.py` (extend the `fingerprint` import list with `Artifact`, `CheckReport`, `check_artifacts`, `generate_artifacts`):

```python
def _config(**overrides: object) -> CodegenConfig:
    base: dict[str, object] = {
        "tshark_version": "4.6.6",
        "protocols": ("udp",),
        "multi": frozenset(),
    }
    base.update(overrides)
    return CodegenConfig(**base)  # type: ignore[arg-type]


class TestGenerateArtifacts:
    def test_generates_headered_pair_per_protocol(self) -> None:
        artifacts, warnings = generate_artifacts(_config(), SAMPLE_DUMP)
        assert warnings == ()
        assert [a.name for a in artifacts] == ["udp.py", "udp.pyi"]
        for artifact in artifacts:
            header = parse_header(artifact.content)
            assert header is not None
            assert header.tshark_version == "4.6.6"
        py = artifacts[0].content
        assert '"srcport": ("udp.srcport", "FT_UINT16", 0),' in py
        assert '"stream": ("udp.stream", "FT_UINT32", 0),' in py

    def test_multi_flag_flows_through(self) -> None:
        artifacts, _ = generate_artifacts(_config(multi=frozenset({"udp.stream"})), SAMPLE_DUMP)
        assert '"stream": ("udp.stream", "FT_UINT32", 1),' in artifacts[0].content
        assert "stream: MultiField[int]" in artifacts[1].content

    def test_unknown_protocol_raises(self) -> None:
        with pytest.raises(ValueError, match="nope"):
            generate_artifacts(_config(protocols=("nope",)), SAMPLE_DUMP)

    def test_empty_config_generates_nothing(self) -> None:
        artifacts, warnings = generate_artifacts(_config(protocols=()), SAMPLE_DUMP)
        assert artifacts == ()
        assert warnings == ()

    def test_deterministic(self) -> None:
        assert generate_artifacts(_config(), SAMPLE_DUMP) == generate_artifacts(
            _config(), SAMPLE_DUMP
        )


class TestCheckArtifacts:
    def _write_all(self, proto_dir: Path, artifacts: tuple[Artifact, ...]) -> None:
        proto_dir.mkdir(exist_ok=True)
        for artifact in artifacts:
            (proto_dir / artifact.name).write_text(artifact.content, encoding="utf-8")

    def test_in_sync(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        report = check_artifacts(artifacts, tmp_path)
        assert report == CheckReport(ok=True, messages=())

    def test_drift_produces_readable_diff(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        stale = (tmp_path / "udp.py").read_text(encoding="utf-8").replace(
            '"FT_UINT16"', '"FT_UINT32"'
        )
        (tmp_path / "udp.py").write_text(stale, encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        joined = "\n".join(report.messages)
        assert "udp.py" in joined
        assert "-" in joined and "+" in joined
        assert "FT_UINT16" in joined and "FT_UINT32" in joined

    def test_missing_file_reported(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        (tmp_path / "udp.pyi").unlink()
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        assert any("udp.pyi" in m and "missing" in m for m in report.messages)

    def test_orphan_fingerprinted_file_reported(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        orphan = add_header('"""Stale."""\n', fp())
        (tmp_path / "old.py").write_text(orphan, encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        assert any("old.py" in m and "orphan" in m for m in report.messages)

    def test_headerless_seed_files_ignored(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        (tmp_path / "eth.py").write_text('"""Seed, no header."""\n', encoding="utf-8")
        (tmp_path / "__init__.py").write_text("", encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert report.ok
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: FAIL with ImportError (`Artifact`).

- [ ] **Step 3: Write the implementation**

Append to `src/remora/codegen/fingerprint.py`. New imports: `import difflib`, `from collections.abc import Sequence`, `from remora.codegen.emit import EmitWarning, emit_protocol`, `from remora.codegen.parse import parse_fields_dump`.

```python
@dataclass(frozen=True)
class Artifact:
    """One generated file: bare filename under the proto dir, full content."""

    name: str
    content: str


@dataclass(frozen=True)
class CheckReport:
    """Outcome of a drift check: ok, or messages (notices and unified diffs)."""

    ok: bool
    messages: tuple[str, ...]


def generate_artifacts(
    config: CodegenConfig, dump: str, *, plugins_dump: str = ""
) -> tuple[tuple[Artifact, ...], tuple[EmitWarning, ...]]:
    """Emit fingerprinted ``.py``/``.pyi`` pairs for every configured protocol.

    Raises ValueError if a configured protocol abbrev is not in the dump.
    """
    dictionary = parse_fields_dump(dump)
    fingerprint = make_fingerprint(
        dump, tshark_version=config.tshark_version, plugins_dump=plugins_dump
    )
    by_abbrev = {protocol.abbrev: protocol for protocol in dictionary.protocols}
    artifacts: list[Artifact] = []
    warnings: list[EmitWarning] = []
    for abbrev in config.protocols:
        protocol = by_abbrev.get(abbrev)
        if protocol is None:
            raise ValueError(f"protocol {abbrev!r} not found in the -G fields dump")
        fields = [field for field in dictionary.fields if field.parent == abbrev]
        module = emit_protocol(protocol, fields, config.multi)
        artifacts.append(Artifact(f"{module.module_name}.py", add_header(module.py_source, fingerprint)))
        artifacts.append(Artifact(f"{module.module_name}.pyi", add_header(module.pyi_source, fingerprint)))
        warnings.extend(module.warnings)
    return tuple(artifacts), tuple(warnings)


def check_artifacts(artifacts: Sequence[Artifact], proto_dir: Path) -> CheckReport:
    """Diff freshly generated artifacts against the committed files in ``proto_dir``.

    Reports missing files, drifted files (as unified diffs), and orphans —
    fingerprinted files on disk that the current config no longer generates.
    Files without a fingerprint header (hand-written seeds, ``_meta.py``,
    ``__init__.py``) are ignored.
    """
    messages: list[str] = []
    expected = {artifact.name for artifact in artifacts}
    for artifact in artifacts:
        path = proto_dir / artifact.name
        if not path.is_file():
            messages.append(f"{artifact.name}: missing (regenerate with the write command)")
            continue
        committed = path.read_text(encoding="utf-8")
        if committed == artifact.content:
            continue
        diff = difflib.unified_diff(
            committed.splitlines(keepends=True),
            artifact.content.splitlines(keepends=True),
            fromfile=f"committed/{artifact.name}",
            tofile=f"regenerated/{artifact.name}",
        )
        messages.append("".join(diff))
    for path in sorted(proto_dir.iterdir()):
        if path.suffix not in {".py", ".pyi"} or path.name in expected or not path.is_file():
            continue
        if parse_header(path.read_text(encoding="utf-8")) is not None:
            messages.append(
                f"{path.name}: orphan fingerprinted artifact not produced by codegen.toml"
            )
    return CheckReport(ok=not messages, messages=tuple(messages))
```

Note: the two `artifacts.append(...)` lines exceed 100 columns as written above — wrap them:

```python
        artifacts.append(
            Artifact(f"{module.module_name}.py", add_header(module.py_source, fingerprint))
        )
        artifacts.append(
            Artifact(f"{module.module_name}.pyi", add_header(module.pyi_source, fingerprint))
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean

- [ ] **Step 6: Commit**

```bash
git add src/remora/codegen/fingerprint.py tests/test_codegen_fingerprint.py
git commit -m "codegen: generate fingerprinted artifacts and diff against committed tree (#16)"
```

---

### Task 4: `python -m remora.codegen.fingerprint {check,write}` driver

**Files:**
- Modify: `src/remora/codegen/fingerprint.py` (append `main` + `__main__` guard at the very end)
- Test: `tests/test_codegen_fingerprint.py` (append)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `parse_tshark_version(version_output: str) -> str` — extracts `4.6.6` from the first line of `tshark --version` (`TShark (Wireshark) 4.6.6 (...)`); raises `ValueError` if unrecognizable.
  - `find_tshark(explicit: str | None = None) -> str` — resolution order: explicit arg, `$TSHARK`, `shutil.which("tshark")`, `/opt/homebrew/bin/tshark`; raises `SystemExit` with a readable message if none exists (mirrors `tests/data/make_g_fields_sample.py`).
  - `main(argv: Sequence[str] | None = None) -> int` — exit 0 in sync / written, 1 on drift, 2 on environment errors (tshark missing, version != pin, bad config, unknown protocol). Subcommands `check` and `write`; flags `--config` (default `codegen.toml`), `--proto-dir` (default `src/remora/proto`), `--tshark PATH`.
  - tshark is invoked ONLY inside `_tshark_environment(tshark: str) -> tuple[str, str, str]` (returns `(version_output, fields_dump, plugins_dump)`) so tests monkeypatch that one function.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_codegen_fingerprint.py` (extend imports with `main`, `parse_tshark_version`; add `import remora.codegen.fingerprint as fingerprint_module` and `from collections.abc import Callable` if needed):

```python
class TestParseTsharkVersion:
    def test_release_line(self) -> None:
        line = "TShark (Wireshark) 4.6.6 (Git commit b439fb7b47a9)."
        assert parse_tshark_version(line) == "4.6.6"

    def test_distro_line(self) -> None:
        line = "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).\nmore"
        assert parse_tshark_version(line) == "4.2.2"

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError, match="version"):
            parse_tshark_version("not tshark output")


class TestMain:
    def _prepare(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        reported_version: str = "4.6.6",
        dump: str = SAMPLE_DUMP,
    ) -> tuple[Path, Path]:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = ["udp"]\nmulti = []\n',
            encoding="utf-8",
        )
        proto_dir = tmp_path / "proto"
        proto_dir.mkdir()
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_environment",
            lambda tshark: (f"TShark (Wireshark) {reported_version} (Git).", dump, ""),
        )
        monkeypatch.setenv("TSHARK", "/usr/bin/true")
        return config_file, proto_dir

    def _argv(self, command: str, config_file: Path, proto_dir: Path) -> list[str]:
        return [command, "--config", str(config_file), "--proto-dir", str(proto_dir)]

    def test_write_then_check_in_sync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        assert (proto_dir / "udp.py").is_file()
        assert (proto_dir / "udp.pyi").is_file()
        assert main(self._argv("check", config_file, proto_dir)) == 0
        assert "2" in capsys.readouterr().out  # "... 2 artifact(s) in sync"

    def test_check_reports_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        stale = (proto_dir / "udp.py").read_text(encoding="utf-8") + "# stale\n"
        (proto_dir / "udp.py").write_text(stale, encoding="utf-8")
        assert main(self._argv("check", config_file, proto_dir)) == 1
        captured = capsys.readouterr()
        assert "udp.py" in captured.err
        assert "# stale" in captured.err

    def test_version_mismatch_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch, reported_version="4.6.7")
        assert main(self._argv("check", config_file, proto_dir)) == 2
        captured = capsys.readouterr()
        assert "4.6.7" in captured.err
        assert "4.6.6" in captured.err

    def test_empty_config_passes_trivially(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = []\nmulti = []\n',
            encoding="utf-8",
        )
        assert main(self._argv("check", config_file, proto_dir)) == 0
        assert "0" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: FAIL with ImportError (`main`).

- [ ] **Step 3: Write the implementation**

Append to `src/remora/codegen/fingerprint.py`. New imports: `import argparse`, `import os`, `import re`, `import shutil`, `import subprocess`.

```python
_VERSION_RE = re.compile(r"^TShark \(Wireshark\) (\d+\.\d+\.\d+)", re.MULTILINE)


def parse_tshark_version(version_output: str) -> str:
    """Extract ``X.Y.Z`` from ``tshark --version`` output; ValueError if absent."""
    match = _VERSION_RE.search(version_output)
    if match is None:
        raise ValueError(f"cannot find a tshark version in: {version_output.splitlines()[:1]!r}")
    return match.group(1)


def find_tshark(explicit: str | None = None) -> str:
    """Resolve tshark: explicit path, then $TSHARK, then PATH, then Homebrew."""
    candidate = (
        explicit
        or os.environ.get("TSHARK")
        or shutil.which("tshark")
        or "/opt/homebrew/bin/tshark"
    )
    if not Path(candidate).is_file():
        raise SystemExit(
            f"error: tshark not found at {candidate!r}; install tshark "
            "or point the TSHARK environment variable at the binary"
        )
    return candidate


def _tshark_environment(tshark: str) -> tuple[str, str, str]:
    """Run tshark once each for version, fields dump, and plugins dump."""

    def run(*args: str) -> str:
        return subprocess.run(
            [tshark, *args], check=True, capture_output=True, text=True
        ).stdout

    return run("--version"), run("-G", "fields"), run("-G", "plugins")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m remora.codegen.fingerprint`` (see module docs)."""
    parser = argparse.ArgumentParser(
        prog="python -m remora.codegen.fingerprint",
        description="Check or regenerate fingerprinted protocol artifacts.",
    )
    parser.add_argument("command", choices=("check", "write"))
    parser.add_argument("--config", default="codegen.toml", help="path to codegen.toml")
    parser.add_argument("--proto-dir", default="src/remora/proto", help="artifact directory")
    parser.add_argument("--tshark", default=None, help="path to the tshark binary")
    options = parser.parse_args(argv)

    try:
        config = load_config(Path(options.config))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    version_output, fields_dump, plugins_dump = _tshark_environment(find_tshark(options.tshark))
    installed = parse_tshark_version(version_output)
    if installed != config.tshark_version:
        print(
            f"error: installed tshark {installed} does not match the pinned "
            f"{config.tshark_version} in {options.config}; install the pinned version "
            "or update the pin and regenerate every artifact",
            file=sys.stderr,
        )
        return 2

    try:
        artifacts, warnings = generate_artifacts(config, fields_dump, plugins_dump=plugins_dump)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"warning: {warning.abbrev}: {warning.message}", file=sys.stderr)

    proto_dir = Path(options.proto_dir)
    if options.command == "write":
        for artifact in artifacts:
            (proto_dir / artifact.name).write_text(artifact.content, encoding="utf-8")
            print(f"wrote {proto_dir / artifact.name}")
        print(f"wrote {len(artifacts)} artifact(s)")
        return 0

    report = check_artifacts(artifacts, proto_dir)
    if not report.ok:
        for message in report.messages:
            print(message, file=sys.stderr)
        print(
            f"error: {len(report.messages)} artifact problem(s); regenerate with "
            f"`uv run python -m remora.codegen.fingerprint write` under tshark "
            f"{config.tshark_version}",
            file=sys.stderr,
        )
        return 1
    print(f"codegen artifacts in sync ({len(artifacts)} artifact(s) checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_fingerprint.py -v`
Expected: all PASS

- [ ] **Step 5: Smoke-test the real command (local tshark is 4.6.7, pin is 4.6.6 — expect the version-mismatch refusal)**

Run: `uv run python -m remora.codegen.fingerprint check; echo "exit=$?"`
Expected: stderr contains `installed tshark 4.6.7 does not match the pinned 4.6.6`, exit=2. This confirms the guard works end-to-end.

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean

- [ ] **Step 7: Commit**

```bash
git add src/remora/codegen/fingerprint.py tests/test_codegen_fingerprint.py
git commit -m "codegen: add check/write drift command driving pinned tshark (#16)"
```

---

### Task 5: Public re-exports + documentation

**Files:**
- Modify: `src/remora/codegen/__init__.py`
- Modify: `README.md` (add a "Generated artifacts & drift check" section — read the README first and match its tone/structure)
- Test: `tests/test_codegen_fingerprint.py` (append one import-surface test)

**Interfaces:**
- Produces: `remora.codegen` re-exports `Artifact`, `CheckReport`, `CodegenConfig`, `Fingerprint`, `add_header`, `check_artifacts`, `generate_artifacts`, `load_config`, `make_fingerprint`, `parse_header`, `render_header` (driver-only helpers `main`/`find_tshark`/`parse_tshark_version`/`summarize_env`/`GENERATOR` stay module-level).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_codegen_fingerprint.py`:

```python
def test_codegen_package_reexports() -> None:
    import remora.codegen as codegen

    for name in (
        "Artifact",
        "CheckReport",
        "CodegenConfig",
        "Fingerprint",
        "add_header",
        "check_artifacts",
        "generate_artifacts",
        "load_config",
        "make_fingerprint",
        "parse_header",
        "render_header",
    ):
        assert name in codegen.__all__
        assert getattr(codegen, name) is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_codegen_fingerprint.py::test_codegen_package_reexports -v`
Expected: FAIL (`Artifact` not in `__all__`)

- [ ] **Step 3: Update `src/remora/codegen/__init__.py`**

Add to the imports:

```python
from remora.codegen.fingerprint import (
    Artifact,
    CheckReport,
    CodegenConfig,
    Fingerprint,
    add_header,
    check_artifacts,
    generate_artifacts,
    load_config,
    make_fingerprint,
    parse_header,
    render_header,
)
```

and merge the names into `__all__` (keep it sorted).

- [ ] **Step 4: Document the command in README.md**

Read `README.md` first. Add a section (near existing development/codegen material, or at the end before any license section) titled `## Generated artifacts & drift check` with exactly this substance, adjusted to the README's heading level and voice:

```markdown
Generated protocol modules under `src/remora/proto/` carry a fingerprint
header recording the tshark version, a hash of the `tshark -G fields` dump,
the plugin environment, and the generator version. The generation toolchain
is pinned in **`codegen.toml`** at the repo root — the pinned tshark version
lives there and nowhere else; CI and this document both defer to it.

Verify the committed artifacts against a fresh regeneration:

    uv run python -m remora.codegen.fingerprint check

The command exits non-zero with a unified diff when any committed artifact
drifts from what the pinned tshark regenerates, and refuses to run against a
tshark that does not match the pin. To regenerate in place after a pin bump
or emitter change:

    uv run python -m remora.codegen.fingerprint write

CI runs the same check on every push and pull request.
```

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean (note AGENTS.md: ruff formats fenced code blocks in docs — README code fences above are indented blocks, which ruff format does not touch; if you used ```-fences instead, run `uv run ruff format README.md` before the check).

- [ ] **Step 6: Commit**

```bash
git add src/remora/codegen/__init__.py README.md tests/test_codegen_fingerprint.py
git commit -m "codegen: re-export fingerprint API and document the drift check (#16)"
```

---

### Task 6: CI drift job + PR

**Files:**
- Modify: `.github/workflows/ci.yml` (append a `codegen-drift` job)

**Interfaces:**
- Consumes: Task 4's `python -m remora.codegen.fingerprint check` (exit 0/1/2, diff on stderr) and `codegen.toml` (read by the command itself — the workflow does NOT parse it and contains no version numbers).

- [ ] **Step 1: Append the job to `.github/workflows/ci.yml`**

```yaml
  codegen-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@v9.0.0
        with:
          python-version: "3.12"
      - name: Install
        run: uv sync
      - name: Install pinned tshark (ppa:wireshark-dev/stable)
        run: |
          sudo add-apt-repository -y ppa:wireshark-dev/stable
          sudo apt-get update
          sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
          tshark --version | head -n 1
      - name: Check generated-artifact drift
        run: uv run python -m remora.codegen.fingerprint check
```

The check command enforces that the installed tshark matches the `codegen.toml` pin (exit 2 with a readable message if the PPA has moved past the pin — the fix is bump the pin + `write` + commit).

- [ ] **Step 2: Validate the workflow file locally**

Run: `uv run python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"` — if PyYAML is unavailable in the env, `actionlint` or a plain visual inspection of indentation is acceptable; do not add a yaml dependency.

- [ ] **Step 3: Run the FULL gate (including integration tests, local tshark present)**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean

- [ ] **Step 4: Commit and push**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add codegen drift job under the pinned tshark (#16)"
git push -u origin feat/issue-16-fingerprint-drift
```

- [ ] **Step 5: Open the PR**

```bash
gh pr create \
  --title "codegen: fingerprint generated artifacts and add CI drift check" \
  --body "$(cat <<'EOF'
Closes #16

- `src/remora/codegen/fingerprint.py`: fingerprint value (tshark version, dump sha256, plugin-env summary, generator version), 5-line `# remora-fingerprint: v1` header on every generated file, `generate_artifacts`/`check_artifacts` core, and a `python -m remora.codegen.fingerprint {check,write}` driver (exit 0 sync / 1 drift with unified diff / 2 environment error).
- `codegen.toml`: the single place the tshark toolchain is pinned (4.6.6 — what ppa:wireshark-dev/stable ships for noble) plus the to-be-populated (#19) protocol/multi lists; CI and docs both defer to it.
- `.github/workflows/ci.yml`: `codegen-drift` job installing tshark from the stable PPA and running the check; the command itself refuses a tshark that does not match the pin.
- README documents `check`/`write`; `remora.codegen` re-exports the fingerprint API.

With `protocols = []` the check passes trivially by design — #19 populates the list and commits the first fingerprinted artifacts.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6: Watch CI — the codegen-drift job is the real validation**

Run: `gh pr checks --watch` (or poll `gh run list --branch feat/issue-16-fingerprint-drift`).

- If `codegen-drift` fails because the PPA tshark version differs from 4.6.6: update the `version` in `codegen.toml` to the version CI actually reports (visible in the job log's `tshark --version` line and in the check command's error message), commit, push, re-watch. This is the designed maintenance path, exercised early.
- All other CI failures: fix on the branch until green.

---

## Self-review notes

- **Spec coverage:** header with all four recorded components → Task 1; single documented check command → Tasks 4+5; CI drift job with readable diff → Tasks 3 (diff), 4 (exit codes/stderr), 6 (job); fingerprint changes under version/dump change, synthetic unit tests → Task 1; pin recorded in exactly one place consumed by CI and docs → Task 2 (`codegen.toml`) + Task 5 (docs defer to it) + Task 6 (workflow contains no version).
- **Zero-artifact state:** `protocols = []` → `check` exits 0 ("0 artifact(s) checked"), so CI is green before #19.
- **Out of scope respected:** no `psdsl` console script (that's #21); no protocol-set decisions (that's #19); `emit.py` untouched.
- **Known intentional behavior:** local `check` on this machine exits 2 (Homebrew 4.6.7 ≠ pin 4.6.6) — verified deliberately in Task 4 Step 5.
