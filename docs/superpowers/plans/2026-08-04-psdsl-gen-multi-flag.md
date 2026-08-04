# `psdsl gen --multi` Curation Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--multi NAME...` flag to `psdsl gen` so locally generated modules can declare multi-valued fields (`MultiField` / multiplicity `1`), closing the parity gap with the hand-curated committed modules (issue #66).

**Architecture:** Pure argv wiring plus docs. `generate_artifacts(config, ...)` and `emit_protocol(protocol, fields, multi)` already accept a multi-abbrev set; `_cmd_gen` currently hardcodes `multi=frozenset()` at `src/remora/codegen/cli.py:86`. We add an argparse flag mirroring `--protocols` (`nargs="+"`, `action="extend"`), feed it into `CodegenConfig.multi`, update the `gen` subparser description (which currently states every field is scalar), and replace the README caveat with the flag.

**Tech Stack:** Python argparse, pytest (existing `fake_tshark` monkeypatch fixture in `tests/test_codegen_cli.py` — no real tshark needed), uv.

## Global Constraints

- CI gate must pass: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest -m "not integration"` (integration tests need a real tshark; run plain `uv run pytest` if tshark is installed).
- One PR per issue. Branch `feat/issue-66-gen-multi-flag`, PR body includes `Closes #66`.
- Out of scope (explicitly, per issue): config-file multi-list source; validating that `--multi` abbrevs exist in the dump (unknown names stay inert, matching the committed pipeline).
- `emit_protocol`'s `multi` is membership-tested only; `CodegenConfig.multi` is a `frozenset[str]` (see `src/remora/codegen/fingerprint.py:129`).

---

### Task 1: `--multi` flag on `psdsl gen`

**Files:**
- Modify: `src/remora/codegen/cli.py` (parser at `_build_parser`, wiring at `_cmd_gen`, `gen` subparser description)
- Test: `tests/test_codegen_cli.py`

**Interfaces:**
- Consumes: `CodegenConfig(tshark_version, protocols, multi: frozenset[str])` from `remora.codegen.fingerprint`; existing `fake_tshark` fixture whose `SAMPLE_DUMP` defines protocol `udp` with fields `udp.srcport` (`FT_UINT16`) and `udp.stream` (`FT_UINT32`).
- Produces: `psdsl gen ... --multi NAME [NAME ...]` (repeatable, optional, default scalar-only); `options.multi` is a `list[str]` defaulting to `[]`.

- [ ] **Step 1: Write the failing tests**

Add to `class TestGen` in `tests/test_codegen_cli.py` (note: `assert_type`-style static assertions are not needed here — these are runtime tests over generated source text):

```python
    def test_multi_flag_emits_multifield(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "gen"
        argv = ["gen", "--protocols", "udp", "--multi", "udp.srcport", "--out", str(out)]
        assert main(argv) == 0
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        assert "srcport: MultiField[int]" in pyi
        assert "stream: Field[int]" in pyi  # unlisted field stays scalar
        py = (out / "udp.py").read_text(encoding="utf-8")
        assert '"srcport": ("udp.srcport", "FT_UINT16", 1)' in py
        assert '"stream": ("udp.stream", "FT_UINT32", 0)' in py

    def test_multi_defaults_to_all_scalar(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        assert "MultiField" not in pyi

    def test_repeated_multi_flag_extends_parser_level(self) -> None:
        from remora.codegen.cli import _build_parser

        options = _build_parser().parse_args(
            ["gen", "--protocols", "udp", "--multi", "udp.srcport", "--multi", "udp.stream"]
        )
        assert options.multi == ["udp.srcport", "udp.stream"]
```

In `class TestHelp`, extend the flag loop in `test_gen_help_documents_every_flag`:

```python
        for flag in ("--tshark", "--protocols", "--out", "--multi"):
            assert flag in message
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_codegen_cli.py -v`
Expected: the three new tests FAIL (`unrecognized arguments: --multi` → exit code 2 / `AttributeError: ... no attribute 'multi'`), and `test_gen_help_documents_every_flag` FAILS on the `--multi` assertion. All pre-existing tests still PASS.

- [ ] **Step 3: Implement the flag**

In `src/remora/codegen/cli.py`, add after the `--protocols` argument in `_build_parser` (before `--out`):

```python
    gen.add_argument(
        "--multi",
        nargs="+",
        action="extend",
        default=[],
        metavar="NAME",
        help=(
            "tshark field abbrevs to declare multi-valued, emitted as MultiField "
            "(e.g. dns.qry.name ip.addr); unlisted fields are scalar"
        ),
    )
```

In `_cmd_gen`, replace `multi=frozenset(),` with:

```python
        multi=frozenset(options.multi),
```

Update the `gen` subparser `description` — the current text ends with "Every generated field is scalar—multi-occurrence fields resolve to their first occurrence." Replace that sentence so the description reads:

```python
        description=(
            "Run the dump → parse → emit → fingerprint pipeline against the local "
            "tshark and write importable .py/.pyi pairs to the output directory. "
            "Fields listed in --multi are declared multi-valued; all others are "
            "scalar and resolve to their first occurrence."
        ),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_codegen_cli.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/remora/codegen/cli.py tests/test_codegen_cli.py
git commit -m "codegen: add --multi curation flag to psdsl gen"
```

### Task 2: README caveat → flag documentation

**Files:**
- Modify: `README.md` (the "Local generation (`psdsl gen`)" section — the caveat paragraph currently at lines 86–89)

**Interfaces:**
- Consumes: the `--multi` flag from Task 1.
- Produces: user-facing docs; no code.

- [ ] **Step 1: Replace the caveat paragraph**

The current paragraph reads:

> One caveat: `tshark -G fields` carries no multiplicity signal and `psdsl gen`
> takes no curated multi list, so every generated field is declared scalar — a
> field that occurs several times per packet resolves to its first occurrence.
> The committed `remora.proto` modules curate multiplicity by hand.

Replace it with:

```markdown
`tshark -G fields` carries no multiplicity signal, so multiplicity is curated
by hand: pass `--multi` with the field abbrevs that occur several times per
packet, and they are declared multi-valued (`MultiField`); every other field
is scalar and resolves to its first occurrence:

    uv run psdsl gen --protocols dns ip --multi dns.qry.name ip.addr --out ./gen

The committed `remora.proto` modules curate multiplicity the same way, by
hand.
```

- [ ] **Step 2: Check formatting**

Run: `uv run ruff format --check .`
Expected: PASS (ruff also formats code fences in docs/*.md; the README fence here is indented command text, not a fence, so no reformat — but verify).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document psdsl gen --multi in README"
```

### Task 3: Full CI gate and PR

**Files:**
- No new edits expected; fixes only if the gate fails.

**Interfaces:**
- Consumes: Tasks 1–2 committed on `feat/issue-66-gen-multi-flag`.
- Produces: a green branch and an open PR closing #66.

- [ ] **Step 1: Run the full gate**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest
```

Expected: all four PASS (if no tshark binary is available, substitute `uv run pytest -m "not integration"`). Fix and amend/commit if anything fails.

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin feat/issue-66-gen-multi-flag
gh pr create --title "codegen: add --multi curation to psdsl gen" --body "$(cat <<'EOF'
Adds a `--multi NAME...` flag to `psdsl gen` (repeatable, `action="extend"`,
matching `--protocols`) feeding `CodegenConfig.multi`, so locally generated
modules can declare multi-valued fields instead of everything-scalar.
Updates `gen --help` and the README local-generation caveat.

Closes #66

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR opens against `main`.

## Self-Review Notes

- Spec coverage: `--multi` flag with `extend`/`nargs="+"` (Task 1 Step 3), MultiField `.pyi` + `_table_` `1` + unlisted-stays-scalar test (Task 1 Step 1, `test_multi_flag_emits_multifield`), parser-level accumulation (`test_repeated_multi_flag_extends_parser_level`), `gen --help` docs (help string + help test), README caveat replacement (Task 2), CI gate (Task 3). Out-of-scope items are excluded per issue.
- `_table_` assertion format verified against `emit.py:188` (`flag = 1 if field.abbrev in multi else 0`) and the existing import test asserting `("udp.srcport", "FT_UINT16", 0)`.
- `.pyi` assertion format verified against `emit.py:215` (`{attr}: MultiField[{type_name}]`; FT_UINT16 → `int`).
