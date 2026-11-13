# AGENTS.md

Guidance for coding agents working in this repository. This file holds what every task needs. The invariants of each module live in the `AGENTS.md` of its directory (see [Where things live](#where-things-live)); read that file before changing anything under it.

## Project

Remora is a type-safe Python DSL for Wireshark/tshark capture analysis. It drives tshark subprocesses directly (no pyshark): field access is statically typed via `.pyi` stubs, display filters are built from expression trees instead of strings, and predicates are pushed down to tshark where possible. A DuckDB workspace (`remora[workspace]`) caches dissected fields as columns so repeat queries never re-parse the pcap.

Work is organized by milestone epics (#40 M1 kernel, #41 M2 codegen, #42 M3 polish, #43 M4 DuckDB workspace). Design rationale lives in the issue that made the decision. When an `AGENTS.md` cites `#<n>`, `gh issue view <n> --comments` has the full argument.

Durable documentation lives in `docs/`. Each document and the module it describes are two statements of one machinery, so a change to one belongs in the other.

| Document | Covers | Module |
| --- | --- | --- |
| `docs/semantics.md` | Absent-field truth table, regex support matrix, portable-text guard, `-T fields` escape table | `src/remora/compile/`, `src/remora/reader/` |
| `docs/workspace.md` | Cache keys, hit/backfill/refuse, modes and locking, `compact()`, export, annotations, streams, attach | `src/remora/workspace/` |
| `docs/codegen.md` | Docker regeneration recipe, drift-check triage, `psdsl gen` worked example | `src/remora/codegen/`, `src/remora/proto/` |

## Commands

Everything runs through uv (Python ≥3.10; the CI matrix covers 3.10 through 3.14):

```bash
uv sync                                        # install deps
uv run pytest                                  # full test suite
uv run pytest tests/test_planner.py -v         # one file
uv run pytest tests/test_fields.py::TestScalarInstanceAccess::test_static_types -v  # one test
uv run pytest -m "not integration"             # skip tests needing a real tshark binary
uv run mypy --strict src tests                 # typecheck (tests included — this is the CI gate)
uv run mypy --strict --platform win32 src tests  # typecheck the sys.platform == "win32" branches
uv run ruff check .                            # lint
uv run ruff format --check .                   # format check (also formats code fences in docs/*.md)
uv run mypy --strict --python-version 3.12 .github/scripts/check_stub_resolution.py  # extras stubs, editable layout
```

The CI gate is all five: `ruff check`, `ruff format --check`, `mypy --strict src tests`, the stub check, and `pytest`. Run it before committing.

- The stub check keeps `from remora.proto.wlan import WLAN` typed in an editable or multi-root layout (#77). Its `--python-version 3.12` only selects typeshed semantics, so the one step runs unchanged on every interpreter.
- The `windows` CI job is the only leg that type-checks `sys.platform == "win32"` branches and runs the Windows-only tests, so Windows code is covered there or nowhere. Its sibling `windows-tshark` runs the tshark integration suite there. `tests/AGENTS.md` has what each runs.

## Workflow

- One PR per issue. Branch `feat/issue-<n>-<slug>` (or `feat/<n>-<slug>`), and put `Closes #<n>` in the PR body. PRs are squash-merged, so merged local branches need `git branch -D`.
- Process artifacts are issue comments, not repository files. Design docs, specs, plans and progress notes go to `gh issue comment <n>`. Only durable documentation (`docs/*.md`, ADRs, the `AGENTS.md` files) is committed. `docs/superpowers/` is gitignored scratch space.

## Cross-cutting invariants

- Loud beats silent. Parse errors raise, non-injective naming is checked and refused, a stale or foreign workspace file is refused at open, and a backend that cannot express an expression raises its `Unsupported*` error rather than approximating.
- Storage-format changes are never tweaks. Changing a column type, a layout column, a cache-key scheme or a separator byte bumps `SCHEMA_VERSION` or the key-scheme prefix, so older files are refused visibly instead of misread.
- Absence is a value, not an exception: `()` from `get_raw`, `None` from scalar instance access, `()` from multi instance access. The one exception is `FieldNotProjectedError` for a field outside a `-T fields` projection, which is a caller bug rather than absence.
- Names are not re-derived at runtime. `_table_` stores the full tshark name, so nothing maps attribute names to tshark names or back. The pairing tests in `tests/test_proto_seed.py` are the frozen-format contract for generated modules; keep them passing unmodified.
- Underscore-prefixed attributes on protocol classes are reserved, and `_table_` carries the `ClassVar[FieldTable]` annotation (ruff RUF012).

## Architecture

Query data flow: **Expr IR → planner → tshark argv → reader → RawPacket → protocol view / predicate**. The workspace is a second surface over the same IR: **Expr IR → SQL backend → DuckDB scan over materialized columns → Row**.

### Where things live

| Directory | Holds |
| --- | --- |
| `src/remora/` | Core contracts every other package builds on: the expression IR, the ftype mapping, `RawPacket`/`Field`, the planner, `Capture` |
| `src/remora/compile/` | The three backends that lower one `Expr`: display filter, Python predicate, DuckDB SQL |
| `src/remora/reader/` | tshark subprocess lifecycle and the `-T fields` / `-T ek` parsers |
| `src/remora/proto/` | Generated protocol modules, the frozen compact-table format, extras grafting |
| `src/remora/codegen/` | `tshark -G fields` dump → protocol modules |
| `src/remora/workspace/` | DuckDB workspace: layout, cache keys, materialize, modes and locking, `compact()`, export, annotations, streams, query, attach |
| `packages/` | The `remora-<extra>` distributions of generated protocol modules |
| `tests/` | Test doubles, dependency guards, the CI legs, integration suites |

Each directory in the table has an `AGENTS.md` scoped to its whole tree, so `src/remora/AGENTS.md` also applies inside every subpackage. A sibling `CLAUDE.md` containing `@AGENTS.md` makes Claude Code load it on demand; add both files together when you add a directory.

## Non-code artifacts

Issues, PR descriptions, specs, plans, reviews, and every other non-code artifact give readers the context and judgment the diff cannot, not a narrated diff or filler, and are published in full on GitHub. The full rules:

@docs/non-code-rules.md

## PR rules

- Do not merge a PR unless I explicitly ask you to.
- When reviewing a PR, post everything (findings, spec and standards checks, assessment, observations, verification, summary) as one comment on the PR.
- When I ask you to merge a PR, squash-merge by default unless I ask for something else.
- After a PR is merged, clean up local branches and worktrees, fast-forward main, then update and close related issues.

## Git conventions

Never include AI attribution in commit messages, PR titles, or PR descriptions, in any form. That means no

- `Co-Authored-By: Claude`
- `Generated with ...` footers
- sign-offs or footers naming an LLM or AI agent (OpenAI, GPT, Claude, Anthropic, and the like)
- `Claude-Session:` trailers or session URLs (`https://claude.ai/code/session_...`), even when a tool inserts them automatically

When squash-merging, write a clean commit message that describes only the change itself.