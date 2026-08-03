# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Remora is a type-safe Python DSL for Wireshark/tshark capture analysis. It drives tshark subprocesses directly (no pyshark): field access is statically typed via `.pyi` stubs, display filters are built from expression trees instead of strings, and predicates are pushed down to tshark where possible. Work is organized by milestone epics (#40 M1 kernel, #41 M2 codegen, #42 M3 polish, #43 M4 DuckDB workspace); each epic issue defines the execution path and dependency graph.

## Commands

Everything runs through uv (Python ≥3.10; CI matrix is 3.10–3.14):

```bash
uv sync                                        # install deps
uv run pytest                                  # full test suite
uv run pytest tests/test_planner.py -v         # one file
uv run pytest tests/test_fields.py::TestScalarInstanceAccess::test_static_types -v  # one test
uv run pytest -m "not integration"             # skip tests needing a real tshark binary
uv run mypy --strict src tests                 # typecheck (tests included — this is the CI gate)
uv run ruff check .                            # lint
uv run ruff format --check .                   # format check (also formats code fences in docs/*.md)
```

The CI gate is all four: `ruff check`, `ruff format --check`, `mypy --strict src tests`, `pytest`. Run the full gate before committing.

Static typing assertions are part of the test suite: `assert_type(...)` calls in `tests/` are no-ops at runtime and are verified when mypy checks the test files. Beware that a preceding `assert x == value` can narrow a type and break a later `assert_type` — put `assert_type` before runtime asserts.

## Workflow

- One PR per issue. Branch `feat/issue-<n>-<slug>` (or `feat/<n>-<slug>`), PR body includes `Closes #<n>`. PRs are squash-merged, so merged local branches need `git branch -D`.
- Implementation plans live in `docs/superpowers/plans/`.

## Architecture

Data flow for a query: **Expr IR → planner → tshark argv → reader → RawPacket → protocol view / predicate**.

- `src/remora/expr.py` — immutable expression IR, deliberately a leaf module (imports nothing from remora). Comparisons on fields build `Expr` trees via `FieldExprOps`; `__bool__` raises so `and`/`or`/chained comparisons fail loudly (use `&`/`|`/`~`, parenthesize comparisons). There is **no `Ne` node**: `!=` builds `Not(Comparison(EQ, ...))`, making Wireshark's multi-value `!=` pitfall unrepresentable. `FieldRef`s are intentionally unhashable (`__eq__` returns an `Expr`); dedup by `.name`.
- `src/remora/values.py` — the single source of truth mapping tshark ftypes (`"FT_IPv4"` …) to Python types and parse functions. Parse errors raise `ValueError` (loud beats silent); unknown ftypes fall back to `str`. `coerce_literal` normalizes user literals at compile time for both backends.
- `src/remora/fields.py` — the contract hub. `RawPacket` is the minimal packet protocol: `get_raw(name) -> tuple[str, ...]` with `()` meaning absent. `Field`/`MultiField` are dual-mode descriptors: class access (`IP.src`) returns a `FieldRef[T]` for building expressions; instance access (`pkt[IP].src`) returns `T | None` (scalar) or `tuple[T, ...]` (multi). Multiplicity is encoded in the descriptor *class* because `@overload` can only express the return type per class.
- `src/remora/compile/` — two backends lowering `Expr`: `dfilter.py` renders Wireshark display-filter strings (raises `UnsupportedExprError` for what it can't push; `!=` always renders `!(f == v)`), `predicate.py` compiles Python predicates over `RawPacket` (the end of the fallback chain — mirrors Wireshark semantics exactly, including any-occurrence matching on multi-value fields).
- `src/remora/planner.py` — two-level pushdown, pure decision, never spawns tshark. Pushable conjuncts become a `-Y` display filter; statically known field sets enable `-T fields` projection; opaque lambdas force `-T ek` whole-packet fallback. Failed-to-push `Expr`s become residual Python predicates.
- `src/remora/reader/` — `process.py` owns tshark subprocess lifecycle only (stderr drained by a daemon thread to avoid pipe deadlock; `close()` terminates/kills/reaps so no orphans). `fields_reader.py` parses `-T fields` output using literal `0x1f`/`0x1e` separator bytes embedded in argv (tshark has no hex-escape separator syntax). `ek_reader.py` parses `-T ek` NDJSON; ek key mapping is `layers["ip"]["ip_ip_src"]` (layer + `_` + dots→underscores).
- `src/remora/proto/` — protocol classes. `_meta.py` defines the **frozen compact-table format**: classes set only `_proto_` and `_table_: ClassVar[FieldTable]` mapping attr name → `(tshark_name, ftype, multi 0/1)`; descriptors are materialized lazily on first access (`ProtocolMeta.__getattr__` for class access, `ProtocolBase.__getattr__` for instance access) so a 10k-field module imports for free. The eth/ip/tcp/udp/dns modules are hand-written M1 seeds in exactly the format the M2 generator (#14) will emit; each `.py` has a sibling `.pyi` stub that shadows it for type checkers, declaring `Field[T]`/`MultiField[T]` per attribute.
- `src/remora/codegen/` — the M2 generator's front half, and now its back half too. `parse.py` turns a `tshark -G fields` dump (`P`/`F` records) into frozen model dataclasses (`Protocol`, `FieldDef`, `FieldDictionary`); malformed, unknown, and duplicate lines become collected `ParseWarning`s (first occurrence wins) rather than silent drops. `mangle.py` is the frozen field-abbrev → attribute-name policy the emitter (#14) must follow; it is **not injective** (dots and hyphens both become `_`), so emitters must detect per-protocol duplicate mangled names. `tests/data/g_fields_sample.txt` is a checked-in subset of a real 4.6.7 dump (regenerate with `tests/data/make_g_fields_sample.py`); tests assert exact record counts against it. `emit.py` is the back half: `emit_protocol(protocol, fields, multi)` renders one protocol's paired `.py` (compact `_table_`, import-pure) and `.pyi` (one `Field[T]`/`MultiField[T]` attr per field) sources, byte-deterministic, in input field order; multiplicity has no `-G fields` signal so the multi-abbrev set is caller-supplied, mangled-name collisions are first-wins with `EmitWarning`s, and `mangle_protocol` (lowercase, non-alnum→`_`, digit→`p_` prefix, keyword→trailing `_`) names the module, upper-cased for the class.

Cross-cutting invariants:

- `tests/test_proto_seed.py` pairing tests are the contract for the M2 emitter — keep them passing unmodified. They parse each seed `.pyi` with `ast` and cross-check it against the runtime `_table_` (attribute sets, multiplicity vs descriptor class, ftype → Python type, ftype known to `FTYPE_TABLE`).
- The seeds' dots→underscores attribute naming (`dns.qry.name` → `qry_name`) is a seed-only convention, **not** part of the frozen format: `_table_` stores the full tshark name precisely so generated modules may deviate (e.g. keyword escapes). Nothing at runtime may re-derive tshark names from attribute names or vice versa.
- Absence is `()` from `get_raw`, `None` from scalar instance access, `()` from multi instance access — never an exception (except `FieldNotProjectedError` for fields outside a `-T fields` projection).
- Underscore-prefixed attributes on protocol classes are reserved; ruff RUF012 requires the `ClassVar[FieldTable]` annotation on tables.
- `tests/conftest.py` provides `FakePacket`, the standard `RawPacket` test double.
