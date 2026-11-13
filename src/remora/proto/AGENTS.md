# src/remora/proto/AGENTS.md

Protocol modules. Almost everything here is generated, so edit the generator (`src/remora/codegen/`) or `codegen.toml`, never the output. `docs/codegen.md` has the Docker regeneration recipe and the drift-check triage.

- `_meta.py` and `__init__.py` are the only hand-written files. `_meta.py` defines the frozen compact-table format: a class sets `_proto_` and `_table_: ClassVar[FieldTable]` (attr name → `(tshark_name, ftype, multi 0/1)`), and descriptors materialize lazily on first access so a 10k-field module imports for free.
- Every other module is generated (#19) with a sibling `.pyi` stub. Regenerate with `uv run python -m remora.codegen write` under the pinned tshark, natively on the host architecture and not under emulation. Regeneration has been architecture-neutral since #97, and `codegen-arch-verify.yml` proves it on both architectures. Committed bytes are emitter-exact: ruff ignores E501 under `proto/`, and the formatter skips the tree.
- `codegen.toml` lists the core set, the curated multi-value fields, and the extras shipped as `remora-<extra>` distributions under `packages/`. Extras graft into `remora.proto` via `pkgutil.extend_path`. `remora.proto.__getattr__` imports installed extras lazily and raises an `ImportError` naming the extra for a missing one.
