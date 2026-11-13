# packages/AGENTS.md

The `remora-<extra>` distributions. Their `src/remora/proto/` trees are generated output, so `src/remora/proto/AGENTS.md` governs them: edit `codegen.toml` or the generator and regenerate, never the modules.

- `remora[all]` is derived rather than listed; `tests/test_packaging.py` computes it.
- Every distribution ships its own `remora/py.typed` (#77). Uninstalling any one of them deletes the shared marker in a wheel layout, an accepted price that only affects type checking.
