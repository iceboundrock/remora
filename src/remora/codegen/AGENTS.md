# src/remora/codegen/AGENTS.md

Turns a `tshark -G fields` dump into the protocol modules under `src/remora/proto/` and `packages/`. The regeneration command and its constraints are in `src/remora/proto/AGENTS.md`; `docs/codegen.md` has the Docker recipe, drift-check triage and a `psdsl gen` worked example.

- `parse.py` turns a `tshark -G fields` dump into frozen dataclasses. Malformed, unknown and duplicate lines become collected `ParseWarning`s (first occurrence wins) rather than silent drops. Tests assert exact record counts against `tests/data/g_fields_sample.txt`.
- `mangle.py` is the frozen abbrev → attribute-name policy. It is not injective (dots and hyphens both become `_`), so emitters must detect per-protocol duplicate mangled names.
- `emit.py` renders one protocol's `.py`/`.pyi` pair, byte-deterministic in input field order, so reproducible bytes need `fingerprint.py`'s canonical dump order. Multiplicity has no `-G fields` signal, so the multi-abbrev set is caller-supplied. Collisions resolve first-wins, except that a data field displaces an earlier `FT_NONE` marker, and every collision path records an `EmitWarning`.
- `fingerprint.py`'s `env:` line hashes only the `(name, version, type)` columns of `tshark -G plugins`, dropping the path column that embeds the multiarch triplet.
