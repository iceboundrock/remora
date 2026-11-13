# src/remora/reader/AGENTS.md

tshark subprocess lifecycle and the two output parsers. The user-facing account of the `-T fields` framing is the escape table in `docs/semantics.md`.

- `process.py` owns tshark subprocess lifecycle and nothing else. A daemon thread drains stderr to avoid pipe deadlock, and `close()` terminates, kills and reaps so no orphan survives.
- `fields_reader.py` parses `-T fields`. Its framing bytes are chosen against tshark's C-style escaper and must not be changed casually. The column separator `UNIT_SEP` (`0x0b`) must be a byte the escaper *replaces*, so no value can forge it. The occurrence aggregator `OCC_SEP` (`0x1e`) must be a byte the escaper *leaves alone*, or it arrives as a two-character escape and never splits. Value unescaping runs only on tshark ≥ 4.4 (`escaping_is_reversible()`, with an unknown version counting as old), because 4.2.x escaping is not injective. Changing either separator changes every stored workspace cache key (#74).
- `ek_reader.py` parses `-T ek` NDJSON. The key mapping is `layers["ip"]["ip_ip_src"]` (layer + `_` + dots→underscores).
