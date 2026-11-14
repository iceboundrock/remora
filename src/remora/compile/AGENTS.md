# src/remora/compile/AGENTS.md

Three backends lower one `Expr`, and `docs/semantics.md` states where they agree and disagree, so a change to any backend's semantics belongs in that document too. The planner catches `UnsupportedExprError` from the dfilter backend and hands the conjunct to the predicate backend, so a dfilter refusal costs only pushdown.

## `dfilter.py`

Renders Wireshark display-filter strings. `!=` renders `!(f == v)`. A NaN literal is refused wherever a float reaches the renderer, because Wireshark lexes `nan` as a literal whose matching is ftype- and version-dependent (#90); `inf`/`-inf` push down unchanged. Ordered comparisons and ranges on `FT_GUID`, and `contains` on `FT_EUI64`, are refused too (#69): tshark 4.2.2 orders GUIDs by a host-endian struct and rejects `contains` on an EUI-64, where 4.6.9 agrees with Python. Every value test on `FT_OID` is refused and only presence is pushed (#149): tshark rejects a quoted OID on every supported build, and a bare one compares the encoded bytes where Python and SQL compare the printed text. Refusals come after literal coercion and range-inversion checks, so user errors surface identically on every backend.

## `predicate.py`

Compiles Python predicates over `RawPacket`. It is the end of the fallback chain and the reference semantics, including any-occurrence matching on multi-value fields.

## `sql.py`

Produces a DuckDB predicate string plus bound parameters (#29). It is import-pure and never imports duckdb. Column name, SQL type and multiplicity come from `workspace.naming`/`workspace.types` and are not re-derived. These rules must survive any edit:

- Every literal takes the one path `_coerce` → `_encode_coerced`, because the value between them is what the NaN test and the range-inversion check read (#89).
- Multi-value columns keep any-occurrence semantics (`list_contains` / `list_filter`). `!=` renders `NOT (...)`; SQL `<>` is never used on a list column.
- A NaN literal compiles to `FALSE`, and `>`/`>=` on a `DOUBLE` column (per `types.COLUMN_TYPES`) carry `NOT isnan(...)`, so a stored NaN is excluded as Python excludes it.
- NULL harmonization (#36): a NULL-able leaf is wrapped `coalesce(<leaf>, FALSE)` only when a `Not` will invert it, and only at the leaf. Coalescing a subtree gets nested negation wrong, and coalescing a positive leaf blocks scan-level filter pushdown for no gain.
- `matches` compiles to `regexp_matches(col, ?, 'i')` behind the portable-text guard and `re2.py`'s ASCII-only pattern rule. The two are only sound together, so do not relax one without the other.
- `UnsupportedSqlExprError` covers unknown nodes, patterns RE2 cannot run, and `contains` on a BLOB column. Malformed literals stay `ValueError`/`TypeError`, as in the sibling backends.
