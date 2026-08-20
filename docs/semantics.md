# Semantics across the three backends

One `Expr` IR, three engines. This document is the contract: what every operator
means when a field is absent, which regex constructs survive the trip, and where
each rule is enforced in the test suite.

| Backend | Where | Engine |
| --- | --- | --- |
| Display filter | `src/remora/compile/dfilter.py` → tshark `-Y` | Wireshark PCRE2 (`PCRE2_CASELESS`, no UTF/UCP) |
| Python predicate | `src/remora/compile/predicate.py` | Python `re` over UTF-8 **bytes** |
| DuckDB SQL | `src/remora/compile/sql.py` → the workspace `Query` | Google RE2 over UTF-8 **runes** |

## Absent-field truth table

An absent field is `()` from `RawPacket.get_raw`, `NULL` in a scalar `pkts`
column and `[]` in a multi-value one. Every positive operator is False on an
absent field and every negated one is True — on all three backends, since #36.
`!=` is not a row of its own: the IR has no `Ne` node, so `f != v` **is**
`~(f == v)` and appears in the negated columns of the `==` row.

<!-- truth-table:start -->

| operator | absent scalar | absent multi | negated, absent scalar | negated, absent multi |
| --- | --- | --- | --- | --- |
| `==` | False | False | True | True |
| `<` | False | False | True | True |
| `<=` | False | False | True | True |
| `>` | False | False | True | True |
| `>=` | False | False | True | True |
| `in` | False | False | True | True |
| `contains` | False | False | True | True |
| `matches` | False | False | True | True |
| `present` | False | False | True | True |

<!-- truth-table:end -->

The rule behind every cell is the same one Wireshark applies: a comparison means
"some occurrence matches", and there are no occurrences, so it is False —
negation then inverts it, which is exactly the pitfall the missing `Ne` node
exists to prevent.

Enforced by `tests/test_semantics_table.py` (`NULL_TRUTH_CASES` — every operator
above × scalar/multi × polarity, each carrying a packet with no such field) run
through the display-filter and predicate backends, and by
`tests/test_sql_duckdb.py`, which runs the same cases against a real DuckDB
seeded through the real `column_spec` codecs. For most of the table the
Wireshark column is not an independent measurement of tshark's booleans: it
rests on `predicate.py`'s documented job of mirroring Wireshark's semantics
exactly, plus `tests/test_dfilter_validation.py` feeding every golden
display-filter string to a real tshark for **syntax acceptance**. Two rows do
better than that: the same file's semantics half runs `!(x == v)` and a negated
`matches` through a real tshark on fixture pcaps containing a frame with no such
field (an ARP frame) and compares the *row sets* against the predicate backend,
so the negated cells of the `==` and `matches` rows — scalar and multi-value
alike, since a multi-value parity case alone would leave the scalar cell
unmeasured — are confirmed against Wireshark itself.
`tests/test_semantics_docs.py` checks this table against the operator list the
suite enumerates.

### How SQL gets there

SQL is three-valued and an absent scalar column is `NULL`, so `NOT ("col" = ?)`
is `NULL` and the row would be dropped — where Wireshark and Python include it.
`sql.py` therefore wraps a NULL-able leaf in `coalesce(<leaf>, FALSE)` **when
and only when a `Not` will invert it**. At the leaf, because coalescing a whole
subtree gets nested negation wrong (`NOT (NOT (x))` with `x` NULL would become
True, where Python's `not not False` is False); only under a `Not`, because
`coalesce` blocks DuckDB's scan-level filter pushdown and a positive predicate
has no divergence to fix — a NULL reaching the `WHERE` clause is filtered out,
which is what the other two backends do.

Presence tests were already two-valued (`IS NOT NULL`, `len(coalesce("col", []))
> 0`) and are untouched, as is the constant `FALSE` a NaN literal compiles to. A
multi column back-filled with `NULL` by a later `add_field_column` follows the
same rule.

## Regex support matrix

`matches` is compiled by three different regex engines, so `remora.expr.Matches`
restricts patterns at **construction** to the Python-`re` ∩ PCRE2 common subset,
and `src/remora/compile/re2.py` states the *further* restriction RE2 imposes,
applied at **SQL compile time** by `compile_sql`.

| Construct | Python `re` | PCRE2 | RE2 | remora policy |
| --- | --- | --- | --- | --- |
| literals, `.`, `^`, `$`, `\|`, groups, `(?:…)` | ✅ | ✅ | ✅ | accepted |
| `*` `+` `?` `{m}` `{m,}` `{m,n}`, lazy `?` | ✅ | ✅ | ✅ | accepted |
| classes `[a-z]`, `[^0-9]` | ✅ | ✅ | ✅ | accepted |
| `\d \D \w \W \s \S \b \B \n \r \t \f \xHH` | ✅ | ✅ | ✅ (but `\s \S` differ) | accepted; see the guard below |
| lookarounds `(?=` `(?!` `(?<=` `(?<!` | ✅ | ✅ | ❌ | accepted by `Expr`; **`UnsupportedSqlExprError`** in `compile_sql` |
| brace repeat above 1000 (see the rule below) | ✅ | ✅ (≤65535) | ❌ | accepted by `Expr` up to 65535; **`UnsupportedSqlExprError`** in `compile_sql` |
| any non-ASCII character in the **pattern** | ✅ | ✅ | ✅ (but disagrees) | accepted by `Expr`; **`UnsupportedSqlExprError`** in `compile_sql` |
| backreferences `\1` | ✅ | ✅ | ❌ | **`ValueError`** at `Expr` construction |
| possessive `a++`, atomic `(?>…)` | ❌ | ✅ | ❌ | **`ValueError`** at `Expr` construction |
| inline flags, named groups, conditionals, branch reset | ✅/❌ | ✅ | ✅/❌ | **`ValueError`** at `Expr` construction |
| POSIX classes `[[:alpha:]]`, `\p{…}`, `\x{…}`, `\A`, `\h`, `\v` | ❌/✅ | ✅ | ✅/❌ | **`ValueError`** at `Expr` construction |

The last two rows are grab-bags of dialect-specific constructs that never reach
any backend — `Expr` refuses them at construction — so their RE2 column is
informational, and mixed: RE2 in fact runs several of them. Measured on duckdb
1.5.5, `(?i)abc`, `(?P<x>a)b`, `[[:alpha:]]+`, `\p{Greek}`, `\x{263A}`, `\Aabc`
and `\v` all compile, while `(?<name>…)`, `(?(1)…)`, `(?|…)` and `\h` are
refused. In every other row a ❌ in the RE2 column means "RE2 cannot run it",
which is the criterion `compile_sql` refuses on.

The Perl-class row carries a caveat: all three engines *run* `\s` and `\S`, but
they do not agree on what the class contains. RE2's `\s` is exactly
`[\t\n\f\r ]`, while Python `re` (over bytes) and PCRE2 also count U+000B
VERTICAL TAB — so `a\x0bb matches "a\sb"` is true on the pcap path and false on
RE2. That difference lives in the *value*, not the pattern, so it is not
refusable at compile time: the portable-text guard below closes it instead, by
refusing any value containing a vertical tab.

RE2's repeat ceiling is 1000, and it applies both to each individual bounded
count and to the **product of the factors along a nesting path**: `(?:a{31}){31}`
(961) compiles, `(?:a{32}){32}` (1024) does not, and `(?:a{500}){3}` (1500) does
not. RE2 divides its budget by a repeat's *max*, falling back to the min when the
max is unbounded, so `{m,}` contributes a factor of `m` — `(?:a{500,}){3}` is
refused exactly like `(?:a{500}){3}`. `{0}` and `{0,}` contribute a factor of 1
and never zero the product; only `*` and `+` contribute no factor at all.

The layering is deliberate: PCRE2 and Python `re` run lookarounds and large
repeats identically, and a caller who never opens a workspace should not lose
them for a backend they never reach. `UnsupportedSqlExprError` names the
construct, its position and RE2, and points at `remora.Capture`.

Enforced by `tests/test_expr.py::TestMatchesCommonSubset` (construction),
`tests/test_re2_portability.py` (the RE2 rules, cross-checked against DuckDB's
own engine) and `tests/test_sql.py::TestMatches` (the refusal).

## The portable-text guard

No construct check can catch the differences that live in the *data*:

| Value | Pattern | Python `re` / PCRE2 (bytes) | RE2 (runes) |
| --- | --- | --- | --- |
| `café` | `^.{5}$` | True (5 bytes) | False (4 runes) |
| `é` | `^[^x]$` | False (2 bytes) | True (1 rune) |
| `K` (U+212A) | `k`, case-insensitive | False | True (Unicode folding) |
| `abc\n` | `^abc$` | True | False (`$` is end-of-text) |
| `a\x0bb` | `a\sb` | True (VT is in `\s`) | False (RE2's `\s` is `[\t\n\f\r ]`) |

Four mechanisms, then: rune-vs-byte counting, Unicode case folding, `$`
anchoring — and the last row, which is a mismatch in the *definitions* of the
Perl classes rather than in how the engines run them. Every one of them needs a
non-ASCII byte, a newline or a vertical tab **in the value**, so the SQL backend
refuses values carrying one: a compiled `matches` tests
`strlen(v) <> length(v) OR contains(v, chr(10)) OR contains(v, chr(11))` and
raises DuckDB `error()` naming the column and pointing at the pcap path.

The guard refuses a *superset*, deliberately. It tests the value alone, so
`a\x0bb` is refused even under a pattern such as `x` that could not observe the
difference. A pattern-aware test would refuse less and would have to be right
about every construct; a cheap value-shaped test that never lets a divergence
through is the trade this backend takes.

The value side is only half of a sound guard, because RE2's case folding is a
*relation* and runs in both directions. A non-ASCII **pattern** character can fold onto an
ASCII value: U+212A KELVIN SIGN folds onto `k` and U+017F LATIN SMALL LETTER
LONG S onto `s`, so a pattern that is the single character U+212A matches the
ASCII value `kelvin` on RE2 and on neither of the other two engines — and that
value is pure ASCII, so the value-side guard above never fires. The pattern side
is therefore closed in `src/remora/compile/re2.py`, which refuses any pattern
that is not `isascii()`, checked first, ahead of the construct rules.

With **both** halves in place the three engines are provably identical on what
survives: pattern and value are ASCII, an ASCII byte never occurs inside a
multi-byte UTF-8 sequence, so `.`, `[^…]` and counted quantifiers consume one
byte = one rune; no character on either side has a simple-fold orbit that leaves
ASCII, so Unicode folding degenerates to ASCII folding; no newline means `$`
cannot differ; and no vertical tab means the one Perl-class definition the
engines disagree about (`\s`/`\S`) cannot differ either.

Two residuals, stated rather than implied: the guard is a property of the
column's data, not of the answer, so a query can fail on a row another conjunct
would have excluded; and whether that row is examined can depend on zone-map
skipping from other pushed-down filters. Making it deterministic would need a
precondition scan in `Query` — future work, not a gap this document hides.

Enforced by `tests/test_sql_duckdb.py::TestPortableTextGuard` and by the
`matches-byte-oriented` case in `tests/test_semantics_table.py`, which carries a
`sql_guard_rows` marker so the shared suite asserts the guard fires rather than
comparing row sets; the pattern half is pinned by
`tests/test_re2_portability.py`, against real RE2 wherever duckdb is installed.

## What is still divergent

- **`matches` on non-string fields** is a `TypeError` on all three backends —
  the same error, so this is not a divergence, only a restriction.
- **Time literals** (`datetime`/`timedelta`) are not pushed to display filters
  (M1 decision); the planner keeps them as residual Python predicates. The row
  set is unchanged; only the execution path differs.
- **`contains` on a `BLOB` column** is `UnsupportedSqlExprError`: DuckDB's
  `contains()` takes `VARCHAR` or `LIST`, not `BLOB`. The pcap path runs it.
- **Field text tshark could not decode as UTF-8** reaches the predicate backend
  as U+FFFD replacement characters, which cannot round-trip to the original
  bytes. Irreducible; noted in `predicate.py`.

Every difference above is loud — a refusal at compile time or an error at query
time — and none of them is a quiet row-set fork. Everything else must select the
same rows on all three backends, and
`tests/test_sql_duckdb.py::test_sql_backend_matches_the_other_two` fails if it
does not.
