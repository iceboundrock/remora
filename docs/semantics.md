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
suite enumerates. The grid is read out of the `Expr` each case carries, not out
of its label, so a case whose id names an operator or a multiplicity its
expression does not have fails rather than filling a cell it never tested.

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
and never zero the product; only `*`, `+`, and `?` contribute no factor at all.

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
comparing row sets. The marker names *which* rows: each listed one is seeded
alone and must raise, and the rest are seeded together and must return the
shared row set, so an index pointing at a portable row — or omitting an
unportable one — fails the suite rather than exempting the case wholesale. The
pattern half is pinned by `tests/test_re2_portability.py`, against real RE2
wherever duckdb is installed.

The vertical-tab row of the table above is measured on all three engines rather
than on the two this repo can run in-process:
`tests/integration/test_control_chars.py::TestTheVerticalTabPerlClassDivergence`
puts `vt\shere` to a live tshark over frame 2 of
`tests/fixtures/ctrl_comments.pcapng`, whose comment carries a genuine `0x0b`,
and compares Wireshark's PCRE2 against Python `re` and RE2 over the same
measured value.

## Reader representation: `-T fields` escaping

The three backends above agree on what an expression *means*; they can still
fork on what the **value** is, because the two pcap readers see tshark's output
in different representations. `-T ek` is JSON, so string decoding hands back the
true value. `-T fields` is not: tshark runs value text through a C-style
escaper on the way out, so a control byte arrives as two characters while the
display-filter engine matched against the real one. Left uncorrected, that is a
quiet row-set fork between a pushed-down `-Y` filter and a fields-mode residual
predicate — the divergence issue #74 was filed for.

`src/remora/reader/fields_reader.py` inverts the escaping **when it can**, so a
`RawPacket` from either reader carries the same value. The table is measured,
not assumed: every byte `0x01`–`0x20`, `0x5c` and `0x7f` was probed through a
pcapng frame comment on three builds — 4.2.2 and 4.4.5 from the Ubuntu
archives, 4.6.8 from Homebrew. On 4.4 and later exactly these eight are
escaped.

<!-- fields-escapes:start -->

| byte | `-T fields` prints |
| --- | --- |
| `0x07` | `\a` |
| `0x08` | `\b` |
| `0x09` | `\t` |
| `0x0a` | `\n` |
| `0x0b` | `\v` |
| `0x0c` | `\f` |
| `0x0d` | `\r` |
| `0x5c` | `\\` |

<!-- fields-escapes:end -->

Every other byte passes through raw — `0x01`–`0x06`, `0x0e`–`0x1f` and `0x7f`
were each confirmed. (`0x00` is out of scope: it cannot be carried through the
tooling that builds the fixture, and would truncate tshark's own C strings.)
From 4.4 the mapping is injective, so the inverse is exact: a backslash in the
output is always the first character of one of the eight escapes.

### The escaping is only invertible from tshark 4.4

**tshark 4.2.x does not double a literal backslash** (and leaves `0x07` raw),
which destroys injectivity: the value `C:\temp` and the value `C:` + TAB +
`emp` are *both* printed `C:\temp`, so nothing in the output tells them apart.
Unescaping on such a build would silently rewrite `C:\temp` into `C:<TAB>emp`,
and backslash-bearing values are ordinary traffic (SMB paths, Windows
filenames). Corrupting a common value is strictly worse than the divergence
this fixes.

So unescaping is **gated on the tshark version**, and only unescaping is:

| | tshark < 4.4 | tshark >= 4.4 |
| --- | --- | --- |
| column/occurrence framing | fixed | fixed |
| control bytes recovered in `-T fields` | no — text stays escaped | yes |
| pushdown / fields / ek row sets agree | only where nothing was escaped | always |

Below 4.4 the reader returns tshark's text unchanged, which is exactly the
pre-#74 behavior: the divergence remains, documented, instead of becoming
corruption. `escaping_is_reversible()` decides, an unknown or unparseable
version counts as old, and 4.3.x — a development series between the two
measured releases — is treated as old for the same reason. `-T ek` is correct
on every version and needs no gate. Ubuntu 24.04 LTS ships 4.2.2, so this is
the common case, not a corner: **control-character fidelity in `-T fields`
requires tshark >= 4.4.**

That table is also why the reader's framing bytes are what they are — and
unlike unescaping, **framing is fixed on every version**, because both choices
hold on all three builds measured. tshark writes the **column separator** to
the stream raw, *after* escaping each column, so the separator must be a byte
the escaper replaces (`0x0b`) — then no value can forge it. The **occurrence
aggregator** must be a byte the escaper leaves alone (`0x1e`). Which side of
the escaper the aggregator sits on itself changed in 4.4, in the opposite
direction: 4.2.2 splices it in *after* escaping, 4.4+ *before*. So an escaped
byte works as an aggregator on 4.2.2 and silently stops splitting on 4.4+,
which is precisely why the never-escaped `0x1e` — and not the escaped-byte
trick that secures the column separator — is the only choice correct on both.
Unescaping, when it runs, happens strictly *after* splitting. The reader's
module docstring carries the full argument; `tests/test_fields_reader.py` pins
both invariants and the version gate, and
`tests/integration/test_control_chars.py` re-measures against whatever tshark
is installed, asserting the three row sets (pushdown, fields residual, ek
residual) equal on >= 4.4 and pinning the documented divergence below it, over
`tests/fixtures/ctrl_comments.pcapng`.

## What is still divergent

- **`matches` on non-string fields** is a `TypeError` on all three backends —
  the same error, so this is not a divergence, only a restriction.
- **Time literals** (`datetime`/`timedelta`) are not pushed to display filters
  (M1 decision); the planner keeps them as residual Python predicates. The row
  set is unchanged; only the execution path differs.
- **IEEE-754 NaN literals** reach the same row set three different ways, so this
  is a mechanism difference rather than a semantic one. Python's comparisons
  with NaN are all false, which is what `predicate.py` evaluates directly and
  what `sql.py` compiles to the constant `FALSE`; `dfilter.py` **refuses** with
  `UnsupportedExprError` and the planner falls back to that predicate. The
  asymmetry is deliberate: SQL has a boolean constant to compile to and a
  `DOUBLE` total order that has to be actively neutralized, with no fallback
  engine to defer to, while a display filter has neither the constant nor the
  need. Wireshark does lex `nan` as a literal rather than rejecting it, which
  is why rendering it is not self-protecting and refusal is the fix. What
  tshark does with it *afterwards* is ftype- and version-dependent, and that
  instability is itself the argument against a dfilter-native rendering: on a
  float field a current tshark release rejects ordered comparisons against it
  while Ubuntu noble's stock build — what CI's `checks` leg installs — accepts
  them and matches nothing; on a relative-time field the current release orders
  `nan` below every value, so `frame.time_delta > nan` selects every frame
  carrying the field where Python selects none, while the stock build rejects
  that filter outright. (Measured on 4.6.8 and 4.2.2 respectively; the builds
  are named rather than the versions because the apt one moves with the runner
  image, while the assertions below are build-agnostic by construction.)
  `inf`/`-inf` are pushed down unchanged everywhere, since all three engines
  order them identically. Enforced by
  `tests/test_dfilter.py::TestNaNLiterals` and the four
  `nan-literal-*`/`inf-literal-*` rows of `tests/test_semantics_table.py`. A
  fifth row, `stored-nan-gt`, covers the mirror case — the NaN in the stored
  *value* rather than the literal, under an ordinary pushable `>` — so the
  table is self-contained about NaN from both sides. All three engines exclude
  such a packet, but only DuckDB needs help doing it: its `DOUBLE` order sorts
  NaN greatest, so that row fails if `sql.py`'s `NOT isnan(...)` guard ever
  regresses.
  `tests/test_dfilter_validation.py::TestNaNIsARecognizedDfilterLiteral`/
  `TestInfinityIsPushedDownUnchanged` add a live-binary check, but assert only
  what holds on **both** tested builds: that `nan` lexes where `nam`/`nan5`/`zzz`
  do not, that an ordered NaN comparison is never accepted-and-matching, and
  that infinities are accepted. The per-build divergences above are *recorded*
  in those test docstrings rather than asserted — one build's behavior is
  evidence for the policy, not a contract — and on a build that accepts the
  ordered comparisons the row-set half is witnessed vacuously, since no
  checked-in fixture carries a populated `FT_DOUBLE` field.
- **`contains` on a `BLOB` column** is `UnsupportedSqlExprError`: on a bytes
  field `contains` means a byte *subsequence*, and DuckDB has no subsequence
  match over `BLOB` — its `contains()` is substring on `VARCHAR` and element
  membership on `LIST`, so a multi-value `BLOB[]` column would even be accepted,
  with the wrong meaning. The refusal names the column type the query would have
  run against, `BLOB[]` included. The pcap path runs it.
- **Control bytes in `-T fields` values on tshark < 4.4** stay escaped: that
  build's escaping is not invertible (see above), so the reader refuses to
  guess and the fields-mode residual keeps diverging from the pushdown and ek
  paths for any value tshark escaped. Loud in the sense that matters — the
  behavior is version-determined and pinned by tests on both sides, not
  data-dependent. Fixed by installing tshark >= 4.4.
- **A field value containing `0x1e`** forks into two occurrences in `-T fields`
  mode. tshark escapes the joined string, so what comes back is a function of
  the join alone and the boundaries are unrecoverable for *any* choice of
  aggregator byte; only `-T ek` sees the truth. Pinned as a known trade-off by
  `tests/test_fields_reader.py`, not papered over.
- **Field text tshark could not decode as UTF-8** reaches the predicate backend
  as U+FFFD replacement characters, which cannot round-trip to the original
  bytes. Irreducible; noted in `predicate.py`.

Every difference above is loud — a refusal at compile time or an error at query
time — and none of them is a quiet row-set fork. Everything else must select the
same rows on all three backends, and
`tests/test_sql_duckdb.py::test_sql_backend_matches_the_other_two` fails if it
does not.
