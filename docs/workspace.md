# The DuckDB workspace

A `Capture` dissects a pcap every time you iterate it. A **workspace** dissects
it once, into DuckDB columns, and answers every later question from those
columns — the same `Expr` trees, compiled to a SQL predicate instead of a
display filter. That trade buys scans that are orders of magnitude cheaper and
aggregate queries a display filter cannot express at all; it costs you a file
that must be kept honest about which capture, which filter and which tshark
produced it.

This document is about that honesty: what the file holds and what it does not,
what invalidates it, how it locks, how a table leaves it, and where the cache
path's semantics are identical to the pcap path's and where it instead refuses
out loud. Row sets never fork silently: the one place the cache path answers a
question differently from the pcap path is regex, and there it raises rather
than answering. Two constructs are refused outright for the same reason —
a `matches` pattern RE2 cannot run, and `contains` on a `BLOB` column.

Install it with the `workspace` extra — `pip install 'remora[workspace]'`, which
adds duckdb. `remora.workspace` is import-pure: importing it never imports
duckdb, which only loads when a connection is actually opened.

## Quickstart

Materialize a capture, query the columns, export a table:

<!-- The ci: comment markers below opt a fence into tests/test_workspace_docs.py,
     which mypy-checks it and — in the exec and run modes — executes it in CI. A
     marker must sit on its own line immediately above its ```python fence. -->
<!-- ci:run -->
```python
from remora import IP, TCP
from remora.workspace import Workspace

with Workspace("capture.duckdb", mode="rw") as ws:
    result = ws.materialize("capture.pcap", [IP.src, IP.dst, TCP.port])
    print(result.outcome, result.row_count, "rows")

    for row in ws.query().filter(TCP.port == 443).select(IP.src, TCP.port):
        print(row.frame_number, row.get(IP.src), row.get_all(TCP.port))

    ws.export_parquet("pkts", "pkts.parquet")
```

```text
materialized 3 rows
1 10.0.0.1 (51234, 443)
```

This snippet is executed by CI against a test pcap on every pull request and
every push to `main` (`tests/test_workspace_docs.py`), so it cannot rot.

Four things to read out of it:

- `Workspace(path, mode="rw")` is a context manager. `"ro"` is the default;
  `"rw"` is what creates a file and what writes to one.
- `materialize()` takes field *references* — the same `IP.src` that builds a
  filter — and turns each into a column. Nothing you did not name gets a column.
- `ws.query()` is the cache-side counterpart of `Capture`: immutable, chainable,
  lazy, and it executes only when iterated. Values come back through
  `row.get(IP.src)` / `row.get_all(TCP.port)`, not `pkt[IP].src` — see
  [Rows are not packets](#rows-are-not-packets).
- `export_parquet()` is how a table leaves. It is a derivative, never the
  original.

## A cache, not an archive

**The workspace file does not contain your capture.** It contains the columns
you asked for, and nothing else:

| In the file | Not in the file |
| --- | --- |
| One `pkts` row per selected packet, keyed by `frame_number` | Packet payloads, in any form |
| One column per field named in `materialize()` | Every field you did not name — even ones tshark dissected |
| `frame_number` / `frame_time`, the row-key skeleton | Raw frame bytes, so no re-dissection is possible |
| `streams` rollups, once `build_streams()` has run | Anything a later tshark version would newly dissect |
| `annotations` — your findings, the mutable half | The pcap itself, or a path guaranteed to still resolve |
| The `meta` catalog: schema version, field registry, cache key | — |

So the rule is blunt: **keep the original pcaps.** A question about a field
nobody materialized has to go back to the capture — either as a `Capture` query
or as a re-materialization that adds the column (see
[Reuse](#repeat-materialization-hit-backfill-refuse), which backfills rather
than rebuilds). A workspace whose capture is gone can answer only the questions
its columns already cover, permanently.

The same rule applies one level further out to Parquet: an export holds one
table's columns and nothing else — no payloads, no unprojected fields, no `meta`
catalog — so it is a derivative of a cache of a capture. The pcap stays the
source of truth.

Two smaller consequences worth stating:

- **One workspace holds one capture.** `pkts` has no capture column; the *file*
  is the capture identity, and `meta.cache_keys` records which capture that is.
  A second capture goes into a second workspace file, correlated with
  [`attach()`](#cross-capture-attach) rather than merged.
- **`pkts` has no `PRIMARY KEY`.** `frame_number` is unique and ascending by
  convention, not by constraint — DuckDB would back a key with an ART index that
  taxes exactly the bulk-append path materialization depends on.

## Cache keys and what invalidates them

A workspace records exactly **one** cache key, describing the materialization
`pkts` currently is. Reuse is decided against it, and the key covers everything
that can change what tshark emits:

| Component | What it is | Notes |
| --- | --- | --- |
| Capture fingerprint | `st_size`, `st_mtime_ns`, and a sha256 over the **first and last 64 KiB** | Rendered as `fp1:size=…:mtime=…:probe=…`. Not a whole-file digest — see the blind spot below |
| Projection field set | The tshark abbrevs asked for, **sorted and deduplicated** | So projection order never flips the key, and the subset test is canonical |
| Display filter | The compiled `-Y` string, or `None` | `None` and `""` digest **differently** |
| tshark version | The version string of the binary that ran | Probed with `tshark --version` unless you pass `tshark_version=` |
| **Full effective argv** | Every argument, **verbatim and order-sensitive** | The component people forget; see below |

Components are length-prefixed before hashing, so `-rcap.pcap` can never digest
as `-r cap.pcap`, and the digest carries a `ck1:` scheme prefix so a future
scheme change invalidates stored keys visibly. The capture *path* is stored for
diagnostics but not hashed — argv already carries the path tshark was given, and
the fingerprint identifies the capture by its bytes, so the same capture moved or
renamed is the same capture.

### The argv pitfall

**`-X lua_script:`, `-d` and `-o` change how identical bytes dissect.** A Lua
dissector, a `-d tcp.port==8080,http` decode-as rule, or an `-o` preference
override each make tshark produce different fields from the very same file — so
a cache that ignored them would hand back rows dissected under a *different*
interpretation and look entirely valid doing it. That is precisely the omission
that makes a cache silently wrong, which is why argv is hashed whole rather than
by an allowlist of "interesting" options.

The reuse comparison relaxes exactly three of those arguments, and only because
another component already owns them:

| Argument | Compared as | Owner |
| --- | --- | --- |
| `-e <abbrev>` | not compared | the projection field set |
| `-r <path>` | not compared | the capture fingerprint |
| `-Y <filter>` | not compared | the display filter |
| everything else, `argv[0]` included | **verbatim** | nothing — it must match |

### A reader change can invalidate every stored key

`-E separator=` and `-E aggregator=` are part of the effective argv, and issue
#74 changed the column separator from `0x1f` to `0x0b` so that a value carrying
a control byte can no longer break the column framing. Because the whole argv is
hashed, that changes the cache key of every projection: a workspace materialized
by an earlier remora refuses reuse with `MaterializationMismatchError` naming
the argv, and has to be re-materialized into a fresh workspace file.

This was chosen deliberately over carving the separator arguments out of the
key. The escaping and the framing are what turn tshark's bytes into the values
that land in a column, so two remoras that frame differently do not necessarily
store the same thing — exempting them would be the same class of mistake as
ignoring `-d`. A loud refusal costs one rematerialization; a silent hit would
cost trust in the cache.

### The fingerprint's blind spot

Fingerprinting is `size + mtime_ns + 64 KiB from each end` because materializing
a multi-gigabyte capture must not begin by reading it twice. The price is a real
blind spot, stated rather than hidden: **an in-place edit to the middle of a
large file that changes neither its length nor its mtime fingerprints
identically.** `tests/test_workspace_cachekey.py::TestFingerprint::test_middle_change_does_not_flip`
pins that so it stays a known trade-off rather than becoming an incident.

A backfill inherits it with a sharper edge: it matches its rescan to the stored
rows by frame number, which establishes *row alignment* and nothing about
whether the columns it does not rescan still hold values from the same bytes. If
such an edit also preserves frame numbering, a backfill can join new-field values
read from the edited capture beside old columns read from the original, under a
key that looks valid. `tests/test_workspace_cache.py::TestInheritedFingerprintBlindSpot`
pins the consequence end to end, alongside a companion showing that a *visible*
edit still refuses. If you cannot rule out an in-place edit, materialize into a
fresh workspace file.

### Repeat materialization: hit, backfill, refuse

With the fingerprint, filter, version and argv residue all equal, the field set
decides:

| Outcome | When | What it costs |
| --- | --- | --- |
| `"hit"` | Requested fields ⊆ materialized fields | No dissecting tshark at all — a `list_has_all` test in SQL. The `tshark --version` probe still runs unless you pass `tshark_version=`, because the version is one of the compared components |
| `"backfilled"` | Anything else — at least one requested field has no column yet | One rescan, projecting only `frame.number` plus the *new* fields, filling the new columns with `UPDATE`. No existing column is rewritten, and fields you stop asking for keep their columns |
| `MaterializationMismatchError` | Any other component differs | Nothing is written; the message names each changed component |

<!-- ci:typecheck -->
```python
from remora import IP, TCP
from remora.proto import UDP
from remora.workspace import MaterializationMismatchError, Workspace

with Workspace("capture.duckdb", mode="rw") as ws:
    first = ws.materialize("capture.pcap", [IP.src, TCP.port])
    assert first.outcome == "materialized"

    # Subset of what is stored: no tshark dissection at all.
    again = ws.materialize("capture.pcap", [IP.src])
    assert again.outcome == "hit"

    # A new field: one rescan that fills just the new column.
    wider = ws.materialize("capture.pcap", [IP.src, TCP.port, UDP.srcport])
    assert wider.outcome == "backfilled"
    print([record.abbrev for record in wider.added_fields])

    try:
        ws.materialize("other.pcap", [IP.src])
    except MaterializationMismatchError as exc:
        print("refused:", exc)
```

A backfill is written so that the result is indistinguishable from having asked
for everything at once — the recorded key is recomputed over the union field set
with the argv the equivalent one-shot run *would* have used, and the superseded
key row is deleted rather than accumulated. Refusal, rather than
re-materializing in place, is deliberate: rematerializing would drop rows you may
already have annotated.

`frame.number` and `frame.time` are a special case throughout: they are the
`pkts` row key, so requesting them adds no column, but they still count in the
cache key's field set — a request that adds only those widens the key without any
rescan and reports as a hit.

## Modes and locking

DuckDB allows **one writer at a time per file**, and a read-write connection
holds an exclusive lock for as long as it is open. That single fact shapes the
whole API.

| | `mode="ro"` (default) | `mode="rw"` |
| --- | --- | --- |
| Connection lifetime | One, held for the workspace's lifetime | **None** between operations |
| Lock held | Shared read lock, continuously | Exclusive, for each `write()` **and each `read()`** body |
| For how long | Your program's lifetime | The operation's — and `materialize()` lasts as long as tshark does |
| Other processes | Readers unaffected; writers blocked | Free between operations |
| Missing file | Error naming `mode="rw"` | Created, with the schema |
| Write APIs | `WorkspaceModeError` | Work |

**Why `ro` is the default.** A long-lived read-write connection would block every
other process's *reads* for as long as your program lives — a workspace is a
shared analysis artifact, and the common case is querying one, not writing it. Ro
mode takes a shared lock instead, so any number of readers coexist.

**What `rw` actually does.** It holds no connection between operations. Each
`write()` opens a short-lived read-write connection around exactly one
transaction: commit on clean exit, rollback on exception, close either way. Every
write method (`materialize`, `build_streams`, `add_annotation`, …) is exactly one
such transaction, which is where rollback and prompt lock release come from.
Follow the same discipline in your own code — **short writes** — because the lock
is held for the body of the `with`, not for the statement.

<!-- ci:typecheck -->
```python
from remora import IP
from remora.workspace import Workspace

# Read-mostly: the default, and the one that lets other processes read too.
with Workspace("capture.duckdb") as ws:
    for row in ws.query().filter(IP.src == "10.0.0.1"):
        print(row.frame_number)

# Writing: keep the transaction body short — the exclusive lock spans it.
with Workspace("capture.duckdb", mode="rw") as ws:
    ws.add_annotation("packet", 1, "verdict", "retransmission storm")

    with ws.write() as con:  # raw SQL, still exactly one transaction
        con.execute("DELETE FROM main.annotations WHERE key = 'scratch'")

    ws.compact()  # reclaims what those deletes left behind; needs sole access
```

Two consequences that surprise people:

- **An rw-mode *read* holds the exclusive lock too.** `read()` in rw mode opens a
  read-write-*configured* connection, because DuckDB refuses two live
  same-process connections to one file with different configurations and a read
  may nest inside `write()`. So a long read under `mode="rw"` locks other
  processes out exactly like a write does. A read-mostly caller wants
  `mode="ro"`.
- **A read nested inside `write()` runs on its own connection**, so it does not
  see the enclosing transaction's uncommitted rows.

**`materialize()` holds the lock for as long as tshark takes.** The whole run —
spawn, read, append every batch — is inside one transaction, which is what makes
a failure roll back every row *and* every added column. On a large capture that
is a long exclusive lock; plan for it, and materialize before you hand the file
to other readers.

**Query iteration is not streaming**, deliberately: the whole result set is
fetched inside one `read()` block and decoded afterwards, so a half-consumed
iteration holds no connection and — in rw mode — no lock. Paging would hold the
lock across the *consumer's* loop. The cost is peak memory proportional to the
result's raw tuples; filter harder, or use `arrow()`, or take the connection
`read()` hands out.

### `compact()`

A DuckDB checkpoint truncates only **trailing** free blocks. Emptying a table
therefore shrinks the file mostly by itself, while *scattered* deletes — deleting
annotations, re-running `build_streams()` over and over — leave interior free
blocks the file keeps forever. `compact()` is what reclaims those: it rewrites
every schema, table and row into a sibling `<name>.compacting` file and swaps it
in atomically with `os.replace`.

| Property | Behaviour |
| --- | --- |
| Mode | `rw` only; `WorkspaceModeError` in ro |
| Concurrency | Needs **sole access**. Any other connection — including a read-only reader in another process, or an ro-mode `Workspace` on the same file in this one — makes it fail fast on the lock with **nothing modified** |
| In-process | A `write()` or rw-mode `read()` in flight on *any* `Workspace` for this file raises `WorkspaceError`, and for compaction's duration writers and rw-mode readers fail fast the same way |
| Interruption | The original is replaced whole, so a crash at any point leaves it intact, and at worst a stale temp file the next compact removes |
| Symlinks | Compacts the *resolved* target, so a symlink survives as a symlink. A **hard link** cannot survive an atomic swap: the replaced name gets the new inode, the other name keeps the old one, and the two diverge |
| Permissions | Mode bits are copied onto the temp before the swap, so a `0o640` workspace is not widened to `0o644`. Ownership follows the fresh file |
| Platform | **POSIX-only today.** Windows refuses a rename over a file the process holds open, and `compact()` raises `WorkspaceError` naming that limitation (#85) |

When to run it: after deleting a lot of annotations, after repeated
re-materialization cycles, or before archiving a workspace — not routinely, and
never while anyone else is connected.

## Parquet export

Parquet is remora's **export** format, never its storage format. The live
workspace stays DuckDB-native because it is *mutable* (annotations are the whole
reason); Parquet is how a table leaves for delivery, archival, or a downstream
Spark/Athena load. Importing Parquet back in and partitioned dataset layouts are
both out of scope.

The whole export is one DuckDB `COPY … TO … (FORMAT PARQUET)` statement, so a
table of any size streams to disk without a row passing through Python. It is a
*read*: it works in `mode="ro"` and never opens a write connection. pyarrow is
**not** needed — that is only for `Query.arrow()`, which is the separate
`remora[arrow]` extra.

Three tables are exportable, and the set is closed — a table name cannot be a
bound parameter, so anything else is refused rather than escaped:

| `table=` | Holds |
| --- | --- |
| `"pkts"` | One row per materialized packet: row key plus every field column |
| `"streams"` | One row per `(protocol, stream_id)` conversation rollup |
| `"annotations"` | Your findings |

**Never aim an export at the workspace file.** `COPY` overwrites whatever is at
the destination, so an export aimed at the database is a deletion — and aimed at
its `.wal` sidecar it is a *silent* one, since DuckDB replays a write-ahead log
on open and a log overwritten with Parquet is discarded along with every
committed row it still held. The destination is therefore compared against the
database file and its `.wal` by file **identity** (`st_dev`, `st_ino`, so a
symlink or hard link is seen through) before anything is written, and a match
raises `WorkspaceError`. The export itself is written into a private `0700`
directory beside the destination and renamed into place, so the file `COPY` opens
cannot be swapped for a link after the check, and a failed export leaves the
previous file exactly as it was instead of a truncated one. What remains: the
destination's own directory is trusted, and an external process moving the
database onto the destination path mid-export is not defended against.

### Two deliberate type divergences

Types pass through as themselves — `UINTEGER` IPv4 stays `uint32`, narrow ints
keep their width, `TIMESTAMP` is `timestamp[us]`, `BLOB` is `binary`, a
multi-value `T[]` stays `list<T>`. Exactly two stored types cannot be represented
exactly by DuckDB's Parquet writer, and a documented type change beats a silent
corruption:

| Stored type | Ftype | Exported as | Why | Read back with |
| --- | --- | --- | --- | --- |
| `UHUGEINT` | `FT_IPv6` | `string` (exact decimal text) | duckdb writes 128-bit integers as a **`double`** — 53 mantissa bits for a 128-bit address, so `7fff:…:ffff` and `8000::` collide and nothing is recoverable | `IPv6Address(int(text))`, or `CAST(col AS UHUGEINT)` |
| `INTERVAL` | `FT_RELATIVE_TIME` | `string` (`'00:00:00.001234'`) | Parquet's own interval logical type is millisecond-resolution, so a native write truncates 1234µs to 1000µs | `CAST(col AS INTERVAL)` |

Both rewrites apply at list depth too, so a multi-value `UHUGEINT[]` exports as
`list<string>`. Reading the file back in DuckDB:

```sql
SELECT CAST(ipv6_src AS UHUGEINT) AS ipv6_src,
       CAST(rtt AS INTERVAL) AS rtt
FROM 'pkts.parquet';
```

The same `UHUGEINT`-through-Arrow hazard exists for `Query.arrow()` and is
handled there the same way — DuckDB exports `UHUGEINT` through Arrow as
`decimal128(38, 0)` read as **signed**, so every address with the high bit set
(all of `fe80::/10` and `ff00::/8`) would come back negative. `arrow()` casts
those columns to `VARCHAR` in the SELECT list; the stored type is untouched, and
the DuckDB-native iteration path decodes straight to `IPv6Address`.

## Semantics: NULL and regex

**[`docs/semantics.md`](semantics.md) is the single source for both**, and it is
enforced — unevenly, so it is worth being exact about how. Its absent-field truth
table is *parsed out of the markdown* by `tests/test_semantics_docs.py` and
compared against the operator set the shared semantics table
(`tests/test_semantics_table.py`) actually runs through all three backends. Its
regex matrix is not parsed: what is checked there is that the doc names the real
RE2 repeat limit and the real lookaround prefixes from
`remora.compile.re2`, and quotes the portable-text guard condition
`remora.compile.sql` emits, each read from the code rather than copied. So the
table cannot drift; the matrix's prose around those constants can.

This section says only what a cache-path user has to carry in their head; it does
not restate the table.

**Absence.** An absent field is `NULL` in a scalar column and `[]` in a
multi-value one. Every positive operator is False on an absent field and every
negated one is True — on all three backends, including this one. The one place
SQL had to be pushed to agree is negation over a NULL scalar: `NOT ("col" = ?)`
is `NULL` in three-valued logic, which would *drop* a row that Wireshark and the
Python predicate backend both keep. The SQL backend therefore wraps a NULL-able
leaf in `coalesce(<leaf>, FALSE)` when — and only when — a `Not` will invert it,
at the leaf rather than over the subtree. So `TCP.port != 80` selects the same
rows on a pcap and on a workspace, packets with no TCP layer included.

**Regex.** `matches` reaches three different engines: PCRE2 (display filter),
Python `re` over bytes (predicate), and Google RE2 over runes (DuckDB). Remora
refuses rather than diverging, in two layers:

- **Pattern side**, at SQL compile time: lookarounds, a bounded repeat above
  1000 (counting the product along a nesting path), and **any non-ASCII pattern
  character** raise `UnsupportedSqlExprError`. They are refused only here, not at
  `Expr` construction, so the pcap path keeps constructs PCRE2 and Python `re`
  run identically.
- **Value side**, at query time: a compiled `matches` raises a DuckDB error
  naming the column on any value that is non-ASCII, contains a newline, or
  contains a vertical tab — the three value shapes behind the four mechanisms
  the engines genuinely disagree about (rune-vs-byte counting, Unicode case
  folding, `$` anchoring, and `\s`'s definition). The guard tests the value
  alone, so it refuses a superset: a
  vertical tab is refused even under a pattern that could not observe the
  difference.

`UnsupportedSqlExprError` also covers `contains` on a `BLOB` column — on a bytes
field `contains` means a byte *subsequence*, and DuckDB has no subsequence match
over `BLOB`. It is a statement about the backend, not about your workspace, and
it propagates as itself.

<!-- ci:exec -->
```python
from remora import IP, TCP
from remora.expr import ValueRange
from remora.proto import HTTP

# Identical row sets on both paths: no occurrence equals 80, absent field included.
not_port_80 = TCP.port != 80

# Compiles to BETWEEN over the integer address column — the subnet test, and the
# reason the workspace stores addresses as integers rather than as text.
private = IP.src.in_([ValueRange("10.0.0.0", "10.255.255.255")])

# Fine on the pcap path; UnsupportedSqlExprError on the workspace path.
lookahead = HTTP.request_uri.matches("^/api/(?!internal)")
```

Everything else must select the same rows on all three backends, and it is
measured rather than asserted: `tests/test_sql_duckdb.py` runs the shared
semantics table against a real DuckDB seeded through the real codecs, and
`tests/integration/workspace/test_parity_matrix.py` compares a `Capture` and a
`Query` operator by operator over the same capture.

### Rows are not packets

The cache path deliberately diverges from `pkt[IP].src`. Protocol views are
defined over raw tshark *text*, and a stored row has none — an `FT_ETHER` column
holds bytes, an `FT_ABSOLUTE_TIME` column holds a timestamp — so re-rendering
values as tshark would have printed them is a lossy round trip nobody needs. A
`Row` is therefore not a `RawPacket`, and access is by field reference:

| Packet path | Workspace path |
| --- | --- |
| `pkt[IP].src` → `IPv4Address \| None` | `row.get(IP.src)` → `IPv4Address \| None` |
| `pkt[TCP].port` → `tuple[int, ...]` | `row.get_all(TCP.port)` → `tuple[int, ...]` |
| — | `row.frame_number`, `row.frame_time` (aware UTC) |

The shapes are the descriptor contract's, and multiplicity is checked at access
time: `get()` on a multi-value field raises rather than dropping occurrences.
Three refusals are worth recognizing — `FieldNotMaterializedError` (no column;
re-materialize including it), `FieldNotProjectedError` (a column exists but this
query's `.select()` left it out), and `FieldDeclarationMismatchError` (the
reference's ftype or multiplicity disagrees with the stored catalog, which is
version skew between a workspace and the protocol modules querying it). All three
name the field, but they do not all fire at the same moment.
`FieldNotMaterializedError` is a statement about *storage*. A `Query` is lazy, so
it is raised when the query is executed — from `sql()`, from iteration, or from
`arrow()` — as the plan is built, and still before any generated SQL reaches
DuckDB, because every reference in the filter tree and the projection is checked
against `meta.fields` first. `.filter()` and `.select()` themselves never raise
it; they only build. `FieldNotProjectedError` is a statement about *this query*, and it is
raised at row-access time, from `row.get()`/`row.get_all()` while decoding a
result the database has already returned: a projection is only wrong once you
ask it for something it left out.

`FieldDeclarationMismatchError` fires on **both** paths, because a field
reference is a static type as much as it is a column address. At build time the
declaration is what a literal gets encoded with, so a stale one compiles a
predicate against the wrong column shape; at row access it is what an accessor's
return type was checked as, so a name-only lookup would hand an `IPv4Address`
back through an accessor mypy typed `str | None`. One rule
(`_declaration_mismatch`), applied in the two places a reference is used.

## Annotations

Annotations are the mutable half of the workspace, and the reason storage is
DuckDB-native rather than a pile of immutable Parquet. An annotation targets a
packet (by frame number) or a stream (by the `(protocol, stream_id)` pair
`streams` is keyed by — `tcp` and `udp` each number their conversations from
zero, so a bare id names two rows). `add_annotation` therefore *requires*
`protocol` for `scope="stream"` and *refuses* it for `scope="packet"`, where the
frame number is unique on its own.

The orphan policy is **kept-but-flagged**: annotations are analyst findings, so
nothing in the materialization path ever deletes one. An annotation can name a
row this workspace does not hold — a frame the materialization's filter never
admitted, or a stream that `build_streams()` has not built yet or dropped on a
rebuild — and `list_annotations()` derives `AnnotationRecord.orphaned` at read
time from an `EXISTS` against `pkts`/`streams` rather than storing it, so the
flag follows the current contents and `delete_orphan_annotations()` is the one
explicit call that removes anything.

Note what that does **not** mean: you cannot re-materialize this workspace under
a different filter to widen or narrow what the annotations point at.
`materialize()` compares the requested dfilter against the stored cache key and
raises `MaterializationMismatchError` on any change, pointing at a fresh
workspace file — rematerializing in place would drop rows a caller may already
have annotated, which is the same reasoning as this orphan policy seen from the
other side. Widening means a new workspace, and the annotations do not follow it. `remove_annotations()` refuses a call
with no filters at all — wiping every finding is too destructive to be what zero
arguments means. Ids come from a monotonic high-water mark and are **never
reused**, so a stale id matches nothing rather than naming a different finding.

## Streams: `build_streams()`

Sessionization is the headline capability a display filter cannot express: a
filter selects *packets*, this aggregates the *conversation* each one belongs to.
`ws.build_streams()` writes one `streams` row per `(protocol, stream_id)` pair,
carrying the endpoints, `first_frame`/`last_frame`, `pkt_count`, `byte_count`
and `first_time`/`last_time`. It is one grouped `INSERT … SELECT` per protocol
inside one transaction, and rerunning it replaces the rollups rather than
duplicating them.

It reads nine columns out of `pkts`, and the rule is **all nine, both protocols',
or nothing** — validating each protocol independently would let a capture with no
UDP traffic "succeed" and surface the omission on the next capture instead. A gap
raises `MissingStreamFieldsError` naming the exact abbrevs, before any SQL
touches `pkts`. Materialize them up front:

<!-- ci:exec -->
```python
from remora.fields import FieldRef
from remora.proto import IP, TCP, UDP

# frame.len has no generated protocol module (frame is not in codegen.toml's
# protocol set), so name it directly.
FRAME_LEN: FieldRef[int] = FieldRef("frame.len", "FT_UINT32", False)

STREAM_FIELDS = [
    FRAME_LEN,
    IP.src,
    IP.dst,
    TCP.stream,
    TCP.srcport,
    TCP.dstport,
    UDP.stream,
    UDP.srcport,
    UDP.dstport,
]
```

`byte_count` sums **`frame.len`** — the packet's length on the wire, link-layer
header included, deliberately the definition tshark's own `-z conv,tcp` Bytes
column uses, and not payload bytes or `ip.len`. Endpoints come from the stream's
first frame by frame number, all four read in one aggregate so they describe one
packet: `src` is the initiator and `dst` the responder, matching the A/B ordering
of tshark's conversation table, and a reverse-direction packet later in the
stream never flips them.

**Addresses are IPv4-only, and `NULL` is the signal.** `src_addr`/`dst_addr` come
from `ip.src`/`ip.dst`, so they are NULL exactly when the stream's first frame
carries no IPv4 header. The *ports* are unaffected — they are transport-layer
fields — so an IPv6 stream's row carries real ports, stream id, counts and
timestamps and only lacks addresses. Such rows are kept rather than dropped;
`WHERE src_addr IS NOT NULL` is the documented way to select the fully-addressed
ones. Real IPv6 support would need `UHUGEINT` columns and an address-family
discriminator — a storage-format change, tracked as follow-up work.

## Cross-capture: `attach()`

Correlating two captures is the other reason storage is DuckDB-native. `attach()`
mounts another workspace file under an alias, **read-only in either mode** — the
`ATTACH` always carries `(READ_ONLY)`, which DuckDB enforces, so cross-workspace
writes are impossible rather than merely unattempted. The alias is validated and
the attached file's schema version is checked at attach time, so a foreign or
stale file is refused by path rather than surfacing later as a binder error.

An attachment is recorded and replayed onto every connection the workspace
opens, so it outlives the short-lived connections `rw` mode uses. Every ATTACH a
replay issues is validated, and validated *after* the file is open — so what
gets checked is what actually got attached, and a peer replaced at that path in
between is refused rather than trusted. No disguise on disk (same inode,
restored timestamps) and no swap timed against the check slips a foreign or
stale peer past that, because nothing is decided from the file's metadata
beforehand. A replay that fails detaches whatever it had already attached, so a
failed operation leaves no half-applied attachments behind.

One consequence to know: an attachment binds to the **file** it attached, not to
the pathname. While an alias is live — continuously in `ro` mode, for the
duration of a body in `rw` — replacing the file at its path does not change what
the alias serves, and `attachments` will report a path whose current contents
are not what your queries see. `detach()` and attach again to pick up a
replacement; that validates the new file.

And because the replay runs on every connection, an attachment
DuckDB can no longer honour — a deleted peer, one another process now holds
read-write — fails whatever you were doing, including operations that never
mention it; that reads as a `WorkspaceError` naming the alias, the path and the
remedy (`detach()` it), never as a raw duckdb exception.

<!-- ci:typecheck -->
```python
from remora import IP
from remora.workspace import Workspace

with Workspace("today.duckdb") as ws:
    ws.attach("yesterday.duckdb", "peer")

    # A query against the attached workspace: its pkts, its meta.fields.
    for row in ws.query(alias="peer").filter(IP.src == "10.0.0.1"):
        print(row.frame_number)

    # A cross-capture *join* is ordinary SQL over the connection read() hands out.
    with ws.read() as con:
        rows = con.execute(
            "SELECT p.ip_src, count(*) FROM main.pkts p "
            'JOIN "peer".main.pkts q USING (ip_src) GROUP BY 1'
        ).fetchall()
    print(rows)
```

`Query` stays single-table on purpose; a join is SQL, on the connection `read()`
already gives you. What an attachment costs: a shared read lock on the peer file
for as long as a connection carrying it is open. In `ro` mode that connection is
held continuously, so the peer cannot be opened read-write until you detach; in
`rw` mode the attachment exists only for each `read()`/`write()` body, so between
operations the peer opens read-write fine.

## Where the rules live

| Rule | Enforced in |
| --- | --- |
| Absent-field truth table, regex matrix, portable-text guard | [`docs/semantics.md`](semantics.md), `tests/test_semantics_docs.py`, `tests/test_sql_duckdb.py` |
| Cache key components and the fingerprint blind spot | `tests/test_workspace_cachekey.py`, `tests/test_workspace_cache.py` |
| Hit / backfill / refuse | `tests/test_workspace_materialize.py`, `tests/test_workspace_cache.py` |
| Modes, locking, `compact()` coordination | `tests/test_workspace_lifecycle.py` |
| Export destination safety and the two type rewrites | `tests/test_workspace_export.py` |
| The three query-time refusals, at both the moments they fire | `tests/test_workspace_query.py` |
| Pcap-path / cache-path parity | `tests/integration/workspace/test_parity_matrix.py` |
| This document's fences | `tests/test_workspace_docs.py` |
