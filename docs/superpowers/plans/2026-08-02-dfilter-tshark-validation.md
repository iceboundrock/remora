# Dfilter tshark Validation Implementation Plan (issue #18)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every compiled display filter in the test suite — golden strings and ≥200 seeded random expression trees — is syntax-validated by a real tshark in CI, plus a semantics spot-check that tshark's `!(x == v)` row set matches the predicate backend's `!=` row set on fixture pcaps.

**Architecture:** Test-suite-only work (no `src/remora` changes). The golden `(Expr, expected-string)` pairs move out of `tests/test_dfilter.py` into a shared corpus module `tests/dfilter_corpus.py` whose stub fields all use **real** tshark field names, so every golden string is valid parser input. A seeded generator `tests/exprgen.py` produces random `Expr` trees over the same real fields. A new integration-marked suite `tests/test_dfilter_validation.py` batch-validates all compiled strings through `tshark -r <fixture.pcap> -Y <filter>` (OR-joined chunks, bisect on failure) and runs the `!=` semantics parity check.

**Tech Stack:** pytest, subprocess (tshark), `random.Random` (seeded), existing fixtures `tests/fixtures/*.pcap`.

## Global Constraints

- Python ≥3.10; everything runs through `uv` (`uv run pytest`, `uv run mypy --strict src tests`, `uv run ruff check .`, `uv run ruff format --check .`). The CI gate is all four — run the full gate before each commit.
- `mypy --strict` covers `tests/` — all new test code must be fully typed.
- ruff line-length 100.
- **Do not modify `src/remora/`.** Bugs found by validation get filed as separate issues (issue #18 scope), not fixed here.
- New test helper modules live in `tests/` root (NOT `tests/integration/`) so same-directory imports work exactly like the existing `from conftest import FakePacket` pattern for both pytest and mypy.
- tshark-requiring tests use the exact skip pattern from `tests/integration/test_end_to_end.py:37-44`: `pytest.mark.integration` + skipif on `shutil.which(os.environ.get("TSHARK") or "tshark") is None and not os.environ.get("REMORA_REQUIRE_TSHARK")`. CI already installs tshark and sets `REMORA_REQUIRE_TSHARK=1`, so no CI workflow changes are needed.
- Branch: `feat/issue-18-dfilter-validation` off `main`. PR body includes `Closes #18`.
- `tests/test_proto_seed.py` pairing tests must keep passing unmodified.

## Pre-verified facts (do not re-litigate)

- Local tshark/dftest 4.6.7 accept ALL current golden-string shapes: `\xHH` and `\a\b\f\v` escapes in strings, non-ASCII UTF-8, empty string `""`, string/bytes/IPv6 ordered comparisons (`>`, `<`), `tcp.flags.syn == 1`, `1e-05`/`1e+21` scientific notation, `!(...)` forms, deep parenthesized nesting.
- Invalid filters make tshark exit with code **4** and print the reason to stderr (e.g. `tshark: "bogus.field" is not a valid protocol or protocol field.`). NOTE: `===` is VALID in Wireshark 4.x (all_eq operator) — don't use it as an "invalid" example.
- `frame.loss` (used by the old `LOSS` stub) is NOT a real tshark field. `icmp.resptime` is a real, unconditionally registered `FT_DOUBLE` field — use it as the double-typed stub.
- `x.custom` is intentionally fake (tests the unknown-ftype fallback) — its golden string can never validate; it stays inline in `test_dfilter.py`, excluded from the corpus.
- Real ftypes used by new stubs: `tcp.seq` = FT_UINT32, `udp.length` = FT_UINT16.
- OR-joining parenthesized filters is a sound batch-validation strategy: a display filter is valid iff all parenthesized operands are valid; on chunk failure, re-check each filter individually to attribute blame.

## File Structure

- Create `tests/dfilter_corpus.py` — `StubField` (moved from `test_dfilter.py`, plus `__repr__`), stub field constants (all real tshark names), `GoldenCase` NamedTuple, `GOLDEN` tuple of every golden pair.
- Modify `tests/test_dfilter.py` — one parametrized golden test over `GOLDEN`; keeps inline the tests that can't join the corpus (structural asserts, error cases, fake-field fallback, unsupported exprs).
- Create `tests/exprgen.py` — seeded random `Expr`-tree generator over real fields.
- Create `tests/test_exprgen.py` — generator unit tests (no tshark needed).
- Create `tests/test_dfilter_validation.py` — integration-marked tshark validation + semantics parity.

---

### Task 1: Extract shared golden corpus with real field names

**Files:**
- Create: `tests/dfilter_corpus.py`
- Modify: `tests/test_dfilter.py`

**Interfaces:**
- Produces: `tests/dfilter_corpus.py` exporting `StubField`, stub constants `SRC, DST, SRC6, PORT, HOST, PAYLOAD, TIME, DELTA, SYN, RESPTIME`, `GoldenCase(id: str, expr: Expr, expected: str)` NamedTuple, and `GOLDEN: tuple[GoldenCase, ...]`. Tasks 2 and 3 import these.

- [ ] **Step 1: Create branch**

```bash
git checkout main && git pull && git checkout -b feat/issue-18-dfilter-validation
```

Also commit this plan file if not yet committed.

- [ ] **Step 2: Write `tests/dfilter_corpus.py`**

Move `StubField` verbatim from `test_dfilter.py`, add a readable `__repr__`, define stubs with real field names (the old `LOSS = StubField("frame.loss", "FT_DOUBLE")` becomes `RESPTIME = StubField("icmp.resptime", "FT_DOUBLE")`), and list every golden pair currently asserted in `test_dfilter.py`:

```python
"""Shared display-filter golden corpus (issue #18).

Single source of truth for (Expr, expected display-filter string) pairs,
consumed by:

- tests/test_dfilter.py — golden-string equality against compile_dfilter
- tests/test_dfilter_validation.py — every golden string is syntax-validated
  by a real tshark

Every StubField here uses a REAL tshark field name with its real ftype, so
each golden string is valid input for tshark's display-filter parser. Cases
whose strings cannot validate (the deliberately fake ``x.custom`` field) live
inline in test_dfilter.py instead, excluded from this corpus.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import NamedTuple

from remora.expr import Expr, FieldExprOps


class StubField(FieldExprOps):
    """Minimal FieldLike for tests; mirrors remora.fields.FieldRef."""

    __slots__ = ("_ftype", "_multi", "_name")

    def __init__(self, name: str, ftype: str = "FT_STRING", multi: bool = False) -> None:
        self._name = name
        self._ftype = ftype
        self._multi = multi

    @property
    def name(self) -> str:
        return self._name

    @property
    def ftype(self) -> str:
        return self._ftype

    @property
    def multi(self) -> bool:
        return self._multi

    def __repr__(self) -> str:
        return f"StubField({self._name!r}, {self._ftype!r})"


# All real tshark fields (verified against `tshark -G fields`, Wireshark 4.6).
SRC = StubField("ip.src", "FT_IPv4")
DST = StubField("ip.dst", "FT_IPv4")
SRC6 = StubField("ipv6.src", "FT_IPv6")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)
HOST = StubField("http.host", "FT_STRING")
PAYLOAD = StubField("tcp.payload", "FT_BYTES")
TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")
DELTA = StubField("frame.time_delta", "FT_RELATIVE_TIME")
SYN = StubField("tcp.flags.syn", "FT_BOOLEAN")
RESPTIME = StubField("icmp.resptime", "FT_DOUBLE")


class GoldenCase(NamedTuple):
    """One golden pair: compile_dfilter(expr) must equal expected, and
    expected must be accepted by a real tshark."""

    id: str
    expr: Expr
    expected: str


GOLDEN: tuple[GoldenCase, ...] = (
    # comparison operators
    GoldenCase("eq", PORT == 443, "tcp.port == 443"),
    GoldenCase("lt", PORT < 1024, "tcp.port < 1024"),
    GoldenCase("le", PORT <= 1024, "tcp.port <= 1024"),
    GoldenCase("gt", PORT > 1024, "tcp.port > 1024"),
    GoldenCase("ge", PORT >= 1024, "tcp.port >= 1024"),
    # != arrives as Not(Comparison(EQ)) and renders !(field == value) — never
    # Wireshark's multi-value `!=` pitfall.
    GoldenCase("ne-negated-eq", PORT != 443, "!(tcp.port == 443)"),
    # floats
    GoldenCase("float-gt", RESPTIME > 0.25, "icmp.resptime > 0.25"),
    GoldenCase("float-int-widened", RESPTIME > 1, "icmp.resptime > 1.0"),
    GoldenCase("float-sci-small", RESPTIME > 1e-05, "icmp.resptime > 1e-05"),
    GoldenCase("float-sci-large", RESPTIME < 1e21, "icmp.resptime < 1e+21"),
    # presence
    GoldenCase("presence", SRC.present(), "ip.src"),
    # boolean structure
    GoldenCase(
        "and",
        (SRC == "10.0.0.1") & (PORT == 443),
        "(ip.src == 10.0.0.1) && (tcp.port == 443)",
    ),
    GoldenCase(
        "or",
        (SRC == "10.0.0.1") | (DST == "10.0.0.2"),
        "(ip.src == 10.0.0.1) || (ip.dst == 10.0.0.2)",
    ),
    GoldenCase("not-presence", ~SRC.present(), "!(ip.src)"),
    GoldenCase(
        "not-over-or-conjoined",
        ~((SRC == "10.0.0.1") | (PORT == 443)) & (DST == "10.0.0.2"),
        "(!((ip.src == 10.0.0.1) || (tcp.port == 443))) && (ip.dst == 10.0.0.2)",
    ),
    GoldenCase(
        "and-left-leaning",
        ((SRC == "10.0.0.1") & (PORT == 443)) & (DST == "10.0.0.2"),
        "((ip.src == 10.0.0.1) && (tcp.port == 443)) && (ip.dst == 10.0.0.2)",
    ),
    GoldenCase(
        "and-right-leaning",
        (SRC == "10.0.0.1") & ((PORT == 443) & (DST == "10.0.0.2")),
        "(ip.src == 10.0.0.1) && ((tcp.port == 443) && (ip.dst == 10.0.0.2))",
    ),
    GoldenCase(
        "or-inside-and-inside-not",
        ~((SRC.present() & (PORT >= 1024)) | (SYN == True)),  # noqa: E712
        "!(((ip.src) && (tcp.port >= 1024)) || (tcp.flags.syn == 1))",
    ),
    GoldenCase("double-negation", ~~(PORT == 443), "!(!(tcp.port == 443))"),
    # string literals
    GoldenCase("str-plain", HOST == "example.com", 'http.host == "example.com"'),
    GoldenCase("str-embedded-quote", HOST == 'say "hi"', 'http.host == "say \\"hi\\""'),
    GoldenCase("str-backslash", HOST == "a\\b", 'http.host == "a\\\\b"'),
    GoldenCase("str-backslash-quote", HOST == '\\"', 'http.host == "\\\\\\""'),
    GoldenCase("str-non-ascii", HOST == "café.example", 'http.host == "café.example"'),
    GoldenCase("str-named-controls", HOST == "a\nb\tc\rd", 'http.host == "a\\nb\\tc\\rd"'),
    GoldenCase("str-named-controls-2", HOST == "\a\b\f\v", 'http.host == "\\a\\b\\f\\v"'),
    GoldenCase("str-hex-controls", HOST == "\x00\x1b\x7f", 'http.host == "\\x00\\x1b\\x7f"'),
    # address literals
    GoldenCase("ipv4-from-str", SRC == "10.0.0.1", "ip.src == 10.0.0.1"),
    GoldenCase("ipv4-object", SRC == IPv4Address("10.0.0.1"), "ip.src == 10.0.0.1"),
    GoldenCase("ipv6-compressed", SRC6 == "2001:0db8:0::1", "ipv6.src == 2001:db8::1"),
    # bytes literals
    GoldenCase("bytes-colon-hex", PAYLOAD == b"\xaa\xbb\xcc", "tcp.payload == aa:bb:cc"),
    GoldenCase("bytes-from-str", PAYLOAD == "aabbcc", "tcp.payload == aa:bb:cc"),
    # bool literals
    GoldenCase("bool-true", SYN == True, "tcp.flags.syn == 1"),  # noqa: E712
    GoldenCase("bool-false", SYN == False, "tcp.flags.syn == 0"),  # noqa: E712
)
```

- [ ] **Step 3: Rewrite `tests/test_dfilter.py` to consume the corpus**

Replace the whole file. The parametrized golden test covers everything in `GOLDEN`; the retained inline tests are exactly those that cannot live in the corpus (structural asserts, fake fields, error paths):

```python
"""Golden-string tests for the Wireshark display-filter backend.

The golden (expr, expected) pairs live in dfilter_corpus.GOLDEN — shared with
tests/test_dfilter_validation.py, which syntax-validates every expected string
against a real tshark. Only cases that cannot join that corpus stay inline
here: structural assertions, deliberately fake fields, and error paths.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from dfilter_corpus import GOLDEN, PAYLOAD, PORT, SRC, GoldenCase, StubField

from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.expr import Expr

TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")
DELTA = StubField("frame.time_delta", "FT_RELATIVE_TIME")
# Deliberately fake: exercises the unknown-ftype fallback. Its golden string
# can never validate against a real tshark, so it is excluded from GOLDEN.
CUSTOM = StubField("x.custom", "FT_SOMETHING_NEW")


class TestGoldenCorpus:
    @pytest.mark.parametrize("case", GOLDEN, ids=[case.id for case in GOLDEN])
    def test_compiles_to_golden_string(self, case: GoldenCase) -> None:
        assert compile_dfilter(case.expr) == case.expected

    def test_corpus_ids_are_unique(self) -> None:
        ids = [case.id for case in GOLDEN]
        assert len(ids) == len(set(ids))


class TestStructuralInvariants:
    def test_eq_on_multi_value_field_means_any_occurrence_matches(self) -> None:
        # Wireshark semantics: tcp.port occurs twice per packet (src and dst);
        # `tcp.port == 443` is true if ANY occurrence equals 443. That is the
        # DSL's intended meaning, so plain == passes through unchanged.
        assert PORT.multi is True
        assert compile_dfilter(PORT == 443) == "tcp.port == 443"

    def test_ne_compiles_to_negated_eq_never_bang_eq(self) -> None:
        # Wireshark's `tcp.port != 443` on a multi-value field means "SOME
        # occurrence differs" — almost never what the user meant. The DSL's !=
        # arrives as Not(Comparison(EQ, ...)) and must render as
        # !(field == value): "NO occurrence equals".
        rendered = compile_dfilter(PORT != 443)
        assert rendered == "!(tcp.port == 443)"
        assert "!=" not in rendered


class TestFallbacksAndErrors:
    def test_unknown_ftype_falls_back_to_quoted_string(self) -> None:
        assert compile_dfilter(CUSTOM == "hello") == 'x.custom == "hello"'

    def test_bad_ip_literal_raises_value_error_not_unsupported(self) -> None:
        with pytest.raises(ValueError, match="not-an-ip"):
            compile_dfilter(SRC == "not-an-ip")

    def test_empty_bytes_raise_unsupported(self) -> None:
        with pytest.raises(UnsupportedExprError, match="empty bytes"):
            compile_dfilter(PAYLOAD == b"")


class TestUnsupported:
    def test_datetime_comparison_raises_unsupported(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(UnsupportedExprError, match="time comparisons"):
            compile_dfilter(TIME >= moment)  # noqa: SIM300

    def test_timedelta_comparison_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedExprError, match="time comparisons"):
            compile_dfilter(DELTA > timedelta(milliseconds=1))  # noqa: SIM300

    def test_unknown_expr_subclass_raises_unsupported(self) -> None:
        class FutureNode(Expr):
            __slots__ = ()

        with pytest.raises(UnsupportedExprError, match="FutureNode"):
            compile_dfilter(FutureNode())
```

Note: `TIME`/`DELTA` moved here (they never produce golden strings), but the corpus also defines them for the record — either keep them in only one place or import from corpus; prefer importing from corpus and delete the local definitions if mypy/ruff are happy. Keep whichever direction leaves no duplicate definitions. (If importing, drop `TIME`/`DELTA` locals above and add them to the corpus import list.) The noqa comments may need adjusting to whatever ruff actually flags — run ruff and fix.

- [ ] **Step 4: Run the gate**

```bash
uv run pytest tests/test_dfilter.py -v
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
```

Expected: all pass; golden coverage identical to before (same strings, `frame.loss` → `icmp.resptime` rename only).

- [ ] **Step 5: Commit**

```bash
git add tests/dfilter_corpus.py tests/test_dfilter.py docs/superpowers/plans/2026-08-02-dfilter-tshark-validation.md
git commit -m "test: extract shared dfilter golden corpus with real field names (#18)"
```

---

### Task 2: Seeded random expression-tree generator

**Files:**
- Create: `tests/exprgen.py`
- Create: `tests/test_exprgen.py`

**Interfaces:**
- Consumes: `dfilter_corpus.StubField` and stub constants (Task 1).
- Produces: `exprgen.gen_corpus(seed: int = DEFAULT_SEED, count: int = DEFAULT_COUNT) -> list[Expr]` and constants `DEFAULT_SEED`, `DEFAULT_COUNT` (= 200). Task 3 calls `gen_corpus()`.

- [ ] **Step 1: Write the failing tests (`tests/test_exprgen.py`)**

```python
"""Unit tests for the seeded random Expr-tree generator (no tshark needed)."""

from __future__ import annotations

from exprgen import DEFAULT_COUNT, DEFAULT_SEED, gen_corpus

from remora.compile.dfilter import compile_dfilter


class TestDeterminism:
    def test_same_seed_same_corpus(self) -> None:
        first = [compile_dfilter(e) for e in gen_corpus(seed=123, count=50)]
        second = [compile_dfilter(e) for e in gen_corpus(seed=123, count=50)]
        assert first == second

    def test_different_seed_different_corpus(self) -> None:
        first = [compile_dfilter(e) for e in gen_corpus(seed=1, count=50)]
        second = [compile_dfilter(e) for e in gen_corpus(seed=2, count=50)]
        assert first != second


class TestDefaultCorpus:
    def test_produces_at_least_200_trees(self) -> None:
        assert DEFAULT_COUNT >= 200
        assert len(gen_corpus()) == DEFAULT_COUNT

    def test_every_tree_compiles_to_a_dfilter(self) -> None:
        # The generator must only build shapes the dfilter backend supports:
        # no datetime/timedelta literals, no empty bytes.
        for tree in gen_corpus():
            compiled = compile_dfilter(tree)
            assert compiled

    def test_corpus_has_variety(self) -> None:
        compiled = {compile_dfilter(e) for e in gen_corpus(seed=DEFAULT_SEED, count=200)}
        assert len(compiled) >= 150
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_exprgen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'exprgen'`.

- [ ] **Step 3: Write `tests/exprgen.py`**

```python
"""Seeded random Expr-tree generator for dfilter validation (issue #18).

Generates trees only over shapes the dfilter backend supports (no
datetime/timedelta literals, no empty bytes) using real tshark field names, so
every compiled filter must be accepted by a real tshark parser. Determinism:
same seed, same corpus — required so a CI failure reproduces locally.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address

from dfilter_corpus import DST, HOST, PAYLOAD, PORT, RESPTIME, SRC, SRC6, SYN, StubField

from remora.expr import And, CompareOp, Comparison, Expr, LiteralValue, Not, Or, Presence

DEFAULT_SEED = 20260802
DEFAULT_COUNT = 200

_MAX_DEPTH = 4
_LEAF_PROBABILITY = 0.35
_PRESENCE_PROBABILITY = 0.15

SEQ = StubField("tcp.seq", "FT_UINT32")
ULEN = StubField("udp.length", "FT_UINT16")

_ORDERED = (CompareOp.EQ, CompareOp.LT, CompareOp.LE, CompareOp.GT, CompareOp.GE)
_EQ_ONLY = (CompareOp.EQ,)

_TRICKY_STRINGS = (
    "example.com",
    'say "hi"',
    "a\\b",
    "café.example",
    "a\nb\tc\rd",
    "\x1b[0m",
    "",
)

_SPECIAL_FLOATS = (0.0, 0.25, 1e-05, 1e21)


def _gen_string(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return rng.choice(_TRICKY_STRINGS)
    length = rng.randrange(1, 12)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789.-") for _ in range(length))


def _gen_float(rng: random.Random) -> float:
    if rng.random() < 0.3:
        return rng.choice(_SPECIAL_FLOATS)
    return round(rng.uniform(0.0, 1000.0), 6)


def _gen_bytes(rng: random.Random) -> bytes:
    return rng.randbytes(rng.randrange(1, 9))


#: (field, allowed comparison ops, literal generator)
_FIELD_SPECS: tuple[tuple[StubField, tuple[CompareOp, ...], Callable[[random.Random], LiteralValue]], ...] = (
    (SRC, _ORDERED, lambda rng: IPv4Address(rng.getrandbits(32))),
    (DST, _ORDERED, lambda rng: IPv4Address(rng.getrandbits(32))),
    (SRC6, _ORDERED, lambda rng: IPv6Address(rng.getrandbits(128))),
    (PORT, _ORDERED, lambda rng: rng.randrange(65536)),
    (SEQ, _ORDERED, lambda rng: rng.randrange(2**32)),
    (ULEN, _ORDERED, lambda rng: rng.randrange(65536)),
    (HOST, _ORDERED, _gen_string),
    (PAYLOAD, _ORDERED, _gen_bytes),
    (SYN, _EQ_ONLY, lambda rng: rng.random() < 0.5),
    (RESPTIME, _ORDERED, _gen_float),
)


def _gen_leaf(rng: random.Random) -> Expr:
    field, ops, literal_gen = rng.choice(_FIELD_SPECS)
    if rng.random() < _PRESENCE_PROBABILITY:
        return Presence(field)
    return Comparison(rng.choice(ops), field, literal_gen(rng))


def gen_expr(rng: random.Random, depth: int = 0) -> Expr:
    """Generate one random Expr tree, at most ``_MAX_DEPTH`` connectives deep."""
    if depth >= _MAX_DEPTH or rng.random() < _LEAF_PROBABILITY:
        return _gen_leaf(rng)
    kind = rng.random()
    if kind < 0.4:
        return And(gen_expr(rng, depth + 1), gen_expr(rng, depth + 1))
    if kind < 0.8:
        return Or(gen_expr(rng, depth + 1), gen_expr(rng, depth + 1))
    return Not(gen_expr(rng, depth + 1))


def gen_corpus(seed: int = DEFAULT_SEED, count: int = DEFAULT_COUNT) -> list[Expr]:
    """Generate ``count`` random trees from ``seed``, deterministically."""
    rng = random.Random(seed)
    return [gen_expr(rng) for _ in range(count)]
```

Formatting note: the `_FIELD_SPECS` annotation line exceeds 100 chars — introduce a type alias, e.g. `_FieldSpec = tuple[StubField, tuple[CompareOp, ...], Callable[[random.Random], LiteralValue]]`, then `_FIELD_SPECS: tuple[_FieldSpec, ...] = (...)`. Run `uv run ruff format` on the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_exprgen.py -v`
Expected: PASS (5 tests). If `test_corpus_has_variety` fails, the generator is degenerate — raise `_MAX_DEPTH`/literal ranges rather than lowering the threshold.

- [ ] **Step 5: Full gate, then commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
git add tests/exprgen.py tests/test_exprgen.py
git commit -m "test: add seeded random Expr-tree generator (#18)"
```

---

### Task 3: tshark validation suite + `!=` semantics parity

**Files:**
- Create: `tests/test_dfilter_validation.py`

**Interfaces:**
- Consumes: `dfilter_corpus.GOLDEN` (Task 1), `exprgen.gen_corpus` (Task 2), `remora.Capture`, `remora.compile.predicate.compile_predicate`, fixtures `tests/fixtures/tcp_mixed.pcap` + `dns_multi.pcap`.

- [ ] **Step 1: Write `tests/test_dfilter_validation.py`**

```python
"""Validate compiled display filters against a real tshark (issue #18).

Two halves:

1. Syntax: every golden string in dfilter_corpus.GOLDEN and every filter
   compiled from exprgen's 200-tree seeded corpus must be accepted by
   ``tshark -r <fixture> -Y <filter>``. Filters are batch-validated in
   OR-joined chunks (one tshark spawn per ~32 filters); a failing chunk is
   bisected filter-by-filter so the report names each offending tree and
   filter string.

2. Semantics: the row set tshark returns for ``!(x == v)`` must match the
   predicate backend's row set for the DSL's ``!=`` on the fixture pcaps —
   including the multi-value (tcp.port) and absent-field (ARP frame) cases.

Runs whenever tshark is installed; in CI, REMORA_REQUIRE_TSHARK=1 turns the
"tshark missing" skip into a hard failure so the suite can never silently
vanish.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from dfilter_corpus import GOLDEN
from exprgen import gen_corpus

from remora import DNS, IP, TCP, UDP, Capture
from remora.compile.dfilter import compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

# Same skip contract as tests/integration/: skipped with a clear message when
# tshark is absent locally; REMORA_REQUIRE_TSHARK (set in CI) turns a missing
# tshark into a hard failure instead of a silent skip.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping dfilter validation tests",
    ),
]

_TSHARK = os.environ.get("TSHARK") or "tshark"
_CHUNK_SIZE = 32


def _run_tshark(dfilter: str, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    argv = [_TSHARK, "-n", "-r", str(TCP_MIXED), "-Y", dfilter, *(extra or [])]
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _assert_all_valid(cases: list[tuple[str, str]]) -> None:
    """``cases`` is (description, filter). Chunk-validate via OR-join; on a
    failing chunk, re-check each filter individually to attribute blame."""
    failures: list[str] = []
    for start in range(0, len(cases), _CHUNK_SIZE):
        chunk = cases[start : start + _CHUNK_SIZE]
        joined = " || ".join(f"({dfilter})" for _, dfilter in chunk)
        if _run_tshark(joined).returncode == 0:
            continue
        for description, dfilter in chunk:
            result = _run_tshark(dfilter)
            if result.returncode != 0:
                failures.append(
                    f"{description}\n  filter: {dfilter}\n  tshark: {result.stderr.strip()}"
                )
    if failures:
        pytest.fail(
            "tshark rejected compiled display filters:\n" + "\n".join(failures), pytrace=False
        )


class TestGoldenCorpusValidates:
    def test_every_golden_string_is_accepted_by_tshark(self) -> None:
        _assert_all_valid([(f"golden[{case.id}]", case.expected) for case in GOLDEN])


class TestGeneratedCorpusValidates:
    def test_all_generated_filters_are_accepted_by_tshark(self) -> None:
        trees = gen_corpus()
        assert len(trees) >= 200
        _assert_all_valid(
            [(f"tree[{i}]: {tree!r}", compile_dfilter(tree)) for i, tree in enumerate(trees)]
        )


def _tshark_matching_frames(pcap: Path, dfilter: str) -> set[int]:
    argv = [
        _TSHARK, "-n", "-r", str(pcap), "-Y", dfilter, "-T", "fields", "-e", "frame.number",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"tshark rejected {dfilter!r}: {result.stderr.strip()}"
    return {int(line) for line in result.stdout.split() if line}


def _predicate_matching_frames(pcap: Path, expr: Expr) -> set[int]:
    predicate = compile_predicate(expr)
    packets = list(Capture(pcap))  # no filter: every frame, in file order
    return {number for number, packet in enumerate(packets, start=1) if predicate(packet)}


class TestNeSemanticsParity:
    """The DSL's ``!=`` compiles to ``!(x == v)``; tshark's row set for that
    filter must equal the predicate backend's row set for the same Expr —
    multi-value fields match on ANY occurrence, and frames lacking the field
    entirely (the ARP frame) satisfy the negation on both sides."""

    @pytest.mark.parametrize(
        ("pcap", "expr"),
        [
            pytest.param(TCP_MIXED, TCP.port != 443, id="multi-value-tcp-port"),
            pytest.param(TCP_MIXED, IP.src != "10.0.0.1", id="scalar-ip-src"),
            pytest.param(TCP_MIXED, UDP.dstport != 53, id="mostly-absent-udp-dstport"),
            pytest.param(DNS_MULTI, DNS.qry_name != "alpha.example", id="multi-occurrence-dns"),
        ],
    )
    def test_ne_row_set_matches_predicate_backend(self, pcap: Path, expr: Expr) -> None:
        dfilter = compile_dfilter(expr)
        assert dfilter.startswith("!(")  # sanity: != really is negated ==
        assert _tshark_matching_frames(pcap, dfilter) == _predicate_matching_frames(pcap, expr)
```

Check the real attribute names on the seed protocol classes before writing (e.g. `DNS.qry_name`, `UDP.dstport` — see `src/remora/proto/`); adjust if the seeds name them differently.

- [ ] **Step 2: Run the suite locally with tshark present**

Run: `uv run pytest tests/test_dfilter_validation.py -v`
Expected: PASS. Failure triage:
- A rejected **golden** string or rejected **generated** filter means the compiler emits something outside Wireshark's grammar → do NOT change `src/remora`; file a separate GitHub issue quoting the offending tree/filter/stderr, and narrow the generator (or corpus field choice) so the suite passes without hiding the report. Note the follow-up issue number in the PR body.
- A semantics-parity mismatch likewise gets filed separately; only reshape the test if the mismatch traces to a wrong fixture assumption (e.g. wrong frame count), not to real divergence.

- [ ] **Step 3: Verify the skip path and the CI-required path**

```bash
TSHARK=definitely-not-a-binary uv run pytest tests/test_dfilter_validation.py -v      # expect: all SKIPPED with clear reason
TSHARK=definitely-not-a-binary REMORA_REQUIRE_TSHARK=1 uv run pytest tests/test_dfilter_validation.py -v  # expect: FAILURES (binary missing), NOT skips
uv run pytest -m "not integration"                                                    # expect: validation suite deselected
```

The second command failing loudly (FileNotFoundError from subprocess) is the desired behavior — CI can never silently skip.

- [ ] **Step 4: Full gate, then commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
git add tests/test_dfilter_validation.py
git commit -m "test: validate compiled display filters against real tshark (#18)"
```

---

### Task 4: Final gate and PR

- [ ] **Step 1: Run the complete CI gate one final time**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
```

Expected: everything green, including the integration-marked validation suite (tshark is installed locally).

- [ ] **Step 2: Push and open the PR**

```bash
git push -u origin feat/issue-18-dfilter-validation
gh pr create --title "test: validate compiled display filters against real tshark" --body "..."
```

PR body must include `Closes #18`, summarize the three pieces (shared golden corpus on real fields, seeded 200-tree generator, tshark batch validation + `!=` semantics parity), and list any follow-up issues filed for bugs the validation uncovered.

---

## Acceptance-criteria mapping

- "Every display-filter golden string … syntax-validated by a real tshark in CI" → Task 1 single-sources the strings; Task 3 `TestGoldenCorpusValidates`; CI already runs integration tests with `REMORA_REQUIRE_TSHARK=1`.
- "Seeded generator produces ≥200 trees; all compiled filters validate; failure prints the offending tree and filter string" → Task 2 (`DEFAULT_COUNT = 200`, determinism tests); Task 3 `TestGeneratedCorpusValidates` (`tree[{i}]: {tree!r}` + filter + stderr in the failure report).
- "Semantics spot-check … `!(x == v)` row set matches predicate backend's `!=` row set" → Task 3 `TestNeSemanticsParity` over both fixture pcaps, covering multi-value, scalar, absent-field, and multi-occurrence cases.
- "Skipped with a clear message when tshark is absent locally, but always runs in CI" → shared skipif + `REMORA_REQUIRE_TSHARK` contract (Task 3 Step 3 verifies both paths).
