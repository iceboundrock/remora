# Codegen: Parse `tshark -G fields` Into Field Dictionary Model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse the tab-separated `tshark -G fields` dump into an in-memory field-dictionary model (protocols + fields + warnings), plus a documented identifier-mangling policy, backed by a checked-in real-dump fixture. Closes issue #5.

**Architecture:** New package `src/remora/codegen/` with two modules: `parse.py` (frozen dataclasses `Protocol`/`FieldDef`/`ParseWarning`/`FieldDictionary` and the line parser `parse_fields_dump`) and `mangle.py` (pure function `mangle_field` mapping a tshark field abbrev to a Python attribute name). No tshark subprocess is spawned here — input is text. Emitters (#14) will consume the model; fingerprinting and CLI are out of scope.

**Tech Stack:** Python ≥3.10, stdlib only (`dataclasses`, `keyword`). Tests with pytest; `mypy --strict src tests` is part of the gate.

## Global Constraints

- CI gate before every commit-worthy state: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest -m "not integration"` (full `uv run pytest` at the end; the new tests must not require tshark at runtime).
- Branch `feat/issue-5-codegen-parse-g-fields`; one PR, body includes `Closes #5`.
- No new dependencies. Line length 100 (ruff).
- Parse errors / invalid inputs raise `ValueError` where a caller passes garbage directly (loud beats silent, matching `src/remora/values.py`); malformed *lines inside a dump* become collected warnings, never exceptions and never silent drops.
- `from __future__ import annotations` at the top of every new `src` module (repo convention).

## Background: the `tshark -G fields` format (verified against tshark 4.6.7 locally)

Tab-separated lines, two known record types:

- `P` records, exactly 3 columns: `P<TAB>display name<TAB>abbrev`
  e.g. `P\tDomain Name System\tdns`
- `F` records, exactly 8 columns: `F<TAB>display name<TAB>abbrev<TAB>ftype<TAB>parent protocol abbrev<TAB>display base<TAB>bitmask<TAB>blurb`
  e.g. `F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\t` (base and blurb may be empty; base may be `BASE_DEC`, `BASE_HEX`, … or a bare integer for booleans)

Real-world facts the design must handle (all verified in the 4.6.7 dump):

- Duplicate `P` abbrevs exist (`tpkt` appears twice with different display names). Duplicate `F` abbrevs don't exist in 4.6.7 but are not guaranteed absent in other versions.
- Field abbrevs are NOT always prefixed by their parent protocol abbrev: field `can.len` has parent `acf-can`.
- Abbrevs may start with a digit (`6lowpan.class`), contain hyphens (`acf-can`), contain uppercase letters, and end in Python keywords (`6lowpan.class`, `afp.spotlight.return`, `afs.reassembled.in`).
- A whole-protocol abbrev may begin with an underscore (`_ws.malformed`).

## Documented policies (these go verbatim into module docstrings)

**Duplicate policy (parse.py):** first occurrence wins, for both protocol abbrevs and field abbrevs. Every later duplicate is dropped from the model and recorded as a `ParseWarning`. This is deterministic because input line order is deterministic.

**Mangling policy (mangle.py):** `mangle_field(abbrev, parent)`:
1. If `abbrev` starts with `parent + "."` and has content after the prefix, strip the prefix (`dns.qry.name` + `dns` → `qry.name`); otherwise use the full abbrev (`can.len` + `acf-can` → `can.len`).
2. Replace every character that is not ASCII alphanumeric with `_` (covers dots and hyphens). Case is preserved.
3. If the result starts with a digit, prefix `f_` (`4_incorrect_cip_fn` → `f_4_incorrect_cip_fn`).
4. If the result starts with `_`, prefix `f` (underscore-prefixed attributes are reserved on protocol classes — see `src/remora/proto/_meta.py`).
5. If the result is a Python hard keyword (`keyword.iskeyword`), append `_` (`class` → `class_`, PEP 8 style). Soft keywords (`match`, `type`, …) are valid attribute names and are left alone.
6. Empty `abbrev` raises `ValueError`.

Steps 3–5 cannot interact (a keyword never starts with a digit or underscore; step 4 cannot fire after step 3 because `f_` starts with a letter).

## File Structure

- Create: `src/remora/codegen/__init__.py` — re-exports the public API.
- Create: `src/remora/codegen/mangle.py` — `mangle_field`.
- Create: `src/remora/codegen/parse.py` — model dataclasses + `parse_fields_dump`.
- Create: `tests/test_codegen_mangle.py`
- Create: `tests/test_codegen_parse.py`
- Create: `tests/data/make_g_fields_sample.py` — regeneration script (provenance; not run by tests).
- Create: `tests/data/g_fields_sample.txt` — checked-in real-dump subset fixture.

---

### Task 1: Package skeleton + identifier mangling (`mangle.py`)

**Files:**
- Create: `src/remora/codegen/__init__.py`
- Create: `src/remora/codegen/mangle.py`
- Test: `tests/test_codegen_mangle.py`

**Interfaces:**
- Consumes: nothing (leaf module, stdlib `keyword` only).
- Produces: `mangle_field(abbrev: str, parent: str) -> str` — used by #14's emitter; re-exported from `remora.codegen`.

- [ ] **Step 1: Create the branch**

```bash
git checkout main && git pull && git checkout -b feat/issue-5-codegen-parse-g-fields
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_codegen_mangle.py`:

```python
"""Tests for the field-abbrev -> Python attribute name mangling policy."""

from __future__ import annotations

import pytest

from remora.codegen.mangle import mangle_field


class TestParentStripping:
    def test_strips_parent_prefix_and_replaces_dots(self) -> None:
        assert mangle_field("dns.qry.name", "dns") == "qry_name"

    def test_abbrev_equal_to_parent_keeps_full_name(self) -> None:
        assert mangle_field("dns", "dns") == "dns"

    def test_field_not_under_parent_prefix_uses_full_abbrev(self) -> None:
        # Real case: protocol "acf-can" registers field "can.len".
        assert mangle_field("can.len", "acf-can") == "can_len"

    def test_prefix_must_match_whole_segment(self) -> None:
        # "ip" is not a dot-terminated prefix of "ipv6.src".
        assert mangle_field("ipv6.src", "ip") == "ipv6_src"


class TestCharacterReplacement:
    def test_hyphens_become_underscores(self) -> None:
        assert mangle_field("acf-can.flags", "acf-can") == "flags"
        assert mangle_field("dns.qry-name", "dns") == "qry_name"

    def test_case_is_preserved(self) -> None:
        assert mangle_field("iso.SS", "iso") == "SS"


class TestLeadingDigit:
    def test_leading_digit_gets_f_prefix(self) -> None:
        # Real case: iec61883.4_incorrect_cip_fn under parent iec61883.
        assert mangle_field("iec61883.4_incorrect_cip_fn", "iec61883") == "f_4_incorrect_cip_fn"

    def test_full_abbrev_with_leading_digit(self) -> None:
        assert mangle_field("6lowpan", "nonmatching") == "f_6lowpan"


class TestLeadingUnderscore:
    def test_leading_underscore_gets_f_prefix(self) -> None:
        # Underscore-prefixed attributes are reserved on protocol classes.
        assert mangle_field("_ws.short", "_ws.short") == "f_ws_short"


class TestKeywords:
    def test_hard_keyword_gets_trailing_underscore(self) -> None:
        # Real case: 6lowpan.class under parent 6lowpan.
        assert mangle_field("6lowpan.class", "6lowpan") == "class_"
        assert mangle_field("afp.spotlight.return", "afp") == "spotlight_return"
        assert mangle_field("afs.reassembled.in", "afs") == "reassembled_in"
        assert mangle_field("dns.in", "dns") == "in_"

    def test_soft_keywords_left_alone(self) -> None:
        assert mangle_field("dns.match", "dns") == "match"
        assert mangle_field("dns.type", "dns") == "type"


class TestInvalidInput:
    def test_empty_abbrev_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            mangle_field("", "dns")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_mangle.py -v`
Expected: collection error — `ModuleNotFoundError: No module named 'remora.codegen'`

- [ ] **Step 4: Write the implementation**

Create `src/remora/codegen/mangle.py`:

```python
"""Identifier mangling: tshark field abbrev -> Python attribute name.

Policy (deterministic, frozen for generated modules)
----------------------------------------------------
1. If ``abbrev`` starts with ``parent + "."`` (and is longer than the
   prefix), the prefix is stripped: ``dns.qry.name`` under ``dns`` ->
   ``qry.name``. Otherwise the full abbrev is used — field abbrevs are not
   always prefixed by their parent (real case: field ``can.len`` is
   registered by protocol ``acf-can``).
2. Every character that is not ASCII alphanumeric is replaced with ``_``
   (dots, hyphens, anything exotic). Case is preserved.
3. A result starting with a digit gets an ``f_`` prefix
   (``iec61883.4_incorrect_cip_fn`` -> ``f_4_incorrect_cip_fn``).
4. A result starting with ``_`` gets an ``f`` prefix: underscore-prefixed
   attributes are reserved on protocol classes (see
   :mod:`remora.proto._meta`).
5. A result that is a Python *hard* keyword gets a trailing ``_``
   (``6lowpan.class`` -> ``class_``, PEP 8 style). Soft keywords
   (``match``, ``type``, ...) are valid attribute names and are left alone.

The attribute name is derived once at generation time and stored alongside
the full tshark name in ``_table_``; nothing at runtime may re-derive one
from the other.
"""

from __future__ import annotations

import keyword

__all__ = ["mangle_field"]


def mangle_field(abbrev: str, parent: str) -> str:
    """Map a tshark field abbrev to a Python attribute name (see module docs).

    Raises ValueError if ``abbrev`` is empty.
    """
    if not abbrev:
        raise ValueError("cannot mangle an empty field abbrev")
    prefix = parent + "."
    base = (
        abbrev[len(prefix) :] if abbrev.startswith(prefix) and len(abbrev) > len(prefix) else abbrev
    )
    mangled = "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in base)
    if mangled[0].isdigit():
        mangled = "f_" + mangled
    if mangled.startswith("_"):
        mangled = "f" + mangled
    if keyword.iskeyword(mangled):
        mangled += "_"
    return mangled
```

Create `src/remora/codegen/__init__.py`:

```python
"""Code generation from ``tshark -G fields`` dumps (M2, epic #41)."""

from remora.codegen.mangle import mangle_field

__all__ = ["mangle_field"]
```

(Note: `parse.py` exports are added to this `__init__` in Task 2.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_mangle.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean. If `ruff format --check` complains about the long ternary line in `mangle.py`, run `uv run ruff format src/remora/codegen/mangle.py` and re-check.

- [ ] **Step 7: Commit**

```bash
git add src/remora/codegen tests/test_codegen_mangle.py
git commit -m "codegen: add identifier mangling policy (issue #5)"
```

---

### Task 2: Model dataclasses + dump parser (`parse.py`)

**Files:**
- Create: `src/remora/codegen/parse.py`
- Modify: `src/remora/codegen/__init__.py`
- Test: `tests/test_codegen_parse.py` (synthetic-input tests only; fixture tests are Task 3)

**Interfaces:**
- Consumes: nothing from other remora modules (input is plain text).
- Produces (consumed by #14's emitter and by Task 3's tests):
  - `Protocol(name: str, abbrev: str)` — frozen dataclass.
  - `FieldDef(name: str, abbrev: str, ftype: str, parent: str, base: str)` — frozen dataclass; `base` is the raw display-base column, possibly `""`.
  - `ParseWarning(line_no: int, message: str)` — frozen dataclass; `line_no` is 1-based.
  - `FieldDictionary(protocols: tuple[Protocol, ...], fields: tuple[FieldDef, ...], warnings: tuple[ParseWarning, ...])` — frozen dataclass.
  - `parse_fields_dump(text: str) -> FieldDictionary`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_codegen_parse.py` (Task 3 appends a fixture test class to this file):

```python
"""Tests for parsing ``tshark -G fields`` dumps into the field-dictionary model."""

from __future__ import annotations

from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    ParseWarning,
    Protocol,
    parse_fields_dump,
)

P_DNS = "P\tDomain Name System\tdns"
F_DNS_QRY_NAME = "F\tName\tdns.qry.name\tFT_STRING\tdns\t\t0x0\tQuery Name"
F_IP_SRC = "F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\t"
F_6LOWPAN_CLASS = "F\tTraffic class\t6lowpan.class\tFT_UINT8\t6lowpan\tBASE_HEX\t0x0\t"


class TestRecordParsing:
    def test_protocol_record(self) -> None:
        result = parse_fields_dump(P_DNS + "\n")
        assert result.protocols == (Protocol(name="Domain Name System", abbrev="dns"),)
        assert result.fields == ()
        assert result.warnings == ()

    def test_field_record(self) -> None:
        result = parse_fields_dump(F_DNS_QRY_NAME + "\n")
        assert result.fields == (
            FieldDef(name="Name", abbrev="dns.qry.name", ftype="FT_STRING", parent="dns", base=""),
        )

    def test_field_record_with_base(self) -> None:
        result = parse_fields_dump(F_6LOWPAN_CLASS + "\n")
        assert result.fields[0].base == "BASE_HEX"

    def test_mixed_records_preserve_order(self) -> None:
        text = "\n".join([P_DNS, F_DNS_QRY_NAME, F_IP_SRC]) + "\n"
        result = parse_fields_dump(text)
        assert [p.abbrev for p in result.protocols] == ["dns"]
        assert [f.abbrev for f in result.fields] == ["dns.qry.name", "ip.src"]

    def test_empty_input(self) -> None:
        assert parse_fields_dump("") == FieldDictionary(protocols=(), fields=(), warnings=())

    def test_blank_lines_skipped_silently(self) -> None:
        result = parse_fields_dump("\n\n" + P_DNS + "\n\n")
        assert len(result.protocols) == 1
        assert result.warnings == ()


class TestWarnings:
    def test_unknown_record_type_collected_not_dropped(self) -> None:
        result = parse_fields_dump("X\tsomething\tweird\n" + P_DNS + "\n")
        assert len(result.protocols) == 1
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 1
        assert "unknown record type 'X'" in result.warnings[0].message

    def test_malformed_protocol_record_wrong_columns(self) -> None:
        result = parse_fields_dump("P\tonly-two-columns\n")
        assert result.protocols == ()
        assert len(result.warnings) == 1
        assert "malformed P record" in result.warnings[0].message

    def test_malformed_field_record_wrong_columns(self) -> None:
        result = parse_fields_dump("F\tName\tdns.qry.name\tFT_STRING\tdns\n")
        assert result.fields == ()
        assert len(result.warnings) == 1
        assert "malformed F record" in result.warnings[0].message


class TestDuplicatePolicy:
    """Duplicates: first occurrence wins; later ones become warnings."""

    def test_duplicate_protocol_abbrev_first_wins(self) -> None:
        text = "P\tTPKT - ISO on TCP - RFC1006\ttpkt\nP\tTPKT Heuristic (for RDP)\ttpkt\n"
        result = parse_fields_dump(text)
        assert result.protocols == (Protocol(name="TPKT - ISO on TCP - RFC1006", abbrev="tpkt"),)
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 2
        assert "duplicate protocol abbrev 'tpkt'" in result.warnings[0].message

    def test_duplicate_field_abbrev_first_wins(self) -> None:
        first = "F\tFirst\tdns.id\tFT_UINT16\tdns\tBASE_HEX\t0x0\t"
        second = "F\tSecond\tdns.id\tFT_UINT32\tdns\tBASE_DEC\t0x0\t"
        result = parse_fields_dump(first + "\n" + second + "\n")
        assert len(result.fields) == 1
        assert result.fields[0].name == "First"
        assert result.fields[0].ftype == "FT_UINT16"
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 2
        assert "duplicate field abbrev 'dns.id'" in result.warnings[0].message

    def test_protocol_and_field_abbrev_namespaces_are_independent(self) -> None:
        # A field abbrev may equal a protocol abbrev (e.g. checksum-carrying
        # pseudo-fields); that is not a duplicate.
        text = P_DNS + "\n" + "F\tDNS\tdns\tFT_NONE\tdns\t\t0x0\t\n"
        result = parse_fields_dump(text)
        assert len(result.protocols) == 1
        assert len(result.fields) == 1
        assert result.warnings == ()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_parse.py -v`
Expected: collection error — `ImportError` (no module `remora.codegen.parse`)

- [ ] **Step 3: Write the implementation**

Create `src/remora/codegen/parse.py`:

```python
"""Parse ``tshark -G fields`` dumps into the field-dictionary model.

Input format (tab-separated, one record per line):

- ``P`` records, exactly 3 columns: ``P<TAB>display name<TAB>abbrev``
- ``F`` records, exactly 8 columns: ``F<TAB>display name<TAB>abbrev<TAB>
  ftype<TAB>parent protocol abbrev<TAB>display base<TAB>bitmask<TAB>blurb``

Robustness policy — no line is ever silently dropped:

- Unknown record types are skipped and recorded as :class:`ParseWarning`.
- Records with the wrong column count are skipped and recorded as warnings.
- Duplicate abbrevs (protocol and field namespaces are independent): the
  *first* occurrence wins; every later duplicate is skipped and recorded as
  a warning. Input line order makes this deterministic. Real dumps contain
  duplicate protocol abbrevs (e.g. ``tpkt`` in tshark 4.6.x).
- Blank lines are skipped silently.

The bitmask and blurb columns are currently not modeled (nothing consumes
them); ``base`` keeps the raw text of the display-base column, which may be
empty, a ``BASE_*`` name, or a bare integer (boolean field width).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["FieldDef", "FieldDictionary", "ParseWarning", "Protocol", "parse_fields_dump"]


@dataclass(frozen=True)
class Protocol:
    """One ``P`` record: a dissector protocol."""

    name: str
    abbrev: str


@dataclass(frozen=True)
class FieldDef:
    """One ``F`` record: a dissector field."""

    name: str
    abbrev: str
    ftype: str
    parent: str
    base: str


@dataclass(frozen=True)
class ParseWarning:
    """A skipped input line: where and why. ``line_no`` is 1-based."""

    line_no: int
    message: str


@dataclass(frozen=True)
class FieldDictionary:
    """Everything one ``tshark -G fields`` dump parses into, in input order."""

    protocols: tuple[Protocol, ...]
    fields: tuple[FieldDef, ...]
    warnings: tuple[ParseWarning, ...]


_P_COLUMNS = 3
_F_COLUMNS = 8


def parse_fields_dump(text: str) -> FieldDictionary:
    """Parse a full ``tshark -G fields`` dump (see module docs for policy)."""
    protocols: list[Protocol] = []
    fields: list[FieldDef] = []
    warnings: list[ParseWarning] = []
    seen_protocols: set[str] = set()
    seen_fields: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        columns = line.split("\t")
        tag = columns[0]
        if tag == "P":
            if len(columns) != _P_COLUMNS:
                warnings.append(
                    ParseWarning(
                        line_no,
                        f"malformed P record: expected {_P_COLUMNS} columns, got {len(columns)}",
                    )
                )
                continue
            _, name, abbrev = columns
            if abbrev in seen_protocols:
                warnings.append(ParseWarning(line_no, f"duplicate protocol abbrev {abbrev!r}"))
                continue
            seen_protocols.add(abbrev)
            protocols.append(Protocol(name=name, abbrev=abbrev))
        elif tag == "F":
            if len(columns) != _F_COLUMNS:
                warnings.append(
                    ParseWarning(
                        line_no,
                        f"malformed F record: expected {_F_COLUMNS} columns, got {len(columns)}",
                    )
                )
                continue
            _, name, abbrev, ftype, parent, base, _bitmask, _blurb = columns
            if abbrev in seen_fields:
                warnings.append(ParseWarning(line_no, f"duplicate field abbrev {abbrev!r}"))
                continue
            seen_fields.add(abbrev)
            fields.append(FieldDef(name=name, abbrev=abbrev, ftype=ftype, parent=parent, base=base))
        else:
            warnings.append(ParseWarning(line_no, f"unknown record type {tag!r}"))

    return FieldDictionary(
        protocols=tuple(protocols), fields=tuple(fields), warnings=tuple(warnings)
    )
```

Update `src/remora/codegen/__init__.py` to:

```python
"""Code generation from ``tshark -G fields`` dumps (M2, epic #41)."""

from remora.codegen.mangle import mangle_field
from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    ParseWarning,
    Protocol,
    parse_fields_dump,
)

__all__ = [
    "FieldDef",
    "FieldDictionary",
    "ParseWarning",
    "Protocol",
    "mangle_field",
    "parse_fields_dump",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_parse.py -v`
Expected: all PASS

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean (run `uv run ruff format src tests` first if format check flags the long f-string lines, then re-run the gate).

- [ ] **Step 6: Commit**

```bash
git add src/remora/codegen tests/test_codegen_parse.py
git commit -m "codegen: parse tshark -G fields dumps into field dictionary model (issue #5)"
```

---

### Task 3: Checked-in real-dump fixture + fixture tests

**Files:**
- Create: `tests/data/make_g_fields_sample.py`
- Create: `tests/data/g_fields_sample.txt`
- Modify: `tests/test_codegen_parse.py` (append fixture test class)

**Interfaces:**
- Consumes: `parse_fields_dump`, `FieldDictionary` from Task 2; `mangle_field` from Task 1.
- Produces: the fixture file later issues (#14, #16) will reuse.

The fixture is a real `tshark -G fields` dump truncated to 9 protocols chosen to cover the edge cases: `eth`, `ip`, `tcp`, `udp`, `dns` (the M1 seeds), `6lowpan` (leading digit + `class` keyword), `acf-can` (hyphen; fields not under the parent prefix), `iec61883` (digit-leading segment), `tpkt` (real duplicate P abbrev). Tests run against the checked-in file — they never invoke tshark, so they are NOT integration tests.

- [ ] **Step 1: Write the regeneration script**

Create `tests/data/make_g_fields_sample.py`:

```python
"""Regenerate g_fields_sample.txt — a truncated real ``tshark -G fields`` dump.

Usage: uv run python tests/data/make_g_fields_sample.py

Keeps only the records of a fixed protocol set chosen to cover parser and
mangling edge cases:

- eth, ip, tcp, udp, dns — the M1 seed protocols
- 6lowpan  — abbrev starts with a digit; has a ``.class`` keyword field
- acf-can  — hyphen in the abbrev; registers fields not under its prefix (``can.*``)
- iec61883 — digit-leading field segment (``iec61883.4_incorrect_cip_fn``)
- tpkt     — real duplicate P record (appears twice in tshark 4.6.x)

The fixture is checked in and pinned: tests assert exact counts against the
committed file, so regenerating under a different tshark version may require
updating the counts in tests/test_codegen_parse.py (a fingerprint/drift
mechanism is issue #16's scope).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PROTOCOLS = frozenset({"eth", "ip", "tcp", "udp", "dns", "6lowpan", "acf-can", "iec61883", "tpkt"})
OUT = Path(__file__).parent / "g_fields_sample.txt"


def main() -> None:
    dump = subprocess.run(
        ["tshark", "-G", "fields"], check=True, capture_output=True, text=True
    ).stdout
    kept: list[str] = []
    for line in dump.splitlines():
        columns = line.split("\t")
        if columns[0] == "P" and len(columns) == 3 and columns[2] in PROTOCOLS:
            kept.append(line)
        elif columns[0] == "F" and len(columns) == 8 and columns[4] in PROTOCOLS:
            kept.append(line)
    OUT.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(f"wrote {len(kept)} records to {OUT}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Generate the fixture and record its exact counts**

```bash
uv run python tests/data/make_g_fields_sample.py
awk -F'\t' '{print $1}' tests/data/g_fields_sample.txt | sort | uniq -c
```

Expected with tshark 4.6.7: `10 P` and `976 F` (the 10 P lines contain `tpkt` twice → 9 unique protocols; all 976 field abbrevs are unique). If the local tshark differs and prints other counts, use the printed counts in Step 3's constants instead — the test must assert the *committed* fixture's real counts.

- [ ] **Step 3: Write the failing fixture tests**

Append to `tests/test_codegen_parse.py` (add `from pathlib import Path` and the `mangle_field` import at the top of the file):

```python
FIXTURE = Path(__file__).parent / "data" / "g_fields_sample.txt"

# Exact record counts of the committed fixture (tshark 4.6.7); regenerating
# the fixture with another tshark version requires updating these.
FIXTURE_P_RECORDS = 10  # tpkt appears twice -> 9 unique protocols
FIXTURE_UNIQUE_PROTOCOLS = 9
FIXTURE_F_RECORDS = 976  # all field abbrevs unique


class TestRealDumpFixture:
    def test_counts_match_fixture(self) -> None:
        result = parse_fields_dump(FIXTURE.read_text(encoding="utf-8"))
        assert len(result.protocols) == FIXTURE_UNIQUE_PROTOCOLS
        assert len(result.fields) == FIXTURE_F_RECORDS
        # The only warnings are the duplicate tpkt P records.
        assert len(result.warnings) == FIXTURE_P_RECORDS - FIXTURE_UNIQUE_PROTOCOLS
        assert all("duplicate protocol abbrev 'tpkt'" in w.message for w in result.warnings)

    def test_known_field_spot_checks(self) -> None:
        result = parse_fields_dump(FIXTURE.read_text(encoding="utf-8"))
        by_abbrev = {f.abbrev: f for f in result.fields}
        ip_src = by_abbrev["ip.src"]
        assert ip_src == FieldDef(
            name="Source Address", abbrev="ip.src", ftype="FT_IPv4", parent="ip", base=""
        )
        assert by_abbrev["6lowpan.class"].ftype == "FT_UINT8"
        assert by_abbrev["6lowpan.class"].base == "BASE_HEX"
        assert by_abbrev["can.len"].parent == "acf-can"

    def test_duplicate_protocol_first_wins_on_real_data(self) -> None:
        result = parse_fields_dump(FIXTURE.read_text(encoding="utf-8"))
        tpkt = [p for p in result.protocols if p.abbrev == "tpkt"]
        assert tpkt == [Protocol(name="TPKT - ISO on TCP - RFC1006", abbrev="tpkt")]

    def test_every_fixture_field_mangles_to_valid_identifier(self) -> None:
        result = parse_fields_dump(FIXTURE.read_text(encoding="utf-8"))
        for field in result.fields:
            attr = mangle_field(field.abbrev, field.parent)
            assert attr.isidentifier(), (field.abbrev, attr)
            assert not attr.startswith("_"), (field.abbrev, attr)
            assert not keyword.iskeyword(attr), (field.abbrev, attr)
```

(`import keyword` also goes at the top of the test file.)

- [ ] **Step 4: Run the new tests**

Run: `uv run pytest tests/test_codegen_parse.py -v`
Expected: all PASS (the implementation already exists; if counts mismatch, fix the constants to the committed fixture's actual counts — do not touch parser code for a count mismatch).

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add tests/data/make_g_fields_sample.py tests/data/g_fields_sample.txt tests/test_codegen_parse.py
git commit -m "codegen: add real tshark -G fields fixture and fixture tests (issue #5)"
```

---

### Task 4: Final verification + PR

**Files:** none new.

- [ ] **Step 1: Run the complete CI gate including integration tests**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
```

Expected: all four clean, zero failures.

- [ ] **Step 2: Check acceptance criteria against the diff**

- Fixture parses; protocol and field counts asserted → `TestRealDumpFixture.test_counts_match_fixture`
- Unknown record types ignored but collected as warnings → `TestWarnings.test_unknown_record_type_collected_not_dropped`
- Duplicate abbrevs: documented deterministic policy + test → parse.py docstring + `TestDuplicatePolicy`
- Mangling unit-tested for dots, hyphens, leading digits, keywords → `tests/test_codegen_mangle.py`
- `mypy --strict` passes → gate

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/issue-5-codegen-parse-g-fields
gh pr create --title "codegen: parse tshark -G fields output into field dictionary model" --body "$(cat <<'EOF'
Closes #5

## What

- `src/remora/codegen/parse.py`: parses `tshark -G fields` dumps (`P`/`F` records) into frozen model dataclasses (`Protocol`, `FieldDef`, `FieldDictionary`); unknown record types, malformed lines, and duplicate abbrevs are collected as `ParseWarning`s (first occurrence wins — documented deterministic policy), never silently dropped.
- `src/remora/codegen/mangle.py`: documented identifier-mangling policy (parent-prefix stripping, non-alphanumeric -> `_`, `f_`/`f` prefixes for leading digits/underscores, trailing `_` for hard keywords).
- `tests/data/g_fields_sample.txt`: checked-in real tshark 4.6.7 dump truncated to 9 protocols covering the edge cases (duplicate `tpkt` P records, hyphenated `acf-can` with out-of-prefix `can.*` fields, digit-leading `6lowpan`, keyword field `6lowpan.class`), with a regeneration script.

## Out of scope (per issue)

Emitting `.py`/`.pyi` (#14), fingerprinting (#16), the CLI (#21).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Notes

- **Spec coverage:** all five acceptance criteria are mapped in Task 4 Step 2. The three scope bullets map to Task 2 (parse.py + model), Task 1 (mangling policy), Task 3 (checked-in fixture).
- **Type consistency:** `FieldDef`/`Protocol`/`ParseWarning`/`FieldDictionary`/`parse_fields_dump`/`mangle_field` names are identical across Tasks 1–3.
- **Counts caveat:** fixture counts (10/976) were measured against tshark 4.6.7 on the dev machine; Task 3 Step 2 tells the executor to trust the printed counts of the committed fixture over the plan's numbers.
