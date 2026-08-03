# Codegen: Emit Paired `.py` Runtime Tables and `.pyi` Stubs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `src/remora/codegen/emit.py` (issue #14): given a parsed `Protocol` + its `FieldDef`s + a set of multi-valued abbrevs, emit a runtime `.py` module (compact `_table_` consumed by the lazy metaclass) and a `.pyi` stub (one annotated attribute per field), deterministic byte-for-byte, drop-in compatible with the hand-written seed modules.

**Architecture:** `emit.py` is the back half of the M2 generator. It consumes the model from `remora.codegen.parse` (`Protocol`, `FieldDef`), the frozen attr-mangling policy from `remora.codegen.mangle` (`mangle_field`), and the ftype→Python-type mapping from `remora.values` (`get_info`). It is a pure string builder: no filesystem I/O, no tshark. Because `tshark -G fields` carries no multiplicity signal, multiplicity comes in as an explicit `multi: Set[str]` parameter (abbrevs that are multi-valued); choosing that set is issue #19's problem.

**Tech Stack:** Python ≥3.10, stdlib only (`dataclasses`, `keyword`, `textwrap`). Tests: pytest, `ast`, `importlib`, subprocess calls to `ruff`/`mypy` (skipped if not on PATH).

## Global Constraints

- Everything runs through `uv`: `uv run pytest`, `uv run mypy --strict src tests`, `uv run ruff check .`, `uv run ruff format --check .` — all four must pass before every commit (this is the CI gate; mypy checks `tests/` too, so test files must be `--strict`-clean and fully annotated).
- ruff line length is **100** (`[tool.ruff] line-length = 100` in pyproject.toml).
- Branch: `feat/issue-14-emit-modules`. One PR for this issue; PR body includes `Closes #14`.
- **The existing seed pairing tests (`tests/test_proto_seed.py`) must pass unmodified.** Do not edit that file.
- The compact-table format is frozen (see `src/remora/proto/_meta.py` docstring): `_table_: ClassVar[FieldTable]` maps attr name → `(tshark_name, ftype, multi 0/1)`; generated `.py` does no per-field work at import (table literal only).
- The mangling policy in `src/remora/codegen/mangle.py` (`mangle_field`) is frozen; it is **not injective**, so the emitter MUST detect per-protocol duplicate mangled names (policy here: first occurrence in input order wins, later collisions are skipped and recorded as `EmitWarning`s — mirroring `parse.py`'s first-wins-plus-warning policy).
- New `src/` modules start with `from __future__ import annotations` (matches `parse.py`/`mangle.py`).
- Frozen dataclasses for model/output types (matches `parse.py` style).
- Absolutely no wall-clock/randomness in emitted output (no timestamps — fingerprint headers are issue #16, out of scope).
- Out of scope: `psdsl gen` CLI (#21), choosing which protocols ship (#19), fingerprint headers (#16), touching `src/remora/proto/` seed files or `src/remora/proto/__init__.py`.

## File Structure

- Create: `src/remora/codegen/emit.py` — all emission logic: `mangle_protocol`, `EmitWarning`, `EmittedModule`, `emit_protocol`.
- Create: `tests/test_codegen_emit.py` — all tests for this issue.
- Modify: `src/remora/codegen/__init__.py` — re-export the new public names.
- Modify: `AGENTS.md` — extend the `src/remora/codegen/` architecture bullet with one sentence about `emit.py`.

## Frozen Output Format (reference for all tasks)

For `Protocol(name="User Datagram Protocol", abbrev="udp")` with fields `udp.srcport` (FT_UINT16), `udp.port` (FT_UINT16, multi), `udp.checksum.status` (FT_UINT8), `udp.time_delta` (FT_RELATIVE_TIME), the emitted **`.py`** is exactly:

```python
"""Generated protocol module for tshark layer ``udp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["UDP"]


class UDP(ProtocolBase):
    """User Datagram Protocol (tshark layer ``udp``)."""

    _proto_ = "udp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("udp.srcport", "FT_UINT16", 0),
        "port": ("udp.port", "FT_UINT16", 1),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
    }
```

and the emitted **`.pyi`** is exactly (note: **one** blank line before the class — stub style, matching the checked-in seed stubs; the fence below is tagged `pyi` so ruff's docs-fence formatter does not rewrite it to `.py` style, which would fail `ruff format --check` on a real `.pyi`):

```pyi
from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    srcport: Field[int]
    port: MultiField[int]
    checksum_status: Field[int]
    time_delta: Field[timedelta]
```

Both files end with exactly one trailing newline. Table entries and stub attributes appear in **input field order**. The `multi` set is only ever membership-tested, never iterated (iteration order of a set would break byte-determinism).

---

### Task 1: Branch setup + `mangle_protocol`

**Files:**
- Create: `src/remora/codegen/emit.py`
- Test: `tests/test_codegen_emit.py`

**Interfaces:**
- Consumes: `keyword` stdlib.
- Produces: `mangle_protocol(abbrev: str) -> str` — maps a tshark protocol abbrev to a Python **module name**; raises `ValueError` on empty abbrev. Later tasks derive the class name as `mangle_protocol(abbrev).upper()`.

- [ ] **Step 1: Create the branch**

```bash
cd /Users/ruoshi/code/github/remora
git checkout main && git pull && git checkout -b feat/issue-14-emit-modules
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_codegen_emit.py`:

```python
"""Tests for emitting paired protocol modules (runtime .py + stub .pyi)."""

from __future__ import annotations

import pytest

from remora.codegen.emit import mangle_protocol


class TestMangleProtocol:
    def test_plain_abbrev_passes_through(self) -> None:
        assert mangle_protocol("udp") == "udp"

    def test_uppercase_is_lowered(self) -> None:
        assert mangle_protocol("TCP") == "tcp"

    def test_hyphens_become_underscores(self) -> None:
        assert mangle_protocol("acf-can") == "acf_can"

    def test_dots_become_underscores(self) -> None:
        assert mangle_protocol("mp2t.af") == "mp2t_af"

    def test_leading_digit_gets_p_prefix(self) -> None:
        assert mangle_protocol("6lowpan") == "p_6lowpan"

    def test_leading_underscore_result_gets_p_prefix(self) -> None:
        assert mangle_protocol("-ws") == "p_ws"

    def test_keyword_gets_trailing_underscore(self) -> None:
        assert mangle_protocol("class") == "class_"

    def test_empty_abbrev_raises(self) -> None:
        with pytest.raises(ValueError):
            mangle_protocol("")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'remora.codegen.emit'`

- [ ] **Step 4: Write the implementation**

Create `src/remora/codegen/emit.py`:

```python
"""Emit paired protocol modules: runtime ``.py`` tables and ``.pyi`` stubs.

Back half of the M2 generator (issue #14). Pure string building — no
filesystem I/O, no tshark. Consumes the parsed model
(:mod:`remora.codegen.parse`), the frozen field-attr mangling policy
(:mod:`remora.codegen.mangle`), and the ftype -> Python type mapping
(:mod:`remora.values`).

Protocol-name mangling policy (frozen, this module's scope per
:mod:`remora.codegen.mangle` docs):

1. The abbrev is lowercased; every character that is not ASCII
   alphanumeric becomes ``_``.
2. A result starting with a digit gets a ``p_`` prefix; a result starting
   with ``_`` gets a ``p`` prefix (underscore-prefixed module names read
   as private).
3. A hard-keyword result gets a trailing ``_``.

The module name is the mangled abbrev; the class name is the mangled
abbrev upper-cased (``udp`` -> ``UDP``, ``acf-can`` -> ``ACF_CAN``).
"""

from __future__ import annotations

import keyword

__all__ = ["mangle_protocol"]


def mangle_protocol(abbrev: str) -> str:
    """Map a tshark protocol abbrev to a Python module name (see module docs).

    Raises ValueError if ``abbrev`` is empty.
    """
    if not abbrev:
        raise ValueError("cannot mangle an empty protocol abbrev")
    mangled = "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in abbrev.lower())
    if mangled[0].isdigit():
        mangled = "p_" + mangled
    if mangled.startswith("_"):
        mangled = "p" + mangled
    if keyword.iskeyword(mangled):
        mangled += "_"
    return mangled
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: 8 PASS

- [ ] **Step 6: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add src/remora/codegen/emit.py tests/test_codegen_emit.py
git commit -m "codegen: add protocol-abbrev mangling for module/class names"
```

---

### Task 2: `emit_protocol` happy path

**Files:**
- Modify: `src/remora/codegen/emit.py`
- Modify: `src/remora/codegen/__init__.py`
- Test: `tests/test_codegen_emit.py`

**Interfaces:**
- Consumes: `Protocol`, `FieldDef` from `remora.codegen.parse`; `mangle_field(abbrev: str, parent: str) -> str` from `remora.codegen.mangle`; `get_info(ftype: str) -> FTypeInfo[Any]` from `remora.values` (`get_info(ftype).py_type.__name__` gives the stub's inner type name; unknown ftypes fall back to `str`).
- Produces:
  - `@dataclass(frozen=True) class EmitWarning: abbrev: str; message: str`
  - `@dataclass(frozen=True) class EmittedModule: module_name: str; class_name: str; py_source: str; pyi_source: str; warnings: tuple[EmitWarning, ...]`
  - `emit_protocol(protocol: Protocol, fields: Sequence[FieldDef], multi: Set[str] = frozenset()) -> EmittedModule` (`Sequence`/`Set` from `collections.abc`; `multi` holds tshark abbrevs that are multi-valued).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_codegen_emit.py` (extend the existing imports — final import block after this task):

```python
"""Tests for emitting paired protocol modules (runtime .py + stub .pyi)."""

from __future__ import annotations

import pytest

from remora.codegen.emit import EmittedModule, emit_protocol, mangle_protocol
from remora.codegen.parse import FieldDef, Protocol
```

Test data and tests to append:

```python
def make_field(abbrev: str, ftype: str, parent: str) -> FieldDef:
    return FieldDef(name=abbrev, abbrev=abbrev, ftype=ftype, parent=parent, base="")


UDP_PROTO = Protocol(name="User Datagram Protocol", abbrev="udp")
UDP_FIELDS = [
    make_field("udp.srcport", "FT_UINT16", "udp"),
    make_field("udp.port", "FT_UINT16", "udp"),
    make_field("udp.checksum.status", "FT_UINT8", "udp"),
    make_field("udp.time_delta", "FT_RELATIVE_TIME", "udp"),
]

EXPECTED_UDP_PY = '''"""Generated protocol module for tshark layer ``udp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["UDP"]


class UDP(ProtocolBase):
    """User Datagram Protocol (tshark layer ``udp``)."""

    _proto_ = "udp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("udp.srcport", "FT_UINT16", 0),
        "port": ("udp.port", "FT_UINT16", 1),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
    }
'''

EXPECTED_UDP_PYI = """from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    srcport: Field[int]
    port: MultiField[int]
    checksum_status: Field[int]
    time_delta: Field[timedelta]
"""


def emit_udp() -> EmittedModule:
    return emit_protocol(UDP_PROTO, UDP_FIELDS, multi=frozenset({"udp.port"}))


class TestEmitHappyPath:
    def test_module_and_class_names(self) -> None:
        emitted = emit_udp()
        assert emitted.module_name == "udp"
        assert emitted.class_name == "UDP"
        assert emitted.warnings == ()

    def test_py_source_is_exact(self) -> None:
        assert emit_udp().py_source == EXPECTED_UDP_PY

    def test_pyi_source_is_exact(self) -> None:
        assert emit_udp().pyi_source == EXPECTED_UDP_PYI

    def test_ipaddress_types_are_imported(self) -> None:
        proto = Protocol(name="Internet Protocol Version 4", abbrev="ip")
        fields = [
            make_field("ip.src", "FT_IPv4", "ip"),
            make_field("ip.host", "FT_IPv6", "ip"),
        ]
        pyi = emit_protocol(proto, fields).pyi_source
        assert pyi.startswith("from ipaddress import IPv4Address, IPv6Address\n\n")
        assert "    src: Field[IPv4Address]\n" in pyi
        assert "    host: Field[IPv6Address]\n" in pyi

    def test_scalar_only_protocol_imports_only_field(self) -> None:
        proto = Protocol(name="Ethernet", abbrev="eth")
        pyi = emit_protocol(proto, [make_field("eth.type", "FT_UINT16", "eth")]).pyi_source
        assert "MultiField" not in pyi
        assert "from remora.fields import Field\n" in pyi
        assert "from datetime import" not in pyi
        assert "from ipaddress import" not in pyi

    def test_multi_only_protocol_imports_only_multifield(self) -> None:
        proto = Protocol(name="Domain Name System", abbrev="dns")
        fields = [make_field("dns.a", "FT_IPv4", "dns")]
        pyi = emit_protocol(proto, fields, multi=frozenset({"dns.a"})).pyi_source
        assert "from remora.fields import MultiField\n" in pyi
        assert "    a: MultiField[IPv4Address]\n" in pyi
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: FAIL — `ImportError: cannot import name 'EmittedModule'`

- [ ] **Step 3: Write the implementation**

In `src/remora/codegen/emit.py`, add imports at the top (below `from __future__ import annotations`):

```python
import keyword
import textwrap
from collections.abc import Sequence, Set
from dataclasses import dataclass

from remora.codegen.mangle import mangle_field
from remora.codegen.parse import FieldDef, Protocol
from remora.values import get_info

__all__ = ["EmitWarning", "EmittedModule", "emit_protocol", "mangle_protocol"]
```

Then add below `mangle_protocol`:

```python
@dataclass(frozen=True)
class EmitWarning:
    """A skipped field: which abbrev and why."""

    abbrev: str
    message: str


@dataclass(frozen=True)
class EmittedModule:
    """One protocol's generated pair: runtime ``.py`` and stub ``.pyi`` sources."""

    module_name: str
    class_name: str
    py_source: str
    pyi_source: str
    warnings: tuple[EmitWarning, ...]


def _escape(text: str) -> str:
    """Escape text for embedding inside a double-quoted Python string literal."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _resolve_attrs(
    protocol: Protocol, fields: Sequence[FieldDef]
) -> tuple[list[tuple[str, FieldDef]], list[EmitWarning]]:
    """Mangle each field to an attr name; first occurrence wins on collision."""
    attrs: list[tuple[str, FieldDef]] = []
    first_by_name: dict[str, str] = {}
    warnings: list[EmitWarning] = []
    for field in fields:
        attr = mangle_field(field.abbrev, protocol.abbrev)
        prior = first_by_name.get(attr)
        if prior is not None:
            warnings.append(
                EmitWarning(
                    field.abbrev,
                    f"attribute name {attr!r} already taken by {prior!r}; field skipped",
                )
            )
            continue
        first_by_name[attr] = field.abbrev
        attrs.append((attr, field))
    return attrs, warnings


def _class_docstring(protocol: Protocol) -> list[str]:
    """Class docstring lines, wrapped so no emitted line exceeds 100 chars."""
    text = _escape(f"{protocol.name} (tshark layer ``{protocol.abbrev}``).")
    wrapped = textwrap.wrap(text, width=92)
    if len(wrapped) <= 1:
        return [f'    """{text}"""']
    return [f'    """{wrapped[0]}', *(f"    {line}" for line in wrapped[1:]), '    """']


def _emit_py(
    protocol: Protocol,
    class_name: str,
    attrs: Sequence[tuple[str, FieldDef]],
    multi: Set[str],
) -> str:
    lines = [
        f'"""Generated protocol module for tshark layer ``{_escape(protocol.abbrev)}``'
        ' — do not edit."""',
        "",
        "from typing import ClassVar",
        "",
        "from remora.proto._meta import FieldTable, ProtocolBase",
        "",
        f'__all__ = ["{class_name}"]',
        "",
        "",
        f"class {class_name}(ProtocolBase):",
        *_class_docstring(protocol),
        "",
        f'    _proto_ = "{_escape(protocol.abbrev)}"',
    ]
    if attrs:
        lines.append("    _table_: ClassVar[FieldTable] = {")
        for attr, field in attrs:
            flag = 1 if field.abbrev in multi else 0
            lines.append(
                f'        "{attr}": ("{_escape(field.abbrev)}", "{_escape(field.ftype)}", {flag}),'
            )
        lines.append("    }")
    else:
        lines.append("    _table_: ClassVar[FieldTable] = {}")
    lines.append("")
    return "\n".join(lines)


#: Stub import candidates in canonical order; filtered by use, never reordered.
_STDLIB_STUB_IMPORTS = (
    ("datetime", ("datetime", "timedelta")),
    ("ipaddress", ("IPv4Address", "IPv6Address")),
)


def _emit_pyi(class_name: str, attrs: Sequence[tuple[str, FieldDef]], multi: Set[str]) -> str:
    entries: list[str] = []
    used_types: set[str] = set()
    any_scalar = any_multi = False
    for attr, field in attrs:
        type_name = get_info(field.ftype).py_type.__name__
        used_types.add(type_name)
        if field.abbrev in multi:
            any_multi = True
            entries.append(f"    {attr}: MultiField[{type_name}]")
        else:
            any_scalar = True
            entries.append(f"    {attr}: Field[{type_name}]")

    lines: list[str] = []
    for module, names in _STDLIB_STUB_IMPORTS:
        wanted = [name for name in names if name in used_types]
        if wanted:
            lines.append(f"from {module} import {', '.join(wanted)}")
    if lines:
        lines.append("")
    descriptors = [
        name for name, used in (("Field", any_scalar), ("MultiField", any_multi)) if used
    ]
    if descriptors:
        lines.append(f"from remora.fields import {', '.join(descriptors)}")
    lines.append("from remora.proto._meta import ProtocolBase")
    lines.append("")
    if entries:
        lines.append(f"class {class_name}(ProtocolBase):")
        lines.extend(entries)
    else:
        lines.append(f"class {class_name}(ProtocolBase): ...")
    lines.append("")
    return "\n".join(lines)


def emit_protocol(
    protocol: Protocol, fields: Sequence[FieldDef], multi: Set[str] = frozenset()
) -> EmittedModule:
    """Emit one protocol's paired ``.py``/``.pyi`` sources.

    ``fields`` is the exact field set to include, in output order; the caller
    selects and orders it (typically dump order). ``multi`` is the set of
    tshark abbrevs that are multi-valued — ``tshark -G fields`` carries no
    multiplicity signal, so this knowledge must come from the caller.
    ``multi`` is only membership-tested, never iterated, keeping output
    byte-deterministic.

    Distinct abbrevs can mangle to the same attribute name (the policy is not
    injective): the first occurrence wins, later collisions are skipped and
    recorded as :class:`EmitWarning`s.
    """
    module_name = mangle_protocol(protocol.abbrev)
    class_name = module_name.upper()
    attrs, warnings = _resolve_attrs(protocol, fields)
    return EmittedModule(
        module_name=module_name,
        class_name=class_name,
        py_source=_emit_py(protocol, class_name, attrs, multi),
        pyi_source=_emit_pyi(class_name, attrs, multi),
        warnings=tuple(warnings),
    )
```

Note: `used_types` is a `set` but is only membership-tested against the canonical-order candidate tuples — output order comes from `_STDLIB_STUB_IMPORTS`, so determinism holds.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: all PASS. If the golden-string tests fail on whitespace, fix the *implementation* to match the goldens (the goldens are the frozen format).

- [ ] **Step 5: Re-export from the package**

Replace `src/remora/codegen/__init__.py` with:

```python
"""Code generation from ``tshark -G fields`` dumps (M2, epic #41)."""

from remora.codegen.emit import EmittedModule, EmitWarning, emit_protocol, mangle_protocol
from remora.codegen.mangle import mangle_field
from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    ParseWarning,
    Protocol,
    parse_fields_dump,
)

__all__ = [
    "EmitWarning",
    "EmittedModule",
    "FieldDef",
    "FieldDictionary",
    "ParseWarning",
    "Protocol",
    "emit_protocol",
    "mangle_field",
    "mangle_protocol",
    "parse_fields_dump",
]
```

- [ ] **Step 6: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add -A src tests
git commit -m "codegen: emit paired .py runtime tables and .pyi stubs"
```

---

### Task 3: Edge cases — collisions, keyword/digit attrs, unknown ftypes, empty protocol, escaping

**Files:**
- Modify: `src/remora/codegen/emit.py` (only if a test exposes a gap — the Task 2 implementation is expected to already handle these)
- Test: `tests/test_codegen_emit.py`

**Interfaces:**
- Consumes: `emit_protocol`, `make_field` from previous tasks; `ast` stdlib.

- [ ] **Step 1: Write the tests**

Add `import ast` to the test file's imports. Append:

```python
class TestEmitEdgeCases:
    def test_mangle_collision_first_wins_with_warning(self) -> None:
        proto = Protocol(name="Border Gateway Protocol", abbrev="bgp")
        fields = [
            make_field("bgp.prefix_length", "FT_UINT8", "bgp"),
            make_field("bgp.prefix.length", "FT_UINT8", "bgp"),
        ]
        emitted = emit_protocol(proto, fields)
        assert '"prefix_length": ("bgp.prefix_length", "FT_UINT8", 0),' in emitted.py_source
        assert "bgp.prefix.length" not in emitted.py_source
        assert len(emitted.warnings) == 1
        assert emitted.warnings[0].abbrev == "bgp.prefix.length"
        assert "prefix_length" in emitted.warnings[0].message

    def test_keyword_field_attr_is_escaped_in_both_sources(self) -> None:
        proto = Protocol(name="6LoWPAN", abbrev="6lowpan")
        emitted = emit_protocol(proto, [make_field("6lowpan.class", "FT_UINT8", "6lowpan")])
        assert emitted.module_name == "p_6lowpan"
        assert emitted.class_name == "P_6LOWPAN"
        assert '"class_": ("6lowpan.class", "FT_UINT8", 0),' in emitted.py_source
        assert "    class_: Field[int]" in emitted.pyi_source

    def test_unknown_ftype_falls_back_to_str(self) -> None:
        proto = Protocol(name="Example", abbrev="ex")
        emitted = emit_protocol(proto, [make_field("ex.blob", "FT_SOME_FUTURE_TYPE", "ex")])
        assert '"blob": ("ex.blob", "FT_SOME_FUTURE_TYPE", 0),' in emitted.py_source
        assert "    blob: Field[str]" in emitted.pyi_source

    def test_empty_protocol_emits_valid_pair(self) -> None:
        proto = Protocol(name="Empty", abbrev="empty")
        emitted = emit_protocol(proto, [])
        assert "    _table_: ClassVar[FieldTable] = {}" in emitted.py_source
        assert "class EMPTY(ProtocolBase): ..." in emitted.pyi_source
        assert "from remora.fields import" not in emitted.pyi_source
        ast.parse(emitted.py_source)
        ast.parse(emitted.pyi_source)

    def test_display_name_with_quotes_and_backslashes_is_escaped(self) -> None:
        proto = Protocol(name='Weird "Proto" C:\\path', abbrev="weird")
        emitted = emit_protocol(proto, [make_field("weird.x", "FT_UINT8", "weird")])
        tree = ast.parse(emitted.py_source)
        class_def = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        docstring = ast.get_docstring(class_def)
        assert docstring is not None
        assert 'Weird "Proto" C:\\path' in docstring

    def test_long_display_name_wraps_under_line_limit(self) -> None:
        proto = Protocol(name="X" * 150, abbrev="longproto")
        emitted = emit_protocol(proto, [make_field("longproto.x", "FT_UINT8", "longproto")])
        assert all(len(line) <= 100 for line in emitted.py_source.splitlines())
        ast.parse(emitted.py_source)
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: all PASS — Task 2's implementation covers these by design (`textwrap.wrap` breaks long words by default, so even a 150-char unbroken name wraps into ≤92-char lines; the first docstring line is 4 indent + 3 quotes + ≤92 = ≤99 chars). If `test_long_display_name_wraps_under_line_limit` fails anyway, fix `_class_docstring` — the invariant to satisfy is the test: no emitted line over 100 chars, output still parses. Do not weaken the test.

- [ ] **Step 3: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add tests/test_codegen_emit.py src/remora/codegen/emit.py
git commit -m "codegen: cover emitter edge cases (collisions, keywords, unknown ftypes)"
```

---

### Task 4: Determinism + import-purity tests

**Files:**
- Test: `tests/test_codegen_emit.py`

**Interfaces:**
- Consumes: `emit_udp()`, `UDP_PROTO`, `UDP_FIELDS` from Task 2; `ast` stdlib.

- [ ] **Step 1: Write the tests**

Append:

```python
class TestDeterminism:
    def test_two_runs_are_byte_identical(self) -> None:
        first = emit_udp()
        second = emit_protocol(UDP_PROTO, list(UDP_FIELDS), multi={"udp.port"})
        assert first.py_source == second.py_source
        assert first.pyi_source == second.pyi_source

    def test_multi_set_type_does_not_affect_output(self) -> None:
        via_set = emit_protocol(UDP_PROTO, UDP_FIELDS, multi={"udp.port"})
        via_frozenset = emit_protocol(UDP_PROTO, UDP_FIELDS, multi=frozenset({"udp.port"}))
        assert via_set.py_source == via_frozenset.py_source
        assert via_set.pyi_source == via_frozenset.pyi_source


class TestImportPurity:
    """The generated .py must do no per-field work at import: table literal only."""

    def test_py_module_body_shape(self) -> None:
        tree = ast.parse(emit_udp().py_source)
        body = tree.body
        assert isinstance(body[0], ast.Expr)  # module docstring
        assert all(isinstance(node, ast.ImportFrom) for node in body[1:3])
        assert isinstance(body[3], ast.Assign)  # __all__
        assert isinstance(body[4], ast.ClassDef)
        assert len(body) == 5

    def test_table_is_a_literal_of_constant_tuples(self) -> None:
        tree = ast.parse(emit_udp().py_source)
        class_def = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        table = next(node for node in class_def.body if isinstance(node, ast.AnnAssign))
        assert isinstance(table.target, ast.Name) and table.target.id == "_table_"
        value = table.value
        assert isinstance(value, ast.Dict)
        for key, entry in zip(value.keys, value.values, strict=True):
            assert isinstance(key, ast.Constant)
            assert isinstance(entry, ast.Tuple)
            assert all(isinstance(element, ast.Constant) for element in entry.elts)
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: all PASS

- [ ] **Step 3: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add tests/test_codegen_emit.py
git commit -m "codegen: test emitter determinism and import purity"
```

---

### Task 5: Seed drop-in compatibility

**Files:**
- Test: `tests/test_codegen_emit.py`

**Interfaces:**
- Consumes: `SEEDS`, `TestStubTablePairing`, `stub_fields` from `tests/test_proto_seed.py` (the tests directory is on `sys.path` — `test_proto_seed.py` itself does `from conftest import FakePacket`, so `from test_proto_seed import ...` works); `ProtocolBase` from `remora.proto._meta`; `importlib.util`; `pathlib.Path`; `types.ModuleType`.
- Produces: two helpers later tasks reuse: `emit_seed(cls: type[ProtocolBase]) -> EmittedModule` and `load_emitted(emitted: EmittedModule, directory: Path) -> ModuleType`.

- [ ] **Step 1: Write the tests**

Add to the test file's imports:

```python
import importlib.util
from pathlib import Path
from types import ModuleType

from conftest import FakePacket
from remora.proto._meta import ProtocolBase
from test_proto_seed import SEEDS, TestStubTablePairing, stub_fields
```

Append:

```python
def emit_seed(cls: type[ProtocolBase]) -> EmittedModule:
    """Rebuild the emitter's input model from a seed class's frozen table."""
    fields = [
        FieldDef(name=attr, abbrev=tshark_name, ftype=ftype, parent=cls._proto_, base="")
        for attr, (tshark_name, ftype, _multi) in cls._table_.items()
    ]
    multi = frozenset(
        tshark_name for tshark_name, _ftype, is_multi in cls._table_.values() if is_multi
    )
    protocol = Protocol(name=cls.__name__, abbrev=cls._proto_)
    return emit_protocol(protocol, fields, multi)


def load_emitted(emitted: EmittedModule, directory: Path) -> ModuleType:
    """Write the emitted pair into ``directory`` and import the ``.py``."""
    py_path = directory / f"{emitted.module_name}.py"
    py_path.write_text(emitted.py_source)
    (directory / f"{emitted.module_name}.pyi").write_text(emitted.pyi_source)
    spec = importlib.util.spec_from_file_location(emitted.module_name, py_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_case = pytest.mark.parametrize(
    ("seed_module", "seed_cls"), SEEDS, ids=[cls.__name__ for _, cls in SEEDS]
)


@seed_case
class TestSeedDropInCompatibility:
    """Acceptance: generated eth/ip/tcp/udp/dns are drop-in for the seeds.

    The pairing tests in test_proto_seed.py are the frozen contract; here we
    regenerate each seed from its own table and (a) run those pairing checks
    unmodified against the generated pair, (b) assert the generated table and
    stub are exactly equivalent to the checked-in seed's.
    """

    def test_generated_pair_passes_pairing_contract(
        self, seed_module: ModuleType, seed_cls: type[ProtocolBase], tmp_path: Path
    ) -> None:
        emitted = emit_seed(seed_cls)
        generated = load_emitted(emitted, tmp_path)
        generated_cls: type[ProtocolBase] = getattr(generated, emitted.class_name)
        pairing = TestStubTablePairing()
        pairing.test_stub_and_table_declare_the_same_attributes(generated, generated_cls)
        pairing.test_multiplicity_matches_descriptor_class(generated, generated_cls)
        pairing.test_stub_inner_type_matches_ftype(generated, generated_cls)
        pairing.test_every_ftype_is_known(generated, generated_cls)
        pairing.test_attr_names_follow_seed_naming_convention(generated, generated_cls)
        pairing.test_proto_matches_module_name(generated, generated_cls)

    def test_generated_table_equals_seed_table(
        self, seed_module: ModuleType, seed_cls: type[ProtocolBase], tmp_path: Path
    ) -> None:
        emitted = emit_seed(seed_cls)
        generated = load_emitted(emitted, tmp_path)
        generated_cls: type[ProtocolBase] = getattr(generated, emitted.class_name)
        assert generated_cls._proto_ == seed_cls._proto_
        assert generated_cls._table_ == seed_cls._table_

    def test_generated_stub_equals_seed_stub(
        self, seed_module: ModuleType, seed_cls: type[ProtocolBase], tmp_path: Path
    ) -> None:
        emitted = emit_seed(seed_cls)
        generated = load_emitted(emitted, tmp_path)
        assert stub_fields(generated) == stub_fields(seed_module)

    def test_generated_class_reads_packets(
        self, seed_module: ModuleType, seed_cls: type[ProtocolBase], tmp_path: Path
    ) -> None:
        emitted = emit_seed(seed_cls)
        generated = load_emitted(emitted, tmp_path)
        generated_cls: type[ProtocolBase] = getattr(generated, emitted.class_name)
        attr, (tshark_name, _ftype, is_multi) = next(iter(seed_cls._table_.items()))
        view = generated_cls(FakePacket({}))
        assert getattr(view, attr) == (() if is_multi else None)
        assert getattr(generated_cls, attr).name == tshark_name
```

Note the class-name detail: for all five seeds `mangle_protocol(abbrev).upper()` equals the seed class name (`eth`→`ETH`, `ip`→`IP`, `tcp`→`TCP`, `udp`→`UDP`, `dns`→`DNS`), and dump order equals table order because `emit_seed` rebuilds fields from the seed table in insertion order.

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: all PASS (5 seeds × 4 tests = 20 new). If `test_attr_names_follow_seed_naming_convention` fails, the emitter's `mangle_field` usage diverges from the seed convention — debug the mangling, do not touch `test_proto_seed.py`.

- [ ] **Step 3: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add tests/test_codegen_emit.py
git commit -m "codegen: prove emitted modules are drop-in for the seed contract"
```

---

### Task 6: Toolchain gates — emitted output passes ruff and mypy --strict

**Files:**
- Test: `tests/test_codegen_emit.py`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: `emit_seed`, `SEEDS` from Task 5; `shutil.which`, `subprocess`, `os`.

- [ ] **Step 1: Write the tests**

Add `import os`, `import shutil`, `import subprocess` to the test file imports. Append:

```python
REPO_ROOT = Path(__file__).resolve().parent.parent
RUFF = shutil.which("ruff")
MYPY = shutil.which("mypy")


@pytest.mark.skipif(RUFF is None, reason="ruff not on PATH")
def test_emitted_seed_modules_are_ruff_clean(tmp_path: Path) -> None:
    assert RUFF is not None
    paths: list[str] = []
    for _seed_module, seed_cls in SEEDS:
        emitted = emit_seed(seed_cls)
        py_path = tmp_path / f"{emitted.module_name}.py"
        pyi_path = tmp_path / f"{emitted.module_name}.pyi"
        py_path.write_text(emitted.py_source)
        pyi_path.write_text(emitted.pyi_source)
        paths += [str(py_path), str(pyi_path)]
    config = str(REPO_ROOT / "pyproject.toml")
    fmt = subprocess.run(
        [RUFF, "format", "--check", "--config", config, *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    assert fmt.returncode == 0, fmt.stdout + fmt.stderr
    lint = subprocess.run(
        [RUFF, "check", "--config", config, *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    assert lint.returncode == 0, lint.stdout + lint.stderr


@pytest.mark.skipif(MYPY is None, reason="mypy not on PATH")
def test_emitted_dns_stub_passes_mypy_strict(tmp_path: Path) -> None:
    assert MYPY is not None
    dns_cls = next(cls for _module, cls in SEEDS if cls._proto_ == "dns")
    emitted = emit_seed(dns_cls)
    (tmp_path / "dns.py").write_text(emitted.py_source)
    stub_path = tmp_path / "dns.pyi"
    stub_path.write_text(emitted.pyi_source)
    config_path = tmp_path / "mypy.ini"
    config_path.write_text("[mypy]\n")
    env = dict(os.environ, MYPYPATH=str(REPO_ROOT / "src"))
    result = subprocess.run(
        [
            MYPY,
            "--strict",
            "--config-file",
            str(config_path),
            "--cache-dir",
            str(tmp_path / ".mypy_cache"),
            str(stub_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
```

(`check=False` is explicit because ruff bandit-style lint isn't enabled, but `SIM` rules may flag bare `subprocess.run` without it under future rule sets; more importantly we assert on returncode ourselves.)

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_codegen_emit.py -v`
Expected: PASS (both tools are dev deps, so `uv run` puts them on PATH). The mypy test takes a few seconds — that is expected. If the ruff format check fails, diff its output against the goldens and fix the emitter's layout (goldens change only if ruff's own style demands it — then update goldens in the same commit and note why).

- [ ] **Step 3: Update AGENTS.md**

In `AGENTS.md`, find the bullet starting with `- \`src/remora/codegen/\` — the M2 generator's front half.` and change its first sentence to say the module now also holds the back half, appending this sentence to the end of that bullet (keep everything else intact):

```
`emit.py` is the back half: `emit_protocol(protocol, fields, multi)` renders one protocol's paired `.py` (compact `_table_`, import-pure) and `.pyi` (one `Field[T]`/`MultiField[T]` attr per field) sources, byte-deterministic, in input field order; multiplicity has no `-G fields` signal so the multi-abbrev set is caller-supplied, mangled-name collisions are first-wins with `EmitWarning`s, and `mangle_protocol` (lowercase, non-alnum→`_`, digit→`p_` prefix, keyword→trailing `_`) names the module, upper-cased for the class.
```

Also change `parse.py` description phrase `the M2 generator's front half` → keep as-is (already accurate). Do not rewrite other bullets.

- [ ] **Step 4: Run the full gate and commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration"
git add tests/test_codegen_emit.py AGENTS.md
git commit -m "codegen: gate emitted output on ruff and mypy --strict"
```

---

### Task 7: Full verification + PR

**Files:** none (verification only)

- [ ] **Step 1: Run the complete gate, including integration tests if tshark is present**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
```

Expected: all green. If tshark is absent locally, `uv run pytest -m "not integration"` green is acceptable (CI runs the rest).

- [ ] **Step 2: Verify acceptance criteria explicitly**

- Seed pairing tests unmodified: `git diff main -- tests/test_proto_seed.py` → empty.
- Drop-in compatibility: `uv run pytest tests/test_codegen_emit.py -k SeedDropIn -v` → green.
- Determinism: `uv run pytest tests/test_codegen_emit.py -k Determinism -v` → green.
- mypy on generated stub + import purity: `uv run pytest tests/test_codegen_emit.py -k "mypy or ImportPurity" -v` → green.
- Multi annotation: `uv run pytest tests/test_codegen_emit.py -k multi -v` → green.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/issue-14-emit-modules
gh pr create --repo iceboundrock/remora \
  --title "codegen: emit paired .py runtime tables and .pyi stubs" \
  --body "$(cat <<'EOF'
Closes #14

Implements `src/remora/codegen/emit.py`, the back half of the M2 generator:

- `emit_protocol(protocol, fields, multi)` renders, per protocol, a runtime `.py` module (compact `_table_` literal consumed by the lazy metaclass — no per-field work at import) and a `.pyi` stub (one `Field[T]`/`MultiField[T]` annotated attribute per field, types drawn from `FTYPE_TABLE`).
- Output is byte-deterministic (tested across two runs); table entries and stub attributes follow input field order; the caller-supplied `multi` abbrev set is membership-tested only.
- `mangle_protocol` freezes the protocol-abbrev → module/class name policy; per-protocol mangled-name collisions (the policy is not injective) are first-wins with `EmitWarning`s, mirroring the parser's policy.
- Drop-in compatibility: each seed (`eth`/`ip`/`tcp`/`udp`/`dns`) regenerated from its own table passes the unmodified `test_proto_seed.py` pairing contract, and its generated `_table_`/stub are exactly equivalent to the checked-in seed's.
- Toolchain gates in tests: emitted seed modules pass `ruff format --check`/`ruff check`, and the generated `dns.pyi` passes `mypy --strict`.

Out of scope (per issue): fingerprint headers (#16), `psdsl gen` CLI (#21), protocol selection/shipping (#19).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Report the PR URL**
