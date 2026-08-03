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

Protocol mangling, like field mangling, is **not injective**: ``mp2t.af``
and ``mp2t-af`` both mangle to ``mp2t_af``. :func:`emit_protocol` is a
per-protocol function with no view of its siblings, so it cannot detect
module-name collisions; batch callers (#19/#21) MUST dedupe the emitted
module names across a whole dump.

Line length: emitted lines can exceed the repo's 100-column ruff limit when
field abbrevs or mangled attr names are long. A ``.py`` table entry line is
about 20 characters of overhead plus the attr name, the abbrev and the
ftype; a ``.pyi`` annotation line is a single attribute annotation and
cannot be wrapped at all. The five seed protocols (eth/ip/tcp/udp/dns) are
lint-clean, but arbitrary ``tshark -G fields`` dumps are not — roughly a
quarter of real protocols emit at least one over-long line. Entries stay on
one line by design; the lint policy for generated trees (per-file E501
ignores, an exclude, or exploded table entries) is deferred to the
protocol-shipping issue (#19), where generated modules are actually
committed.
"""

from __future__ import annotations

import keyword
import textwrap
from collections.abc import Sequence, Set
from dataclasses import dataclass

from remora.codegen.mangle import mangle_field
from remora.codegen.parse import FieldDef, Protocol
from remora.values import get_info

__all__ = ["EmitWarning", "EmittedModule", "emit_protocol", "mangle_protocol"]


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
        # Strip against the module's protocol abbrev, not ``field.parent``: the attribute
        # namespace belongs to the module. Fields registered under a different parent
        # (e.g. ``can.len`` under ``acf-can``) keep their full abbrev under either choice.
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
    text = f"{protocol.name} (tshark layer ``{protocol.abbrev}``)."
    # Wrap first, escape after: escaping first lets textwrap split a ``\\`` escape
    # sequence, leaving a line ending in a lone backslash (a line continuation).
    wrapped = [_escape(line) for line in textwrap.wrap(text, width=92)]
    if len(wrapped) <= 1:
        return [f'    """{_escape(text)}"""']
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
