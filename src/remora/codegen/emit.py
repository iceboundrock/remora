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
