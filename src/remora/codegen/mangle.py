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
