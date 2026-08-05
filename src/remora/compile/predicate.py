"""Compile :class:`~remora.expr.Expr` trees to Python predicate functions.

This is the fallback backend: anything the display-filter backend cannot push
down (it raises :class:`~remora.compile.dfilter.UnsupportedExprError`) is
evaluated here, in Python, against :class:`~remora.fields.RawPacket` objects.
It therefore accepts every ``Expr`` shape; an unknown ``Expr`` subclass raises
:class:`TypeError` — this backend is the end of the fallback chain, so an
unrenderable node is a programming error, not an unsupported expression.

Semantics (mirror Wireshark display filters exactly)
----------------------------------------------------
- ``Comparison(op, field, value)``: the literal is normalized ONCE at compile
  time with :func:`remora.values.coerce_literal`, so user errors (malformed
  literals such as ``IP.src == "not-an-ip"``) raise ``ValueError``/``TypeError``
  at compile time — the same timing as the dfilter backend. At evaluation time
  each raw occurrence of the field is converted with
  :func:`remora.values.convert` and the comparison is true if ANY occurrence
  matches, exactly like Wireshark's multi-value ``==``. An absent field
  (``get_raw`` returns ``()``) makes every comparison False.
- ``Presence(field)``: true iff the field has at least one occurrence.
- ``Membership(field, values)``: each element (or inclusive range endpoint
  pair) is coerced once at compile time; true if ANY occurrence equals a set
  element or falls inside a range (inclusive on both ends), exactly like
  Wireshark's ``f in {…}`` (which is sugar for an ``==``-chain of ORs).
- ``Contains(field, needle)``: substring (str fields) / subsequence (bytes
  fields) on ANY occurrence; the needle's type must match the field's Python
  type (TypeError at compile time otherwise — same timing as dfilter).
- ``Matches(field, pattern)``: case-insensitive unanchored ``re.search`` on
  ANY occurrence (Wireshark's ``matches`` is case-insensitive by default);
  string fields only. Dialect note: construction restricts patterns to the
  Python-re/PCRE2 common subset (see :class:`remora.expr.Matches`), and
  matching here is **byte-oriented** — the pattern and each value are encoded
  to UTF-8 and matched as ``bytes``, so ``.``/``{m,n}`` count bytes, ``\\w``/
  ``\\d``/``\\s``/``\\b`` are ASCII, and case folding is ASCII-only. That
  mirrors Wireshark, which compiles ``matches`` with ``PCRE2_CASELESS`` but
  without UTF/UCP. One irreducible caveat remains: field text tshark could not
  decode as UTF-8 reaches us as U+FFFD replacement characters, which cannot
  round-trip to the original bytes, so such values may still diverge.
- ``Not`` / ``And`` / ``Or``: Python ``not`` / ``and`` / ``or`` over the
  recursively compiled children. Emergent semantics worth spelling out: the
  DSL's ``!=`` arrives as ``Not(Comparison(EQ, ...))``, so on a packet where
  the field is ABSENT the inner ``Eq`` is False and the ``Not`` is True —
  identical to the row set of Wireshark's ``!(f == v)``. This is intended.

Malformed-input policy
----------------------
Malformed raw data coming out of a packet raises :class:`ValueError` at
evaluation time (the :mod:`remora.values` loud policy): raw text that cannot
be parsed as the field's declared ftype is a bug worth surfacing, not a
silent non-match.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable
from typing import Any

from remora import values
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Contains,
    Expr,
    Matches,
    Membership,
    Not,
    Or,
    Presence,
    ValueRange,
)
from remora.fields import RawPacket

__all__ = ["compile_predicate"]

# Any rather than object: typeshed's ordering operators demand SupportsDunder*
# protocols, and the operands here are dynamically typed by ftype anyway.
_OPS: dict[CompareOp, Callable[[Any, Any], bool]] = {
    CompareOp.EQ: operator.eq,
    CompareOp.LT: operator.lt,
    CompareOp.LE: operator.le,
    CompareOp.GT: operator.gt,
    CompareOp.GE: operator.ge,
}


def compile_predicate(expr: Expr) -> Callable[[RawPacket], bool]:
    """Compile ``expr`` into a ``RawPacket -> bool`` predicate.

    Literal normalization happens here, once per ``Comparison``, once per
    ``Membership`` element/endpoint (after any range conversion), and at
    contains/matches entry for type validation; malformed user literals raise
    ``ValueError``/``TypeError`` immediately, before any packet is seen. The
    returned predicate raises ``ValueError`` when a packet's raw text is
    malformed for the field's ftype. An unknown ``Expr`` subclass raises
    :class:`TypeError` (see module docstring).
    """
    if isinstance(expr, Comparison):
        op = _OPS[expr.op]
        name = expr.field.name
        ftype = expr.field.ftype
        lit = values.coerce_literal(ftype, expr.value)
        # Bind the parse function once at compile time rather than looking the
        # ftype up again for every occurrence of every packet.
        parse = values.get_info(ftype).parse

        def compare(pkt: RawPacket) -> bool:
            # any() over () is False, so an absent field never matches.
            return any(op(parse(raw), lit) for raw in pkt.get_raw(name))

        return compare
    if isinstance(expr, Presence):
        name = expr.field.name

        def present(pkt: RawPacket) -> bool:
            return pkt.get_raw(name) != ()

        return present
    if isinstance(expr, Membership):
        name = expr.field.name
        ftype = expr.field.ftype
        parse = values.get_info(ftype).parse
        scalars: list[Any] = []
        ranges: list[tuple[Any, Any]] = []
        for item in expr.values:
            if isinstance(item, ValueRange):
                lo: Any = values.coerce_literal(ftype, item.lo)
                hi: Any = values.coerce_literal(ftype, item.hi)
                if hi < lo:
                    raise ValueError(f"inverted membership range: {item.lo!r}..{item.hi!r}")
                ranges.append((lo, hi))
            else:
                scalars.append(values.coerce_literal(ftype, item))

        def member(pkt: RawPacket) -> bool:
            for raw in pkt.get_raw(name):
                value = parse(raw)
                if any(value == lit for lit in scalars):
                    return True
                if any(lo <= value <= hi for lo, hi in ranges):
                    return True
            return False

        return member
    if isinstance(expr, Contains):
        name = expr.field.name
        ftype = expr.field.ftype
        needle = expr.needle
        info = values.get_info(ftype)
        if not (
            (info.py_type is str and isinstance(needle, str))
            or (info.py_type is bytes and isinstance(needle, bytes))
        ):
            raise TypeError(
                "contains needs a str needle on string fields and a bytes needle on "
                f"bytes fields; got {type(needle).__name__} for {ftype}"
            )
        parse = info.parse

        def contains(pkt: RawPacket) -> bool:
            return any(needle in parse(raw) for raw in pkt.get_raw(name))

        return contains
    if isinstance(expr, Matches):
        name = expr.field.name
        ftype = expr.field.ftype
        info = values.get_info(ftype)
        if info.py_type is not str:
            raise TypeError(f"matches is only supported on string fields, not {ftype}")
        parse = info.parse
        # Wireshark compiles `matches` patterns with PCRE2_CASELESS but without
        # UTF/UCP: matching is byte-oriented with ASCII-only case folding.
        # Compiling the pattern's UTF-8 bytes against the value's UTF-8 bytes
        # reproduces that byte-level semantics in Python re (bytes patterns use
        # ASCII \w/\d/\s and ASCII-only IGNORECASE).
        regex = re.compile(expr.pattern.encode("utf-8"), re.IGNORECASE)

        def match(pkt: RawPacket) -> bool:
            return any(
                regex.search(parse(raw).encode("utf-8")) is not None for raw in pkt.get_raw(name)
            )

        return match
    if isinstance(expr, Not):
        operand = compile_predicate(expr.operand)

        def negate(pkt: RawPacket) -> bool:
            return not operand(pkt)

        return negate
    if isinstance(expr, And):
        left, right = compile_predicate(expr.left), compile_predicate(expr.right)

        def both(pkt: RawPacket) -> bool:
            return left(pkt) and right(pkt)

        return both
    if isinstance(expr, Or):
        left, right = compile_predicate(expr.left), compile_predicate(expr.right)

        def either(pkt: RawPacket) -> bool:
            return left(pkt) or right(pkt)

        return either
    raise TypeError(
        f"predicate backend cannot compile Expr node of type {type(expr).__name__}; "
        "the predicate backend is the final fallback, so this is a programming error"
    )
