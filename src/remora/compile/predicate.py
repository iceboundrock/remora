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
from collections.abc import Callable
from typing import Any

from remora import values
from remora.expr import And, CompareOp, Comparison, Expr, Not, Or, Presence
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

    Literal normalization happens here, once per ``Comparison``; malformed
    user literals raise ``ValueError``/``TypeError`` immediately, before any
    packet is seen. The returned predicate raises ``ValueError`` when a
    packet's raw text is malformed for the field's ftype. An unknown ``Expr``
    subclass raises :class:`TypeError` (see module docstring).
    """
    if isinstance(expr, Comparison):
        op = _OPS[expr.op]
        name = expr.field.name
        ftype = expr.field.ftype
        lit = values.coerce_literal(ftype, expr.value)

        def compare(pkt: RawPacket) -> bool:
            # any() over () is False, so an absent field never matches.
            return any(op(values.convert(ftype, raw), lit) for raw in pkt.get_raw(name))

        return compare
    if isinstance(expr, Presence):
        name = expr.field.name

        def present(pkt: RawPacket) -> bool:
            return pkt.get_raw(name) != ()

        return present
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
