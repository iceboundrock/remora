"""Compile :class:`~remora.expr.Expr` trees to Wireshark display-filter strings.

Rendering rules
---------------
- ``Comparison(op, field, value)`` -> ``field.name op literal``
- ``Presence(field)`` -> the bare field name
- ``Not(x)`` -> ``!(x)`` — **always** this form. The DSL's ``!=`` arrives as
  ``Not(Comparison(EQ, ...))`` and compiles to ``!(field == value)``, never
  ``field != value``: on multi-value fields (e.g. ``tcp.port``) Wireshark's
  ``!=`` means "some occurrence differs", which is almost never what the user
  meant. ``!(field == value)`` means "no occurrence equals", the intended
  semantics.
- ``And(l, r)`` -> ``(l) && (r)``; ``Or(l, r)`` -> ``(l) || (r)``. Every
  operand is parenthesized so the emitted string preserves the IR tree
  structure regardless of nesting depth.

Literal rendering
-----------------
Literals are first normalized with :func:`remora.values.coerce_literal` (so
``IP.src == "10.0.0.1"`` compares an :class:`~ipaddress.IPv4Address`, and
garbage like ``"not-an-ip"`` is rejected), then rendered by the resulting
Python type: bools as ``1``/``0``, ints as decimal, floats via ``repr``,
strings double-quoted with backslash escapes, IP addresses bare, bytes as
colon-hex (``aa:bb:cc``).

Time literals (M1 design decision)
----------------------------------
``datetime``/``timedelta`` comparisons raise :class:`UnsupportedExprError`:
absolute/relative-time comparisons are not pushed down to the display filter
in M1; the planner keeps them as residual Python predicates.

Error policy
------------
:class:`UnsupportedExprError` means "this backend legitimately cannot render
the expression; the planner should fall back to the Python predicate backend"
(time literals, empty bytes, unknown future Expr nodes). User errors —
malformed literals such as ``IP.src == "not-an-ip"`` — surface as the
``ValueError``/``TypeError`` that :func:`remora.values.coerce_literal` raises
and are deliberately *not* converted into :class:`UnsupportedExprError`.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from remora import values
from remora.expr import And, Comparison, Expr, Not, Or, Presence

__all__ = ["UnsupportedExprError", "compile_dfilter"]


class UnsupportedExprError(Exception):
    """Expr shape the dfilter backend cannot render; the planner catches this
    and routes the conjunct to the Python predicate backend instead."""


def compile_dfilter(expr: Expr) -> str:
    """Render ``expr`` as a Wireshark display-filter string.

    Raises :class:`UnsupportedExprError` when the expression cannot be
    expressed as a display filter (see module docstring for the error policy).
    """
    if isinstance(expr, Comparison):
        literal = _render_literal(values.coerce_literal(expr.field.ftype, expr.value))
        return f"{expr.field.name} {expr.op.value} {literal}"
    if isinstance(expr, Presence):
        return expr.field.name
    if isinstance(expr, Not):
        return f"!({compile_dfilter(expr.operand)})"
    if isinstance(expr, And):
        return f"({compile_dfilter(expr.left)}) && ({compile_dfilter(expr.right)})"
    if isinstance(expr, Or):
        return f"({compile_dfilter(expr.left)}) || ({compile_dfilter(expr.right)})"
    raise UnsupportedExprError(
        f"dfilter backend cannot render Expr node of type {type(expr).__name__}"
    )


def _render_literal(value: object) -> str:
    """Render a *normalized* literal (output of ``coerce_literal``) as dfilter text."""
    # bool before int: bool subclasses int.
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, bytes):
        if not value:
            raise UnsupportedExprError("empty bytes literal has no display-filter rendering")
        return ":".join(f"{byte:02x}" for byte in value)
    if isinstance(value, datetime | timedelta):
        raise UnsupportedExprError(
            "time comparisons are not pushed down to display filters in M1; "
            "the planner evaluates them as Python predicates"
        )
    raise UnsupportedExprError(f"cannot render literal of type {type(value).__name__}")
