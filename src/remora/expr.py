"""Immutable expression IR — the neutral core of the Remora DSL.

Operator overloading builds :class:`Expr` trees, which later compile to
Wireshark display-filter strings or Python predicates.

Precedence pitfall
------------------
Python's ``&``/``|`` bind *tighter* than comparison operators, so comparisons
combined with ``&``/``|`` MUST be parenthesized::

    (IP.src == "10.0.0.1") & (TCP.port == 443)   # correct
    IP.src == "10.0.0.1" & TCP.port == 443       # wrong: & runs first

``and``/``or``/``not`` and chained comparisons cannot be overloaded; they call
``__bool__``, which raises :class:`TypeError` so misuse fails loudly instead of
silently misbehaving.

There is deliberately no ``Ne`` node and no ``CompareOp.NE``: ``!=`` builds
``Not(Comparison(EQ, ...))`` structurally. This guarantees the Wireshark
multi-value ``!=`` pitfall (``tcp.port != 443`` meaning "some occurrence
differs") is unrepresentable — negation always renders as ``!(field == value)``.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol, cast, runtime_checkable

__all__ = [
    "And",
    "CompareOp",
    "Comparison",
    "Expr",
    "FieldExprOps",
    "FieldLike",
    "LiteralValue",
    "Not",
    "Or",
    "Presence",
    "conjuncts",
    "field_refs",
]


@runtime_checkable
class FieldLike(Protocol):
    """Structural stand-in for :class:`remora.fields.FieldRef`.

    ``expr`` is a leaf module: it never imports ``remora.fields``. Anything
    carrying these three attributes can appear inside an expression tree.
    """

    @property
    def name(self) -> str:
        """Canonical tshark field name, e.g. ``"ip.src"``."""
        ...

    @property
    def ftype(self) -> str:
        """tshark field type name, e.g. ``"FT_IPv4"``."""
        ...

    @property
    def multi(self) -> bool:
        """True if the field can occur multiple times per packet."""
        ...


# Literal values are restricted to a closed union of hashable types so that
# every Expr node is hashable by construction (lists/dicts are rejected).
LiteralValue = int | float | bool | str | bytes | IPv4Address | IPv6Address | datetime | timedelta
_LITERAL_TYPES: tuple[type, ...] = (
    int,
    float,
    bool,
    str,
    bytes,
    IPv4Address,
    IPv6Address,
    datetime,
    timedelta,
)


class CompareOp(enum.Enum):
    """Comparison operators. Deliberately no ``NE`` — see module docstring."""

    EQ = "=="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="


class Expr:
    """Base class for all expression nodes.

    Subclasses are ``@dataclass(frozen=True, eq=False, slots=True)``:
    immutable, with identity-based ``__eq__``/``__hash__`` inherited from
    ``object`` (hashable by construction). Structural comparison — needed
    because ``__eq__`` is repurposed on field refs — is :meth:`equals`.
    """

    __slots__ = ()

    def __and__(self, other: Expr) -> And:
        return And(self, other)

    def __or__(self, other: Expr) -> Or:
        return Or(self, other)

    def __invert__(self) -> Not:
        return Not(self)

    def __bool__(self) -> bool:
        raise TypeError(
            "Expr has no truth value. Use & | ~ instead of and/or/not, and "
            "parenthesize comparisons: (IP.src == a) & (TCP.port == 443)."
        )

    def equals(self, other: object) -> bool:
        """Structural comparison.

        Field refs are compared by ``.name``; literals by type and value
        (``1`` and ``True`` are *not* structurally equal).
        """
        if self is other:
            return True
        if type(self) is not type(other):
            return False
        assert isinstance(other, Expr)
        if isinstance(self, Comparison):
            assert isinstance(other, Comparison)
            return (
                self.op is other.op
                and self.field.name == other.field.name
                and type(self.value) is type(other.value)
                and bool(self.value == other.value)
            )
        if isinstance(self, Presence):
            assert isinstance(other, Presence)
            return self.field.name == other.field.name
        if isinstance(self, Not):
            assert isinstance(other, Not)
            return self.operand.equals(other.operand)
        assert isinstance(self, And | Or)
        assert isinstance(other, And | Or)
        return self.left.equals(other.left) and self.right.equals(other.right)


def _check_operand(value: object, side: str) -> None:
    if not isinstance(value, Expr):
        raise TypeError(
            f"{side} operand of a logical connective must be an Expr, not {type(value).__name__}"
        )


@dataclass(frozen=True, eq=False, slots=True)
class Comparison(Expr):
    """``field <op> literal``."""

    op: CompareOp
    field: FieldLike
    value: LiteralValue

    def __post_init__(self) -> None:
        if not isinstance(self.value, _LITERAL_TYPES):
            raise TypeError(
                f"unsupported literal type for comparison: {type(self.value).__name__} "
                f"(allowed: {', '.join(t.__name__ for t in _LITERAL_TYPES)})"
            )


@dataclass(frozen=True, eq=False, slots=True)
class Presence(Expr):
    """Field-existence test; compiles to a bare field name in display filters."""

    field: FieldLike


@dataclass(frozen=True, eq=False, slots=True)
class And(Expr):
    left: Expr
    right: Expr

    def __post_init__(self) -> None:
        _check_operand(self.left, "left")
        _check_operand(self.right, "right")


@dataclass(frozen=True, eq=False, slots=True)
class Or(Expr):
    left: Expr
    right: Expr

    def __post_init__(self) -> None:
        _check_operand(self.left, "left")
        _check_operand(self.right, "right")


@dataclass(frozen=True, eq=False, slots=True)
class Not(Expr):
    operand: Expr

    def __post_init__(self) -> None:
        _check_operand(self.operand, "the")


class FieldExprOps:
    """Mixin giving a :class:`FieldLike` object expression-building operators.

    ``remora.fields.FieldRef`` inherits this; a class using it must satisfy
    :class:`FieldLike`. Because ``__eq__`` is overridden, ``__hash__`` is
    defined here explicitly as ``hash(self.name)``.
    """

    __slots__ = ()

    def _self_field(self) -> FieldLike:
        if not isinstance(self, FieldLike):
            raise TypeError(
                f"{type(self).__name__} uses FieldExprOps but does not provide "
                "name/ftype/multi field metadata"
            )
        return self

    def __eq__(self, other: object) -> Comparison:  # type: ignore[override]
        return Comparison(CompareOp.EQ, self._self_field(), _literal(other))

    def __ne__(self, other: object) -> Not:  # type: ignore[override]
        return Not(self == other)

    def __lt__(self, other: object) -> Comparison:
        return Comparison(CompareOp.LT, self._self_field(), _literal(other))

    def __le__(self, other: object) -> Comparison:
        return Comparison(CompareOp.LE, self._self_field(), _literal(other))

    def __gt__(self, other: object) -> Comparison:
        return Comparison(CompareOp.GT, self._self_field(), _literal(other))

    def __ge__(self, other: object) -> Comparison:
        return Comparison(CompareOp.GE, self._self_field(), _literal(other))

    def __hash__(self) -> int:
        return hash(self._self_field().name)

    def present(self) -> Presence:
        """Build a field-existence test: ``IP.src.present()``."""
        return Presence(self._self_field())


def _literal(value: object) -> LiteralValue:
    if not isinstance(value, _LITERAL_TYPES):
        raise TypeError(
            f"unsupported literal type for comparison: {type(value).__name__} "
            f"(allowed: {', '.join(t.__name__ for t in _LITERAL_TYPES)})"
        )
    # isinstance against a tuple variable does not narrow for mypy.
    return cast(LiteralValue, value)


def conjuncts(expr: Expr) -> Iterator[Expr]:
    """Flatten a top-level ``And`` chain: ``And(And(a, b), c)`` yields a, b, c.

    A non-``And`` expression yields itself. ``Or``/``Not`` are opaque — only
    the top-level conjunction is split (that is what the planner pushes down
    term by term).
    """
    if isinstance(expr, And):
        yield from conjuncts(expr.left)
        yield from conjuncts(expr.right)
    else:
        yield expr


def field_refs(expr: Expr) -> Iterator[FieldLike]:
    """Yield every field reference in the tree (with repeats), depth-first."""
    if isinstance(expr, Comparison | Presence):
        yield expr.field
    elif isinstance(expr, Not):
        yield from field_refs(expr.operand)
    elif isinstance(expr, And | Or):
        yield from field_refs(expr.left)
        yield from field_refs(expr.right)
