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

Extended operators (issue #17)
------------------------------
``field.in_([...])`` (set membership with inclusive ranges),
``field.contains(...)`` (substring/subsequence), and ``field.matches(...)``
(case-insensitive regex) build dedicated nodes::

    PORT.in_([80, 443, range(8000, 8081)])   # tcp.port in {80, 443, 8000 .. 8080}
    HOST.contains("example")                 # http.host contains "example"
    HOST.matches(r"^ex.*com$")               # http.host matches "^ex.*com$"

Python's ``in`` operator is NOT the membership API: ``443 in PORT`` calls
``__contains__``, whose result Python coerces to bool, so it can never
return an Expr — it raises :class:`TypeError` pointing at ``in_``/
``contains``, the same loud-failure policy as ``__bool__``.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import NoReturn, Protocol, TypeAlias, cast, runtime_checkable

__all__ = [
    "And",
    "CompareOp",
    "Comparison",
    "Contains",
    "Expr",
    "FieldExprOps",
    "FieldLike",
    "LiteralValue",
    "Matches",
    "Membership",
    "MembershipItem",
    "Not",
    "Or",
    "Presence",
    "ValueRange",
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


@dataclass(frozen=True, slots=True)
class ValueRange:
    """Inclusive ``lo..hi`` set element for :class:`Membership`.

    A literal value pair, not an Expr node — structural equality and
    hashability come from the plain frozen dataclass. Endpoint ordering is
    validated by the backends after per-ftype coercion (an inverted range
    raises ValueError there, from both backends alike).
    """

    lo: LiteralValue
    hi: LiteralValue

    def __post_init__(self) -> None:
        for side, value in (("lo", self.lo), ("hi", self.hi)):
            if not isinstance(value, _LITERAL_TYPES):
                raise TypeError(
                    f"unsupported {side} endpoint type for ValueRange: {type(value).__name__}"
                )


MembershipItem: TypeAlias = "LiteralValue | ValueRange"


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
        if isinstance(self, Membership):
            assert isinstance(other, Membership)
            return (
                self.field.name == other.field.name
                and len(self.values) == len(other.values)
                and all(_item_equal(a, b) for a, b in zip(self.values, other.values, strict=True))
            )
        if isinstance(self, Contains):
            assert isinstance(other, Contains)
            return (
                self.field.name == other.field.name
                and type(self.needle) is type(other.needle)
                and self.needle == other.needle
            )
        if isinstance(self, Matches):
            assert isinstance(other, Matches)
            return self.field.name == other.field.name and self.pattern == other.pattern
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
class Membership(Expr):
    """``field in {v1, v2, lo .. hi}`` — set membership with optional ranges."""

    field: FieldLike
    values: tuple[MembershipItem, ...]

    def __post_init__(self) -> None:
        if not self.values:
            raise ValueError("membership set must not be empty (it would match nothing)")
        for item in self.values:
            if not isinstance(item, ValueRange) and not isinstance(item, _LITERAL_TYPES):
                raise TypeError(f"unsupported membership element type: {type(item).__name__}")


@dataclass(frozen=True, eq=False, slots=True)
class Contains(Expr):
    """``field contains needle`` — substring (str) / subsequence (bytes) test."""

    field: FieldLike
    needle: str | bytes

    def __post_init__(self) -> None:
        if not isinstance(self.needle, str | bytes):
            raise TypeError(
                f"contains needle must be str or bytes, not {type(self.needle).__name__}"
            )
        if not self.needle:
            raise ValueError("contains needle must not be empty (it would match every packet)")


@dataclass(frozen=True, eq=False, slots=True)
class Matches(Expr):
    """``field matches pattern`` — case-insensitive regex test (Wireshark default)."""

    field: FieldLike
    pattern: str

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, str):
            raise TypeError(f"matches pattern must be str, not {type(self.pattern).__name__}")
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"invalid regular expression {self.pattern!r}: {exc}") from None


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
    :class:`FieldLike`. Because ``__eq__`` is overridden to build ``Expr``
    (never a bool), instances are deliberately **unhashable** (defining
    ``__eq__`` sets ``__hash__`` to ``None``): a hash-by-name would break the
    moment a set or dict probed equality on a collision and got an ``Expr``
    back. Code that needs to dedup or key field refs should use ``.name``.
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

    def present(self) -> Presence:
        """Build a field-existence test: ``IP.src.present()``."""
        return Presence(self._self_field())

    def in_(self, values: Iterable[object]) -> Membership:
        """Set membership: ``PORT.in_([80, 443, range(8000, 8081)])``.

        Elements may be literals, ``(lo, hi)`` tuples (inclusive ranges),
        Python ``range`` objects with step 1 (half-open, converted to the
        inclusive ``start..stop-1``), or :class:`ValueRange` directly. Named
        ``in_`` because Python's ``in`` operator cannot build an Expr — see
        ``__contains__``.
        """
        return Membership(self._self_field(), tuple(_membership_item(v) for v in values))

    def contains(self, needle: str | bytes) -> Contains:
        """Substring/subsequence test: ``HOST.contains("example")``."""
        return Contains(self._self_field(), needle)

    def matches(self, pattern: str) -> Matches:
        """Case-insensitive regex test: ``HOST.matches(r"^ex.*com$")``."""
        return Matches(self._self_field(), pattern)

    def __contains__(self, item: object) -> NoReturn:
        raise TypeError(
            "the `in` operator coerces its result to bool and can never build an "
            "Expr; use field.in_([...]) for set membership or field.contains(...) "
            "for substring tests"
        )


def _literal(value: object) -> LiteralValue:
    if not isinstance(value, _LITERAL_TYPES):
        raise TypeError(
            f"unsupported literal type for comparison: {type(value).__name__} "
            f"(allowed: {', '.join(t.__name__ for t in _LITERAL_TYPES)})"
        )
    # isinstance against a tuple variable does not narrow for mypy.
    return cast(LiteralValue, value)


def _literal_equal(a: LiteralValue, b: LiteralValue) -> bool:
    """Type-strict literal comparison (1 and True are not equal)."""
    return type(a) is type(b) and bool(a == b)


def _item_equal(a: MembershipItem, b: MembershipItem) -> bool:
    if isinstance(a, ValueRange) or isinstance(b, ValueRange):
        return (
            isinstance(a, ValueRange)
            and isinstance(b, ValueRange)
            and _literal_equal(a.lo, b.lo)
            and _literal_equal(a.hi, b.hi)
        )
    return _literal_equal(a, b)


def _membership_item(value: object) -> MembershipItem:
    """Normalize one ``in_`` element: literal, (lo, hi) tuple, range, or ValueRange."""
    if isinstance(value, ValueRange):
        return value
    if isinstance(value, range):
        if value.step != 1:
            raise ValueError(f"range with step {value.step} has no membership meaning; use step 1")
        if len(value) == 0:
            raise ValueError(f"empty range {value!r} in membership set")
        return ValueRange(value.start, value.stop - 1)
    if isinstance(value, tuple):
        if len(value) != 2:
            raise TypeError(f"membership range tuple must be (lo, hi), got {len(value)} elements")
        lo, hi = value
        if not isinstance(lo, _LITERAL_TYPES) or not isinstance(hi, _LITERAL_TYPES):
            raise TypeError("membership range endpoints must be literal values")
        return ValueRange(cast("LiteralValue", lo), cast("LiteralValue", hi))
    if isinstance(value, _LITERAL_TYPES):
        return cast("LiteralValue", value)
    raise TypeError(
        f"unsupported membership element type: {type(value).__name__} "
        "(allowed: literals, (lo, hi) tuples, range with step 1, ValueRange)"
    )


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
    if isinstance(expr, Comparison | Presence | Membership | Contains | Matches):
        yield expr.field
    elif isinstance(expr, Not):
        yield from field_refs(expr.operand)
    elif isinstance(expr, And | Or):
        yield from field_refs(expr.left)
        yield from field_refs(expr.right)
