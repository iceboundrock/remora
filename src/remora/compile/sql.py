"""Compile :class:`~remora.expr.Expr` trees to DuckDB SQL predicates.

The third backend for one IR: :mod:`remora.compile.dfilter` renders Wireshark
display filters, :mod:`remora.compile.predicate` evaluates Python predicates
over :class:`~remora.fields.RawPacket`, and this module renders a SQL boolean
expression over the workspace's ``pkts`` table. The analyses a display filter
cannot express therefore still use the same typed field references.

Output shape
------------
:func:`compile_sql` returns a :class:`SqlPredicate` — a SQL string with ``?``
placeholders and the tuple of values to bind, in placeholder order. Literals are
**never** interpolated into the string, so a hostile literal is inert. Callers
splice the string into a ``WHERE`` clause and pass ``list(predicate.params)`` to
``con.execute``.

Where the compiler gets its facts
---------------------------------
From the field reference alone, exactly like the sibling backends: ``name``
becomes a column through :func:`remora.workspace.naming.column_name` (the frozen
policy — imported, never re-derived), ``ftype`` selects the SQL type and the
value encoder from :mod:`remora.workspace.types`, and ``multi`` decides scalar
column vs ``LIST`` column. Identifiers are always double-quoted, which is the
assumption ``naming.py`` records: a column name needs no reserved-word casing
because generated SQL quotes it.

Rendering rules
---------------
- ``Comparison(op, field, literal)`` on a **scalar** column ->
  ``"col" <op> ?``.
- ``Comparison(EQ, field, literal)`` on a **multi** column ->
  ``list_contains("col", ?)``: any-occurrence semantics, matching Wireshark's
  multi-value ``==`` and the predicate backend's ``any()``.
- Ordered comparisons on a multi column -> ``len(list_filter("col", x -> x <op>
  ?)) > 0``, the same any-occurrence rule spelled out for a list.
- ``Presence(field)`` -> ``"col" IS NOT NULL`` (scalar) / ``len(coalesce("col", [])) > 0``
  (multi).
- ``Membership(field, values)`` -> the ``OR`` of one term per element; a
  :class:`~remora.expr.ValueRange` element becomes ``"col" BETWEEN ? AND ?``
  (multi: ``len(list_filter("col", x -> x BETWEEN ? AND ?)) > 0``). Subnet
  membership is exactly this shape over the integer address columns
  (``FT_IPv4`` -> ``UINTEGER``, ``FT_IPv6`` -> ``UHUGEINT``), which is why #26
  stores addresses as integers: a range over an ordered column is what DuckDB's
  zone maps can skip row groups on.
- ``Contains(field, needle)`` -> ``contains("col", ?)`` on ``VARCHAR`` columns
  (multi: ``len(list_filter("col", x -> contains(x, ?))) > 0``).
- ``Not(x)`` -> ``NOT (x)`` — **always** this form. The DSL's ``!=`` arrives as
  ``Not(Comparison(EQ, ...))``, so it renders ``NOT ("col" = ?)`` /
  ``NOT (list_contains("col", ?))`` and never SQL ``<>``: on a ``LIST`` column
  ``<>`` would compare the whole list, which is not what "no occurrence equals"
  means.
- ``And(l, r)`` -> ``(l AND r)``; ``Or(l, r)`` -> ``(l OR r)``. Compound nodes
  parenthesize themselves; leaves are already self-delimiting (``=``, ``BETWEEN``
  and ``>`` all bind tighter than ``AND``/``OR``), so the emitted string can be
  spliced into a ``WHERE`` clause as it stands.

Parameter encoding
------------------
A literal is normalized once with :func:`remora.values.coerce_literal` (so
``IP.src == "10.0.0.1"`` binds an integer address and ``"not-an-ip"`` is
rejected), then encoded with :mod:`remora.workspace.types`' codec for the ftype
— the same encoder the materialize path writes the column with, so a bound value
and a stored value can never disagree.

``FT_IPv6`` is the one ftype whose encoder emits **decimal text** rather than the
``int`` its ``UHUGEINT`` column suggests (see
``remora.workspace.types._ipv6_to_decimal_text``), so its placeholder is wrapped
as ``CAST(? AS UHUGEINT)``: explicit in scalar position, and required for
``list_contains`` to bind against a ``UHUGEINT[]`` element type. No other ftype
needs it — do not broaden it.

NULL and absence (stated, deliberately not harmonized — see issue #29)
---------------------------------------------------------------------
Materialization (#26) writes an absent scalar as ``NULL`` and an absent
multi-value field as ``[]``, and SQL is three-valued, so:

- **Absent multi column** (``[]``): ``list_contains([], v)`` is ``false`` and
  ``len(list_filter([], ...)) > 0`` is ``false``, so a positive test excludes the
  row and ``NOT (...)`` includes it — identical to the predicate backend, whose
  ``any()`` over no occurrences is ``False``.
- **Absent scalar column** (``NULL``): ``"col" = ?`` is ``NULL``, so the row is
  excluded — same row set as the predicate backend. Under negation the two
  **diverge**: ``NOT (NULL)`` is ``NULL``, so SQL excludes the row while the
  predicate backend's ``not False`` includes it. ``x != v`` on a scalar field
  therefore does not select packets missing the field, where the Wireshark and
  Python backends do.
- **Presence is exempt**: ``IS NOT NULL`` and ``len(coalesce(..., [])) > 0`` never yield
  ``NULL``, so ``~field.present()`` matches the other backends exactly.
- **A multi column back-filled with ``NULL``** (a column added after older rows
  were written) behaves like the absent-scalar case for comparisons (``list_contains(NULL, v)``
  is ``NULL``), but presence treats it as absent via ``coalesce(..., [])``.

Reconciling that divergence across backends is explicitly out of scope for issue
#29; it is stated here so callers can rely on it rather than discover it.

Error policy
------------
:class:`UnsupportedSqlExprError` means "this backend legitimately cannot render
the expression" — an unknown ``Expr`` node, ``Matches`` (DuckDB's regex engine is
RE2, whose dialect and case folding differ from Wireshark's PCRE2 and the
predicate backend's Python ``re``), and ``Contains`` on a ``BLOB`` column
(DuckDB's ``contains`` takes ``VARCHAR`` or ``LIST``, not ``BLOB``). User errors
— a malformed literal such as ``IP.src == "not-an-ip"``, or a ``contains`` needle
whose type does not match the field — surface as the ``ValueError``/``TypeError``
the sibling backends raise and are deliberately not converted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from remora import values
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Contains,
    Expr,
    FieldLike,
    LiteralValue,
    Matches,
    Membership,
    MembershipItem,
    Not,
    Or,
    Presence,
    ValueRange,
)
from remora.workspace.naming import column_name
from remora.workspace.types import column_sql_type, get_column_type

__all__ = ["SqlPredicate", "UnsupportedSqlExprError", "compile_sql"]


class UnsupportedSqlExprError(Exception):
    """Expr shape the DuckDB SQL backend cannot render.

    Mirrors :class:`remora.compile.dfilter.UnsupportedExprError`: it means the
    backend refuses the expression, not that the user made a mistake.
    """


@dataclass(frozen=True)
class SqlPredicate:
    """A SQL boolean expression and the values to bind into it.

    Attributes:
        sql: SQL text with ``?`` placeholders, self-delimiting so it can be
            spliced straight into a ``WHERE`` clause.
        params: Values to bind, in placeholder order. Pass ``list(params)`` to
            ``DuckDBPyConnection.execute``.
    """

    sql: str
    params: tuple[Any, ...]


_SQL_OPS: Final[dict[CompareOp, str]] = {
    CompareOp.EQ: "=",
    CompareOp.LT: "<",
    CompareOp.LE: "<=",
    CompareOp.GT: ">",
    CompareOp.GE: ">=",
}

#: FTypes whose encoded parameter needs an explicit cast to the column type.
#: ``FT_IPv6`` alone: its encoder emits decimal text (see the module docstring).
_CAST_FTYPES: Final[frozenset[str]] = frozenset({"FT_IPv6"})

#: Lambda variable used by the any-occurrence ``list_filter`` forms.
_LAMBDA_VAR: Final[str] = "x"


def compile_sql(expr: Expr) -> SqlPredicate:
    """Render ``expr`` as a DuckDB SQL predicate with bound parameters.

    Args:
        expr: The expression tree to compile.

    Returns:
        The SQL text and the parameter values, in placeholder order.

    Raises:
        UnsupportedSqlExprError: If the backend cannot render a node (see the
            module docstring's error policy).
        ValueError: If a literal is malformed for the field's ftype, or a
            membership range is inverted.
        TypeError: If a literal's type is wrong for the field's ftype.
    """
    params: list[Any] = []
    sql = _render(expr, params)
    return SqlPredicate(sql, tuple(params))


def _render(expr: Expr, params: list[Any]) -> str:
    """Render one node, appending its parameters to ``params`` in order."""
    if isinstance(expr, Comparison):
        return _render_comparison(expr, params)
    if isinstance(expr, Presence):
        column = _column(expr.field)
        return f"len(coalesce({column}, [])) > 0" if expr.field.multi else f"{column} IS NOT NULL"
    if isinstance(expr, Membership):
        return _render_membership(expr, params)
    if isinstance(expr, Contains):
        return _render_contains(expr, params)
    if isinstance(expr, Matches):
        raise UnsupportedSqlExprError(
            "matches is not compiled to SQL: DuckDB's regexp engine is RE2, whose "
            "dialect and case folding differ from Wireshark's PCRE2 and the "
            "predicate backend's Python re"
        )
    if isinstance(expr, Not):
        return f"NOT ({_render(expr.operand, params)})"
    if isinstance(expr, And):
        return f"({_render(expr.left, params)} AND {_render(expr.right, params)})"
    if isinstance(expr, Or):
        return f"({_render(expr.left, params)} OR {_render(expr.right, params)})"
    raise UnsupportedSqlExprError(
        f"sql backend cannot render Expr node of type {type(expr).__name__}"
    )


def _render_comparison(expr: Comparison, params: list[Any]) -> str:
    """Render ``field <op> literal`` against a scalar or a LIST column."""
    field = expr.field
    column = _column(field)
    placeholder = _placeholder(field.ftype)
    params.append(_encode(field.ftype, expr.value))
    if not field.multi:
        return f"{column} {_SQL_OPS[expr.op]} {placeholder}"
    if expr.op is CompareOp.EQ:
        return f"list_contains({column}, {placeholder})"
    return _any_occurrence(column, f"{_LAMBDA_VAR} {_SQL_OPS[expr.op]} {placeholder}")


def _render_membership(expr: Membership, params: list[Any]) -> str:
    """Render ``field in {...}`` as the OR of one term per set element."""
    column = _column(expr.field)
    terms = [_render_member(expr.field, column, item, params) for item in expr.values]
    if len(terms) == 1:
        return terms[0]
    return "(" + " OR ".join(terms) + ")"


def _render_member(field: FieldLike, column: str, item: MembershipItem, params: list[Any]) -> str:
    """Render one membership element: an equality, or an inclusive range.

    A range over an address column is exactly the subnet predicate: ``BETWEEN``
    over the integer form, which DuckDB's zone maps can skip row groups on.
    """
    ftype = field.ftype
    placeholder = _placeholder(ftype)
    if isinstance(item, ValueRange):
        lo: Any = values.coerce_literal(ftype, item.lo)
        hi: Any = values.coerce_literal(ftype, item.hi)
        if hi < lo:
            raise ValueError(f"inverted membership range: {item.lo!r}..{item.hi!r}")
        encode = get_column_type(ftype).encode
        params.append(encode(lo))
        params.append(encode(hi))
        between = f"BETWEEN {placeholder} AND {placeholder}"
        if field.multi:
            return _any_occurrence(column, f"{_LAMBDA_VAR} {between}")
        return f"{column} {between}"
    params.append(_encode(ftype, item))
    if field.multi:
        return f"list_contains({column}, {placeholder})"
    return f"{column} = {placeholder}"


def _render_contains(expr: Contains, params: list[Any]) -> str:
    """Render ``field contains needle`` over a VARCHAR (or VARCHAR LIST) column."""
    field = expr.field
    needle = expr.needle
    py_type = values.get_info(field.ftype).py_type
    if not (
        (py_type is str and isinstance(needle, str))
        or (py_type is bytes and isinstance(needle, bytes))
    ):
        raise TypeError(
            "contains needs a str needle on string fields and a bytes needle on "
            f"bytes fields; got {type(needle).__name__} for {field.ftype}"
        )
    if py_type is not str:
        raise UnsupportedSqlExprError(
            f"contains on {field.ftype} is not compiled to SQL: the column is "
            f"{column_sql_type(field.ftype)} and DuckDB's contains() takes VARCHAR "
            "or LIST, not BLOB"
        )
    column = _column(field)
    params.append(needle)
    if field.multi:
        return _any_occurrence(column, f"contains({_LAMBDA_VAR}, ?)")
    return f"contains({column}, ?)"


def _quote(name: str) -> str:
    """Double-quote a SQL identifier, escaping embedded double quotes."""
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _column(field: FieldLike) -> str:
    """Quoted column name for a field, from the frozen naming policy."""
    return _quote(column_name(field.name))


def _placeholder(ftype: str) -> str:
    """Placeholder for one bound value, cast when the encoding needs it."""
    if ftype in _CAST_FTYPES:
        return f"CAST(? AS {column_sql_type(ftype)})"
    return "?"


def _encode(ftype: str, value: LiteralValue) -> Any:
    """Normalize a user literal and encode it the way the column stores it."""
    return get_column_type(ftype).encode(values.coerce_literal(ftype, value))


def _any_occurrence(column: str, condition: str) -> str:
    """Wrap a per-element condition as an any-occurrence test over a LIST column."""
    return f"len(list_filter({column}, {_LAMBDA_VAR} -> {condition})) > 0"
