r"""Compile :class:`~remora.expr.Expr` trees to DuckDB SQL predicates.

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
``con.execute``. The one literal that binds **no** parameter is a float ``NaN``,
which compiles to the constant ``FALSE`` (see the NaN section below) — a constant
the compiler chose, never user text, so it is not an injection surface.

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
- ``>`` / ``>=`` on a **float** column additionally carry a ``NOT isnan(...)``
  guard, and a ``NaN`` literal anywhere compiles to ``FALSE`` (see the
  IEEE-754 section).
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
- ``Matches(field, pattern)`` -> ``regexp_matches("col", ?, 'i')`` wrapped in the
  portable-text guard below (multi: the same guarded test inside the
  any-occurrence ``list_filter``). String fields only; a non-string field is a
  ``TypeError``, exactly as in the sibling backends.
- ``Not(x)`` -> ``NOT (x)`` — **always** this form, with each NULL-able leaf
  inside ``x`` wrapped as ``coalesce(<leaf>, FALSE)`` (see the NULL section).
  The DSL's ``!=`` arrives as ``Not(Comparison(EQ, ...))``, so it renders
  ``NOT (coalesce("col" = ?, FALSE))`` /
  ``NOT (coalesce(list_contains("col", ?), FALSE))`` and never SQL ``<>``: on a
  ``LIST`` column ``<>`` would compare the whole list, which is not what "no
  occurrence equals" means.
- ``And(l, r)`` -> ``(l AND r)``; ``Or(l, r)`` -> ``(l OR r)``. Compound nodes
  parenthesize themselves; leaves are already self-delimiting (``=``, ``BETWEEN``
  and ``>`` all bind tighter than ``AND``/``OR``), so the emitted string can be
  spliced into a ``WHERE`` clause as it stands.

Parameter encoding
------------------
Every literal takes one two-step path, whichever node it sits in: ``_coerce``
normalizes it with :func:`remora.values.coerce_literal` (so
``IP.src == "10.0.0.1"`` binds an integer address and ``"not-an-ip"`` is
rejected), and ``_encode_coerced`` then encodes it with
:mod:`remora.workspace.types`' codec for the ftype — the same encoder the
materialize path writes the column with, so a bound value and a stored value can
never disagree.

The two halves are separate rather than one call because the value *between*
them is needed on its own: the NaN test below and a range's inversion check both
read the coerced form. Folding them back together would force the range branch
to inline its own coerce and reach for the codec directly, which is what it used
to do — one more call site for a change to the shared pipeline to miss, and one
more literal coerced twice.

``FT_IPv6`` is the one ftype whose encoder emits **decimal text** rather than the
``int`` its ``UHUGEINT`` column suggests (see
``remora.workspace.types._ipv6_to_decimal_text``), so its placeholder is wrapped
as ``CAST(? AS UHUGEINT)``: explicit in scalar position, and required for
``list_contains`` to bind against a ``UHUGEINT[]`` element type. No other ftype
needs it — do not broaden it.

NULL and absence (harmonized, issue #36)
----------------------------------------
Materialization (#26) writes an absent scalar as ``NULL`` and an absent
multi-value field as ``[]``, and SQL is three-valued, so a bare
``NOT ("col" = ?)`` is ``NULL`` for a row missing the field and excludes it —
where Wireshark and the predicate backend include it, because their ``!=`` is
``not (any occurrence equals)`` and ``any()`` over nothing is False. Issue #29
stated that divergence; #36 removes it.

The fix is to make a leaf two-valued exactly where a ``Not`` will invert it:
``coalesce(<leaf>, FALSE)``. Two details are load-bearing.

- **At the leaf, not at the subtree.** Kleene logic over leaves that all mean
  "False in Python when NULL" collapses correctly only if every leaf is
  substituted. ``NOT (NOT (x))`` with x NULL is ``NOT (coalesce(NULL, FALSE))``
  = TRUE if the subtree is coalesced, where Python's ``not not False`` is False.
- **Only under a ``Not``.** ``coalesce`` blocks DuckDB's scan-level filter
  pushdown: ``WHERE "col" = ?`` becomes a zone-map filter, ``WHERE coalesce("col"
  = ?, FALSE)`` does not. A positive leaf has no divergence to fix — a NULL
  reaching the ``WHERE`` clause is filtered out, which is what the other backends
  do — so the hot subnet-``BETWEEN`` and equality scans #26 stores integer
  addresses for keep exactly the plan they had.

Presence is untouched: ``IS NOT NULL`` and ``len(coalesce(..., [])) > 0`` never
yield ``NULL``, so they were already harmonized. A NaN literal's ``FALSE``
constant is untouched for the same reason. A multi column back-filled with
``NULL`` by a later ``add_field_column`` is covered by the same rule: its
comparisons are ``NULL``, so a negated one is coalesced and matches the
predicate backend's reading of "no occurrences".

IEEE-754 specials (harmonized, unlike NULL)
-------------------------------------------
DuckDB gives ``DOUBLE`` a **total** order: ``NaN`` equals itself and sorts
*greater than everything*, ``inf`` included. Python's comparisons are the IEEE
ones, where every comparison involving ``NaN`` is false. Left alone, the same
``Expr`` would select different packets per backend, so this backend compiles the
Python semantics — the predicate backend is the reference:

- **A NaN literal compiles to the constant ``FALSE``**, binding no parameter.
  ``x == nan``, ``x > nan`` and friends are all false in Python, so the compiled
  predicate is simply the constant it already equals. This covers every place a
  float literal can appear: :class:`~remora.expr.Comparison` values,
  :class:`~remora.expr.Membership` scalar elements (a NaN element contributes a
  ``FALSE`` term to the ``OR``) and :class:`~remora.expr.ValueRange` endpoints —
  checked *before* the inverted-range test, since ``hi < lo`` is false for a NaN
  endpoint and would otherwise wave it through. Because ``!=`` is
  ``Not(Comparison(EQ, ...))``, ``x != nan`` renders ``NOT (FALSE)`` and selects
  every row, absent ones included — exactly the predicate backend's ``not False``.
- **A stored NaN is excluded from ``>`` and ``>=``** by a ``NOT isnan(...)``
  guard on float columns: scalar ``("col" > ? AND NOT isnan("col"))``, multi
  ``x -> x > ? AND NOT isnan(x)``. Which ftypes those are is read from #26's
  :data:`remora.workspace.types.COLUMN_TYPES` — every ftype whose column is
  ``DOUBLE`` — rather than from the Python type
  :mod:`remora.values` parses into, because ``isnan()`` runs on the column.
  Without it, NaN sorting greatest makes
  ``"col" > ?`` true for a stored NaN against *any* literal, where Python's
  ``nan > 0.5`` is false.
- **``<``, ``<=``, ``BETWEEN`` and ``=`` need no guard, deliberately.** NaN
  sorting greatest already makes ``NaN < v`` and ``NaN <= v`` false, ``BETWEEN``
  false through its ``<= hi`` conjunct, and ``NaN = v`` false for every non-NaN
  literal (a NaN literal never reaches SQL — it became ``FALSE`` above). Adding
  the guard there would be dead weight, so do not "complete" the set.
- ``inf`` needs nothing: both engines order it identically, above every finite
  value and below ``NaN`` only in DuckDB, which no rule above depends on.

The guard is ``NOT isnan(col)``, which is ``NULL`` on a ``NULL`` column value —
so an absent scalar stays excluded under a guarded comparison, the same as under
an unguarded one. The NULL behavior above is unchanged by this section.

Regex portability (the portable-text guard, issue #36)
------------------------------------------------------
``matches`` runs on three engines. :class:`remora.expr.Matches` already limits a
pattern to the Python-re/PCRE2 intersection, and :mod:`remora.compile.re2` names
what remains: the constructs DuckDB's RE2 cannot compile at all (lookarounds,
repeats above 1000) *and* a non-ASCII pattern character, which RE2 compiles but
does not agree about. Both raise :class:`UnsupportedSqlExprError` here.

What no construct check can catch is that RE2 matches UTF-8 *runes* and folds
case by Unicode, while Wireshark's PCRE2 (``PCRE2_CASELESS``, no UTF/UCP) and
the predicate backend (Python ``re`` over UTF-8 bytes) match bytes and fold
ASCII -- that RE2's ``$`` matches end-of-text only, where the other two also
match before a single trailing newline -- and that the engines do not agree on
what the Perl *classes* contain: RE2's ``\s`` is ``[\t\n\f\r ]``, while
Python ``re`` and PCRE2 also count U+000B VERTICAL TAB. ``'café' matches
'^.{5}$'`` is true on two engines and false on the third, and ``'a\x0bb'
matches 'a\sb'`` is true on two and false on the third; the difference is in
the *value*, not the pattern.

**Both sides need closing, because the fold relation runs both ways.** The
pattern side belongs to :mod:`remora.compile.re2` and is why a pattern must be
pure ASCII: RE2 folds U+212A KELVIN SIGN onto ``k`` and U+017F LATIN SMALL
LETTER LONG S onto ``s``,
so a non-ASCII *pattern* selects ASCII *values* the other two engines reject,
which no value-side test can see.

The value side is this module's guard. Every remaining difference needs a
non-ASCII byte, a newline or a vertical tab in the value, so the compiled
predicate refuses those: ``strlen(v) <> length(v)`` (byte count differs from
character count, i.e. not pure ASCII) or a ``chr(10)`` or ``chr(11)`` anywhere
raises DuckDB ``error()`` naming the column and pointing at the pcap path. It
refuses a *superset*, deliberately — a value carrying one of those characters is
refused even under a pattern that could not observe the difference (``'a\x0bb'
matches 'x'``) — because the guard tests the value alone, and a cheap
value-shaped test that never lets a divergence through beats a pattern-aware one
that might. With **both** halves in place the three engines are provably
identical on what survives: pattern and value are ASCII, an ASCII byte never
occurs inside a multi-byte UTF-8 sequence, so ``.``, ``[^...]`` and counted
quantifiers consume one byte = one rune; no character on either side has a
simple-fold orbit leaving ASCII, so Unicode folding degenerates to ASCII folding;
no newline means ``$`` cannot differ; and no vertical tab means the one
Perl-class definition the engines disagree about (``\s``/``\S``) cannot differ
either.

Two residuals, stated rather than implied: the guard is a property of the
*column's data*, not of the answer, so a query can fail on a row another conjunct
would have excluded; and whether that row is examined at all can depend on
zone-map skipping from other pushed-down filters. Making it deterministic would
need a precondition scan in :class:`remora.workspace.Query`, which is future work.

Error policy
------------
:class:`UnsupportedSqlExprError` means "this backend legitimately cannot render
the expression" — an unknown ``Expr`` node, a ``Matches`` *pattern* DuckDB's RE2
engine cannot run *or* cannot agree about (what
:func:`remora.compile.re2.unportable_reason` names: lookarounds, repeats above
1000, and any non-ASCII character — ``Matches`` itself is no longer refused
categorically), and ``Contains`` on a ``BLOB`` column: on a bytes field
``contains`` means a byte *subsequence*, and DuckDB has no subsequence match
over ``BLOB`` — its ``contains()`` is substring on ``VARCHAR`` and element
membership on ``LIST``, so a multi-value ``BLOB[]`` column would even be
*accepted*, with the wrong meaning. The refusal names the column type the query
would have run against (``BLOB[]``, not ``BLOB``, for such a column), which is
why it passes ``field.multi`` to :func:`column_sql_type`. User errors
— a malformed literal such as ``IP.src == "not-an-ip"``, a ``contains`` needle
whose type does not match the field, or ``matches`` on a non-string field —
surface as the ``ValueError``/``TypeError`` the sibling backends raise and are
deliberately not converted.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

from remora import values
from remora.compile.re2 import unportable_reason
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
from remora.workspace.types import COLUMN_TYPES, column_sql_type, get_column_type

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

#: SQL constant a NaN literal compiles to (a comparison with NaN is false in
#: Python, so the predicate *is* this constant). Self-delimiting like every leaf.
_FALSE: Final[str] = "FALSE"

#: The one column type ``isnan()`` applies to, as #26 spells it.
_DOUBLE_SQL_TYPE: Final[str] = "DOUBLE"

#: FTypes whose column holds a float and can therefore hold a NaN. Derived from
#: the *column* table rather than listed, so a float ftype added to
#: :mod:`remora.values` cannot silently escape the NaN rules — and derived from
#: the SQL type rather than from the Python type because ``isnan()`` is a claim
#: about the column: it runs on a ``DOUBLE`` column, whatever
#: :mod:`remora.values` parses that column's text into.
_FLOAT_FTYPES: Final[frozenset[str]] = frozenset(
    ftype for ftype, column in COLUMN_TYPES.items() if column.sql_type == _DOUBLE_SQL_TYPE
)

#: Operators whose DuckDB result on a *stored* NaN disagrees with Python, because
#: NaN sorts greatest. ``<``/``<=``/``BETWEEN``/``=`` already agree — see the
#: module docstring's IEEE-754 section before adding to this set.
_NAN_GUARDED_OPS: Final[frozenset[CompareOp]] = frozenset({CompareOp.GT, CompareOp.GE})


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


def _render(expr: Expr, params: list[Any], *, negated: bool = False) -> str:
    """Render one node, appending its parameters to ``params`` in order.

    Args:
        expr: The node to render.
        params: Accumulator the node's bound values are appended to, in
            placeholder order.
        negated: True when at least one enclosing ``Not`` will invert this
            node's value; NULL-able leaves are then made two-valued with
            ``coalesce(..., FALSE)`` so SQL's Kleene logic collapses onto the
            predicate backend's booleans (see the module docstring's NULL
            section).

    Returns:
        The SQL text for this node, self-delimiting.

    Raises:
        UnsupportedSqlExprError: If the node's type is one this backend refuses,
            or a leaf renderer refuses its own contents (an unrunnable
            ``matches`` pattern, ``contains`` on a BLOB column).
        ValueError: If a leaf's literal is malformed for the field's ftype, or a
            membership range is inverted.
        TypeError: If a leaf's literal has the wrong type for the field's ftype
            (``matches`` on a non-string field included).
    """
    if isinstance(expr, Comparison):
        return _render_comparison(expr, params, negated=negated)
    if isinstance(expr, Presence):
        # Presence never yields NULL, so it needs no coalesce even under a Not.
        column = _column(expr.field)
        return f"len(coalesce({column}, [])) > 0" if expr.field.multi else f"{column} IS NOT NULL"
    if isinstance(expr, Membership):
        return _render_membership(expr, params, negated=negated)
    if isinstance(expr, Contains):
        return _render_contains(expr, params, negated=negated)
    if isinstance(expr, Matches):
        return _render_matches(expr, params, negated=negated)
    if isinstance(expr, Not):
        return f"NOT ({_render(expr.operand, params, negated=True)})"
    if isinstance(expr, And):
        left = _render(expr.left, params, negated=negated)
        right = _render(expr.right, params, negated=negated)
        return f"({left} AND {right})"
    if isinstance(expr, Or):
        left = _render(expr.left, params, negated=negated)
        right = _render(expr.right, params, negated=negated)
        return f"({left} OR {right})"
    raise UnsupportedSqlExprError(
        f"sql backend cannot render Expr node of type {type(expr).__name__}"
    )


def _render_comparison(expr: Comparison, params: list[Any], *, negated: bool) -> str:
    """Render ``field <op> literal`` against a scalar or a LIST column."""
    field = expr.field
    coerced = _coerce(field.ftype, expr.value)
    if _is_nan(coerced):
        # A constant, never NULL, so it is never coalesced.
        return _FALSE
    column = _column(field)
    placeholder = _placeholder(field.ftype)
    params.append(_encode_coerced(field.ftype, coerced))
    guard = _needs_nan_guard(field.ftype, expr.op)
    if not field.multi:
        condition = f"{column} {_SQL_OPS[expr.op]} {placeholder}"
        if guard:
            # Now a compound, so it parenthesizes itself like And/Or do.
            condition = f"({condition} AND NOT isnan({column}))"
        return _null_safe(condition, negated)
    if expr.op is CompareOp.EQ:
        return _null_safe(f"list_contains({column}, {placeholder})", negated)
    condition = f"{_LAMBDA_VAR} {_SQL_OPS[expr.op]} {placeholder}"
    if guard:
        condition = f"{condition} AND NOT isnan({_LAMBDA_VAR})"
    return _null_safe(_any_occurrence(column, condition), negated)


def _render_membership(expr: Membership, params: list[Any], *, negated: bool) -> str:
    """Render ``field in {...}`` as the OR of one term per set element.

    The assembled ``OR`` is coalesced once rather than term by term: every term
    reads the same column, so they are all NULL together and one wrap is
    equivalent to wrapping each.
    """
    column = _column(expr.field)
    terms = [_render_member(expr.field, column, item, params) for item in expr.values]
    assembled = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
    return _null_safe(assembled, negated)


def _render_member(field: FieldLike, column: str, item: MembershipItem, params: list[Any]) -> str:
    """Render one membership element: an equality, or an inclusive range.

    A range over an address column is exactly the subnet predicate: ``BETWEEN``
    over the integer form, which DuckDB's zone maps can skip row groups on.
    """
    ftype = field.ftype
    placeholder = _placeholder(ftype)
    if isinstance(item, ValueRange):
        lo: Any = _coerce(ftype, item.lo)
        hi: Any = _coerce(ftype, item.hi)
        # Before the inversion check, not after: every comparison with NaN is
        # false, so `hi < lo` would wave a NaN endpoint straight through.
        if _is_nan(lo) or _is_nan(hi):
            return _FALSE
        if hi < lo:
            raise ValueError(f"inverted membership range: {item.lo!r}..{item.hi!r}")
        params.append(_encode_coerced(ftype, lo))
        params.append(_encode_coerced(ftype, hi))
        between = f"BETWEEN {placeholder} AND {placeholder}"
        if field.multi:
            return _any_occurrence(column, f"{_LAMBDA_VAR} {between}")
        return f"{column} {between}"
    coerced = _coerce(ftype, item)
    if _is_nan(coerced):
        return _FALSE
    params.append(_encode_coerced(ftype, coerced))
    if field.multi:
        return f"list_contains({column}, {placeholder})"
    return f"{column} = {placeholder}"


def _render_contains(expr: Contains, params: list[Any], *, negated: bool) -> str:
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
            f"{column_sql_type(field.ftype, field.multi)} and DuckDB has no "
            "subsequence match over BLOB — its contains() is substring on VARCHAR "
            "and element membership on LIST, neither of which is the byte "
            "subsequence contains means on a bytes field; run this filter on the "
            "pcap path (remora.Capture) instead."
        )
    column = _column(field)
    params.append(needle)
    if field.multi:
        return _null_safe(_any_occurrence(column, f"contains({_LAMBDA_VAR}, ?)"), negated)
    return _null_safe(f"contains({column}, ?)", negated)


def _render_matches(expr: Matches, params: list[Any], *, negated: bool) -> str:
    """Render ``field matches pattern`` as guarded RE2, on VARCHAR columns only.

    Args:
        expr: The ``Matches`` node to render.
        params: Accumulator the pattern is appended to, in placeholder order.
        negated: True when an enclosing ``Not`` will invert this leaf.

    Returns:
        The guarded regex test, wrapped in ``coalesce(..., FALSE)`` when negated.

    Raises:
        UnsupportedSqlExprError: If DuckDB's RE2 engine cannot compile the
            pattern (see :func:`remora.compile.re2.unportable_reason`).
        TypeError: If the field is not a string field.
    """
    field = expr.field
    if values.get_info(field.ftype).py_type is not str:
        raise TypeError(f"matches is only supported on string fields, not {field.ftype}")
    reason = unportable_reason(expr.pattern)
    if reason is not None:
        raise UnsupportedSqlExprError(
            f"matches pattern {expr.pattern!r} is not compiled to SQL: {reason}. "
            "Wireshark's PCRE2 and the Python predicate backend both accept it, "
            "so run this filter on the pcap path (remora.Capture) instead."
        )
    column = _column(field)
    params.append(expr.pattern)
    if field.multi:
        return _null_safe(_any_occurrence(column, _guarded_match(_LAMBDA_VAR, column)), negated)
    return _null_safe(_guarded_match(column, column), negated)


def _guarded_match(subject: str, column: str) -> str:
    """A regex test over ``subject``, refusing text the three engines disagree on.

    Args:
        subject: The value being matched — the column for a scalar field, and
            the ``list_filter`` lambda variable for a multi-value one.
        column: The quoted column name, used only to name the column in the
            error message.

    Returns:
        A ``CASE`` expression raising DuckDB ``error()`` on unportable text and
        running ``regexp_matches`` otherwise. See the module docstring's
        portable-text section.
    """
    message = _sql_text_literal(
        f"remora: matches on {column} needs pure-ASCII text free of newline "
        "(chr(10)) and vertical tab (chr(11)) — DuckDB RE2 and Wireshark PCRE2 "
        "disagree on anything else; run this filter on the pcap path "
        "(remora.Capture)"
    )
    return (
        f"CASE WHEN strlen({subject}) <> length({subject}) "
        f"OR contains({subject}, chr(10)) OR contains({subject}, chr(11)) "
        f"THEN error({message}) "
        f"ELSE regexp_matches({subject}, ?, 'i') END"
    )


def _sql_text_literal(text: str) -> str:
    """Single-quote compiler-chosen text for SQL. Never used for user literals.

    Args:
        text: Text the compiler itself chose — an error message, never anything
            a caller supplied.

    Returns:
        The text as a single-quoted SQL literal, with embedded quotes doubled.
    """
    escaped = text.replace("'", "''")
    return f"'{escaped}'"


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


def _coerce(ftype: str, value: LiteralValue) -> Any:
    """Normalize a user literal for a field's ftype — the first half of the seam.

    Paired with :func:`_encode_coerced`, which every literal then passes
    through. The two are separate because the value *between* them is needed on
    its own: a range's inversion check and the NaN test both read the coerced
    value, and coercing a second time to encode would run
    :func:`remora.values.coerce_literal` twice and leave a second call site for
    a future change to miss.

    Args:
        ftype: tshark ftype of the field the literal is compared against.
        value: The literal as the caller wrote it.

    Returns:
        The literal as its ftype's Python type.

    Raises:
        ValueError: If the literal is malformed for the ftype.
        TypeError: If the literal's type is wrong for the ftype.
    """
    return values.coerce_literal(ftype, value)


def _encode_coerced(ftype: str, coerced: Any) -> Any:
    """Encode an already-coerced literal the way the column stores it.

    The second half of the seam :func:`_coerce` opens. The encoder is the same
    one the materialize path writes the column with, so a bound value and a
    stored value can never disagree.

    Args:
        ftype: tshark ftype of the field the literal is compared against.
        coerced: The literal, already through :func:`_coerce`.

    Returns:
        The value to bind, in the column's stored representation.
    """
    return get_column_type(ftype).encode(coerced)


def _is_nan(value: Any) -> bool:
    """Is this coerced literal a float NaN, which no Python comparison matches?"""
    return isinstance(value, float) and math.isnan(value)


def _needs_nan_guard(ftype: str, op: CompareOp) -> bool:
    """Does ``op`` on this column need ``NOT isnan(...)`` to match Python?

    Only ``>``/``>=`` on a float column: DuckDB sorts NaN greatest, so those two
    are true for a stored NaN where Python's are false. See the module
    docstring's IEEE-754 section for why the other operators need nothing.
    """
    return ftype in _FLOAT_FTYPES and op in _NAN_GUARDED_OPS


def _any_occurrence(column: str, condition: str) -> str:
    """Wrap a per-element condition as an any-occurrence test over a LIST column."""
    return f"len(list_filter({column}, {_LAMBDA_VAR} -> {condition})) > 0"


def _null_safe(sql: str, negated: bool) -> str:
    """Make a NULL-able leaf two-valued when a ``Not`` will invert it.

    Applied at the *leaf*, never at a subtree: ``NOT (NOT (x))`` with a NULL x
    must be FALSE, and coalescing the inner ``NOT`` would make it TRUE. Applied
    only under a ``Not``, because ``coalesce`` blocks DuckDB's scan-level filter
    pushdown and a positive predicate has no NULL divergence to fix.

    Args:
        sql: The rendered leaf, self-delimiting.
        negated: True when an enclosing ``Not`` will invert it.

    Returns:
        The leaf, wrapped in ``coalesce(..., FALSE)`` only when ``negated``.
    """
    return f"coalesce({sql}, FALSE)" if negated else sql
