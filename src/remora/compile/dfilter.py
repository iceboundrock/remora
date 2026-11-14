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
- ``Membership(field, values)`` -> ``field in {v1, v2, lo .. hi}``. Elements
  are comma-separated (whitespace-only separators became a syntax error in
  Wireshark 4.0); range elements render spaced ``lo .. hi`` so IPv4 endpoints
  like ``10.0.0.5 .. 10.0.0.9`` cannot lex as a malformed dotted quad.
- ``Contains(field, needle)`` -> ``field contains "text"`` (string fields) or
  ``field contains aa:bb`` (bytes fields). The needle's type must match the
  field's Python type; a mismatch is a user error (TypeError), not
  UnsupportedExprError.
- ``Matches(field, pattern)`` -> ``field matches "pattern"``, string fields
  only. Wireshark's ``matches`` is case-insensitive by default; the predicate
  backend mirrors that with ``re.IGNORECASE``. Patterns are restricted at
  construction to the Python-re/PCRE2 common subset (see
  :class:`remora.expr.Matches`), so pushing one down cannot change its meaning.

Literal rendering
-----------------
Literals are first normalized with :func:`remora.values.coerce_literal` (so
``IP.src == "10.0.0.1"`` compares an :class:`~ipaddress.IPv4Address`, and
garbage like ``"not-an-ip"`` is rejected), then rendered by the resulting
Python type: bools as ``1``/``0``, ints as decimal, floats via ``repr`` —
except NaN, which is refused (see below) — strings double-quoted with
backslash escapes, IP addresses and UUIDs bare (a quoted GUID is a dfilter
error: ``Globally Unique Identifier cannot be converted from a string``),
bytes as colon-hex (``aa:bb:cc``), which is also the only EUI-64 spelling
Wireshark reads as one: on 4.6.9, ``dns.eui64 == 0211223344556677`` is accepted
and matches nothing.

GUIDs and EUI-64s (issue #69)
-----------------------------
Two shapes on these ftypes are refused with :class:`UnsupportedExprError`, so
the planner evaluates them in Python. Each is a case where tshark's answer
depends on its version, measured on 4.2.2 (Ubuntu 24.04, CI's ``checks`` leg)
and 4.6.9:

- **Ordered comparisons and ranges on ``FT_GUID``.** 4.6.9 orders GUIDs by
  their printed text, as :class:`uuid.UUID` and DuckDB's ``UUID`` do. 4.2.2
  orders them by the in-memory struct, whose first three groups are
  host-endian, so ``dhcp.client_id.uuid > 00000034-0000-0000-0000-000000000000``
  is true for ``33221100-...`` on 4.6.9 and false on 4.2.2. ``==`` and
  ``in {a, b}`` agree on both and are pushed down.
- **``contains`` on ``FT_EUI64``.** 4.6.9 runs it as a byte subsequence, as the
  predicate backend does; 4.2.2 rejects the filter outright (``cannot
  participate in contains comparison``), which would fail the whole query.
  Ordered comparisons and ranges on ``FT_EUI64`` agree on both versions with
  ``bytes`` order and are pushed down.

Object identifiers (issue #149)
-------------------------------
Every value test on ``FT_OID`` (``==``, ``!=``, ordered comparisons,
membership, ``contains``, ``matches``) is refused with
:class:`UnsupportedExprError`; only presence is pushed down. ``FT_OID`` is
``str`` (:mod:`remora.values`), so the generic string rendering would quote
the literal, and tshark rejects a quoted OID: ``ASN.1 object identifier cannot
be converted from a string`` on 4.2.2, 4.4.19 and 4.6.9 alike. Before this
refusal, any value filter on an OID field failed the whole capture. ``matches``
is rejected on every build, and ``contains`` accepts neither a string nor a
byte needle. The bare dotted form (``snmp.name == 1.3.6.1.2.1.1.2.0``) is
accepted, but not pushed either, for three reasons:

- tshark compares the BER-encoded bytes, while the Python and SQL backends
  compare the text tshark prints. The two agree only for well-formed
  encodings. A truncated arc (``2b 06 81``) prints ``1.3.6`` but is not
  ``== 1.3.6`` on ``-Y``, and it sorts above ``1.3.6.1.2.1.1.9`` there.
- The orders differ even for well-formed values. tshark orders the content
  octets byte by byte, which a string's order does not follow
  (``1.3.6.1.2.1.1.9 < 1.3.6.1.2.1.1.10`` there) and numeric arc order does
  not follow either: ``ff 7f`` (``1.3.6.16383``) sorts above ``81 80 00``
  (``1.3.6.16384``).
- Two-arc literals lex differently by version: ``snmp.name == 1.3`` is an OID
  on 4.2.2 and a rejected ``Double`` on 4.4.19 and 4.6.9.

So these filters run as Python predicates over the printed text, which is the
same text the workspace stores and SQL compares. The measurements are in
``docs/semantics.md``.

Time literals (M1 design decision)
----------------------------------
``datetime``/``timedelta`` comparisons raise :class:`UnsupportedExprError`:
absolute/relative-time comparisons are not pushed down to the display filter
in M1; the planner keeps them as residual Python predicates.

IEEE-754 specials (issue #90)
-----------------------------
A float **NaN** literal raises :class:`UnsupportedExprError`; ``inf`` and
``-inf`` render normally.

Python's comparisons with NaN are all false, so ``x > nan`` selects nothing and
``x != nan`` — which is ``Not(Comparison(EQ, ...))`` — selects everything. That
is what :mod:`remora.compile.predicate` implements, and Wireshark's engine does
not agree. What it does instead is both ftype- and version-dependent (measured
on tshark 4.6.8): on a float field, ordered comparisons are rejected outright
(``NaN cannot be used in ordered comparisons``) while ``==`` and ``in {nan}``
are accepted; on a relative-time field, ``nan`` parses as a time offset ordered
*below every value*, so ``frame.time_delta > nan`` silently selects every frame
carrying the field where Python selects none. ``nan`` is genuinely lexed as a
literal rather than misparsed — ``nam``, ``nan5`` and ``zzz`` all fail hard —
so rendering it is not self-protecting.

Refusal is the whole fix, and it costs nothing but pushdown: the planner
catches :class:`UnsupportedExprError` and evaluates the conjunct as a Python
predicate, which already has the correct never-matches semantics. Rendering
some dfilter-native never-matches form instead was considered and rejected as a
version-fragile hack, for a predicate that selects nothing anyway.

This is deliberately **asymmetric with the SQL backend**, which compiles a NaN
literal to the constant ``FALSE`` rather than refusing: SQL *has* a boolean
constant to compile to, and DuckDB gives ``DOUBLE`` a total order that has to
be actively neutralized because a workspace query has no fallback engine to
defer to. A display filter has neither the constant nor the need — the fallback
exists and is already correct — so refusal is the cheaper and safer
equivalent. Both backends reach the same observable row set.

``inf``/``-inf`` need nothing, exactly as in the SQL backend: Wireshark orders
them the way Python does (``< inf`` selects every frame carrying the field,
``> inf`` none, ``> -inf`` every one, ``< -inf`` none), so they are pushed down
unchanged. Do not sweep them into the NaN rule.

Error policy
------------
:class:`UnsupportedExprError` means "this backend legitimately cannot render
the expression; the planner should fall back to the Python predicate backend"
(time literals, float NaN literals, empty bytes, ordered GUID comparisons,
``contains`` on an EUI-64, value tests on an OID, unknown future Expr nodes).
User errors — malformed literals such as ``IP.src == "not-an-ip"`` — surface as
the ``ValueError``/``TypeError`` that :func:`remora.values.coerce_literal`
raises and are deliberately *not* converted into :class:`UnsupportedExprError`.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from remora import values
from remora.expr import (
    And,
    CompareOp,
    Comparison,
    Contains,
    Expr,
    Matches,
    Membership,
    MembershipItem,
    Not,
    Or,
    Presence,
    ValueRange,
)

__all__ = ["UnsupportedExprError", "compile_dfilter"]


class UnsupportedExprError(Exception):
    """Expr shape the dfilter backend cannot render.

    The planner catches this and routes the conjunct to the Python predicate
    backend instead.
    """


def compile_dfilter(expr: Expr) -> str:
    """Render ``expr`` as a Wireshark display-filter string.

    Raises :class:`UnsupportedExprError` when the expression cannot be
    expressed as a display filter (see module docstring for the error policy).
    """
    if isinstance(expr, Comparison):
        coerced = values.coerce_literal(expr.field.ftype, expr.value)
        if expr.op is not CompareOp.EQ:
            _refuse_unstable_order(expr.field.ftype)
        rendered = _render_literal(coerced)
        _refuse_value_test(expr.field.ftype)
        return f"{expr.field.name} {expr.op.value} {rendered}"
    if isinstance(expr, Presence):
        return expr.field.name
    if isinstance(expr, Membership):
        rendered = ", ".join(_render_set_item(expr.field.ftype, item) for item in expr.values)
        _refuse_value_test(expr.field.ftype)
        return f"{expr.field.name} in {{{rendered}}}"
    if isinstance(expr, Contains):
        needle = _render_needle(expr.field.ftype, expr.needle)
        _refuse_value_test(expr.field.ftype)
        return f"{expr.field.name} contains {needle}"
    if isinstance(expr, Matches):
        if values.get_info(expr.field.ftype).py_type is not str:
            raise TypeError(f"matches is only supported on string fields, not {expr.field.ftype}")
        _refuse_value_test(expr.field.ftype)
        return f"{expr.field.name} matches {_render_str(expr.pattern)}"
    if isinstance(expr, Not):
        return f"!({compile_dfilter(expr.operand)})"
    if isinstance(expr, And):
        return f"({compile_dfilter(expr.left)}) && ({compile_dfilter(expr.right)})"
    if isinstance(expr, Or):
        return f"({compile_dfilter(expr.left)}) || ({compile_dfilter(expr.right)})"
    raise UnsupportedExprError(
        f"dfilter backend cannot render Expr node of type {type(expr).__name__}"
    )


#: Refusal message for a float NaN literal, shared by the two places one can
#: reach the renderer (a plain literal, and a membership range endpoint).
_NAN_REFUSAL = (
    "NaN literals are not pushed down to display filters; Wireshark does not "
    "give them Python's never-matches semantics, so the planner evaluates them "
    "as Python predicates instead"
)


#: FTypes whose *order* tshark gives differently across versions, so ``<``,
#: ``<=``, ``>``, ``>=`` and membership ranges are refused (module docstring).
_UNSTABLE_ORDER_FTYPES = frozenset({"FT_GUID"})

#: FTypes on which some supported tshark rejects ``contains`` outright.
_NO_CONTAINS_FTYPES = frozenset({"FT_EUI64"})

#: FTypes whose ``py_type`` is not what tshark compares, so no value test is
#: pushed down, only presence (module docstring, "Object identifiers").
_NO_VALUE_TEST_FTYPES = frozenset({"FT_OID"})


def _refuse_value_test(ftype: str) -> None:
    """Refuse a value test on an ftype whose dfilter semantics Remora does not share.

    Called after the literal has been coerced and rendered, so a malformed
    literal or an inverted range is still the user error it is on every
    backend.
    """
    if ftype in _NO_VALUE_TEST_FTYPES:
        raise UnsupportedExprError(
            f"value tests on {ftype} are not pushed down to display filters: tshark "
            "rejects a quoted OID and compares the encoded bytes rather than the "
            "printed text, so the planner evaluates them as Python predicates"
        )


def _refuse_unstable_order(ftype: str) -> None:
    """Refuse an ordered comparison on an ftype tshark orders version-dependently."""
    if ftype in _UNSTABLE_ORDER_FTYPES:
        raise UnsupportedExprError(
            f"ordered comparisons on {ftype} are not pushed down to display filters: "
            "tshark 4.2 orders GUIDs by their host-endian struct where 4.6 orders "
            "their text, so the planner evaluates them as Python predicates"
        )


def _render_literal(value: object) -> str:
    """Render a *normalized* literal (output of ``coerce_literal``) as dfilter text."""
    # bool before int: bool subclasses int.
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # inf/-inf pass through: Wireshark orders them as Python does. NaN does
        # not — see the module docstring's IEEE-754 section.
        if math.isnan(value):
            raise UnsupportedExprError(_NAN_REFUSAL)
        return repr(value)
    if isinstance(value, str):
        return _render_str(value)
    if isinstance(value, IPv4Address | IPv6Address | UUID):
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


#: C-style two-character escapes understood by the display-filter string syntax.
_NAMED_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\a": "\\a",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\v": "\\v",
}


def _render_set_item(ftype: str, item: MembershipItem) -> str:
    """Render one membership element.

    Ranges render spaced (``lo .. hi``) so IPv4 endpoints cannot mis-lex around
    the dots.
    """
    if isinstance(item, ValueRange):
        lo: Any = values.coerce_literal(ftype, item.lo)
        hi: Any = values.coerce_literal(ftype, item.hi)
        # Before the inversion check, not after: every comparison with NaN is
        # false, so `hi < lo` can never fire on a NaN endpoint. Refusing here
        # keeps the NaN policy a property of this renderer rather than an
        # accident of which endpoint _render_literal happens to reach first.
        if _is_nan(lo) or _is_nan(hi):
            raise UnsupportedExprError(_NAN_REFUSAL)
        if hi < lo:
            raise ValueError(f"inverted membership range: {item.lo!r}..{item.hi!r}")
        _refuse_unstable_order(ftype)
        return f"{_render_literal(lo)} .. {_render_literal(hi)}"
    return _render_literal(values.coerce_literal(ftype, item))


def _is_nan(value: object) -> bool:
    """Is this coerced literal a float NaN, which no Python comparison matches?

    Guarded on ``float`` so ``math.isnan`` never sees an address or a string;
    ``bool`` cannot reach here as a float, so no bool-before-int dance is
    needed (that ordering lives in :func:`_render_literal`).
    """
    return isinstance(value, float) and math.isnan(value)


def _render_needle(ftype: str, needle: str | bytes) -> str:
    """Render a contains needle.

    Its type must match the field's Python type (str fields take str, bytes
    fields take bytes) — anything else is a user error (TypeError), mirrored
    exactly by the predicate backend.
    """
    py_type = values.get_info(ftype).py_type
    if py_type is str and isinstance(needle, str):
        return _render_str(needle)
    if py_type is bytes and isinstance(needle, bytes):
        if ftype in _NO_CONTAINS_FTYPES:
            raise UnsupportedExprError(
                f"contains on {ftype} is not pushed down to display filters: tshark "
                "4.2 rejects it, so the planner evaluates it as a Python predicate"
            )
        return ":".join(f"{byte:02x}" for byte in needle)
    raise TypeError(
        "contains needs a str needle on string fields and a bytes needle on "
        f"bytes fields; got {type(needle).__name__} for {ftype}"
    )


def _render_str(value: str) -> str:
    r"""Double-quote a string literal, escaping quotes, backslashes, and control characters.

    Named C escapes are used where Wireshark defines them, ``\xHH`` for the
    rest of C0 and DEL. Other characters — including non-ASCII — pass through
    as UTF-8.
    """
    out: list[str] = []
    for ch in value:
        escape = _NAMED_ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return '"{}"'.format("".join(out))
