r"""RE2 portability rules for ``matches`` patterns (issue #36).

Three engines run one ``matches`` pattern: Wireshark's PCRE2 (display-filter
pushdown), Python ``re`` (the predicate backend) and Google RE2 (DuckDB's
``regexp_matches``, the workspace query path). :class:`remora.expr.Matches`
already restricts patterns at construction to the Python-re/PCRE2 intersection;
this module states the *further* restriction RE2 imposes, so
:mod:`remora.compile.sql` can refuse a pattern it cannot run instead of letting
DuckDB report a raw engine error from inside a query.

The rules are deliberately not applied at ``Expr`` construction: PCRE2 and
Python ``re`` both run lookarounds and large repeats identically, and a caller
who never opens a workspace should not lose them (see ``docs/semantics.md``,
"Regex support matrix").

One further rule is remora's, not RE2's: a **non-ASCII pattern is refused** even
though RE2 compiles it. RE2 folds case by Unicode in *both* directions, so a
pattern character whose simple-fold orbit reaches ASCII matches pure-ASCII text
that PCRE2 (``PCRE2_CASELESS``, no UTF/UCP) and Python ``re`` over UTF-8 bytes
would not: U+212A KELVIN SIGN folds onto ``k`` and U+017F LATIN SMALL LETTER
LONG S onto ``s``, so ``'kelvin' matches '\u212a'`` is true on RE2 and false on
the other two. The value-side guard in :mod:`remora.compile.sql` cannot
see this — the *value* is ASCII — so the pattern side is closed here, and the two
halves together are what make the three engines agree.

What RE2 refuses, measured against duckdb 1.5.5:

- **Lookarounds** ``(?=`` ``(?!`` ``(?<=`` ``(?<!`` -> "invalid perl operator".
  ``(?:`` is fine; it is the only other group prefix the ``Expr`` subset allows.
- **Brace repeats above 1000** -> "invalid repetition size". The limit applies
  to each bounded count *and* to the product of bounded counts along a nesting
  path: ``(?:a{31}){31}`` (961) compiles, ``(?:a{32}){32}`` (1024) does not, and
  ``(?:a{500}){3}`` (1500) does not. For ``{m,}`` (unbounded max), RE2 uses ``m``
  as the factor; only ``*`` and ``+`` (min ≤ 1) contribute factor 1, and ``{0}``
  or ``{0,}`` contribute factor 1.

Everything else the ``Expr`` subset admits -- ASCII literals, ``.``, anchors,
alternation, groups, character classes, the shared escapes, ``\xHH`` -- RE2
compiles. Whether a *value* means the same thing on all
three engines is the remaining question, and it is about the data rather than
the pattern: see the portable-text guard in :mod:`remora.compile.sql`.

This module is a leaf: stdlib only, nothing from ``remora``.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = ["LOOKAROUND_PREFIXES", "MAX_REPEAT", "unportable_reason"]

#: RE2's ceiling on a repeat's expanded size (``kMaxRepeat``).
MAX_REPEAT: Final[int] = 1000

#: Group prefixes RE2 has no operator for. ``?:`` is deliberately absent.
LOOKAROUND_PREFIXES: Final[tuple[str, ...]] = ("?=", "?!", "?<=", "?<!")

#: ``{m}`` / ``{m,}`` / ``{m,n}`` -- the brace forms the ``Expr`` subset admits.
_BRACE = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def _brace_bound(match: re.Match[str]) -> tuple[int, int]:
    """Return ``(declared_count, bounded_factor)`` for one brace quantifier.

    ``bounded_factor`` is the smallest bound RE2 accounts for in nesting products;
    ``{0}`` and ``{0,}`` contribute ``max(1, 0) = 1``, ``{m,}`` contributes ``m``.
    """
    low, high = match.group(1), match.group(2)
    m = int(low) if high in (None, "") else int(high)
    return max(int(low), m), max(1, m)


def unportable_reason(pattern: str) -> str | None:
    """Why DuckDB's RE2 engine cannot compile ``pattern``, or ``None``.

    Args:
        pattern: A ``matches`` pattern that already passed
            :class:`remora.expr.Matches` validation.

    Returns:
        A lowercase reason fragment naming the construct, its position and RE2,
        or ``None`` when RE2 can compile the pattern *and* agrees with the other
        two engines about what it means.
    """
    # RE2 compiles a non-ASCII pattern happily; the refusal is remora's, because
    # RE2's Unicode case folding reaches ASCII from outside it (U+212A -> "k").
    # See the module docstring: the value side is sql.py's portable-text guard.
    if not pattern.isascii():
        position = next(index for index, char in enumerate(pattern) if not char.isascii())
        char = pattern[position]
        return (
            f"non-ASCII character {char!r} (U+{ord(char):04X}) at position {position} — "
            "DuckDB's RE2 engine folds case by Unicode, so it can match ASCII text "
            "Wireshark's PCRE2 and Python re would not"
        )
    # Each stack frame collects the expanded repeat sizes seen at that group
    # level, so a quantifier on the closing ")" can multiply them.
    stack: list[list[int]] = [[]]
    index = 0
    length = len(pattern)
    in_class = False
    while index < length:
        char = pattern[index]
        if in_class:
            if char == "\\":
                index += 2
                continue
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_class = True
            index += 1
            # A leading "^" negates and a leading "]" is a literal member.
            if pattern[index : index + 1] == "^":
                index += 1
            if pattern[index : index + 1] == "]":
                index += 1
            continue
        if char == "(":
            for prefix in LOOKAROUND_PREFIXES:
                if pattern.startswith(prefix, index + 1):
                    return (
                        f"lookaround '({prefix}' at position {index} — DuckDB's RE2 "
                        "engine has no lookaround operators"
                    )
            stack.append([])
            index += 1
            continue
        if char == ")":
            inner = stack.pop() if len(stack) > 1 else []
            index += 1
            match = _BRACE.match(pattern, index)
            if match is not None:
                declared, bounded = _brace_bound(match)
                if declared > MAX_REPEAT:
                    return (
                        f"repeat count {declared} at position {index} exceeds RE2's "
                        f"limit of {MAX_REPEAT}"
                    )
                merged = [size * bounded for size in inner] + [bounded]
                index = match.end()
            else:
                merged = inner
                if pattern[index : index + 1] in {"*", "+", "?"}:
                    index += 1
            for size in merged:
                if size > MAX_REPEAT:
                    return (
                        f"nested repeat expands to {size} at position {index}, "
                        f"exceeding RE2's limit of {MAX_REPEAT}"
                    )
            stack[-1].extend(merged)
            continue
        if char == "{":
            match = _BRACE.match(pattern, index)
            if match is None:  # a literal "{" the Expr subset let through
                index += 1
                continue
            declared, bounded = _brace_bound(match)
            if declared > MAX_REPEAT:
                return (
                    f"repeat count {declared} at position {index} exceeds RE2's "
                    f"limit of {MAX_REPEAT}"
                )
            stack[-1].append(bounded)
            index = match.end()
            continue
        index += 1
    return None
