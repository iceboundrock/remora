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

What RE2 refuses, measured against duckdb 1.5.5:

- **Lookarounds** ``(?=`` ``(?!`` ``(?<=`` ``(?<!`` -> "invalid perl operator".
  ``(?:`` is fine; it is the only other group prefix the ``Expr`` subset allows.
- **Brace repeats above 1000** -> "invalid repetition size". The limit applies
  to each bounded count *and* to the product of bounded counts along a nesting
  path: ``(?:a{31}){31}`` (961) compiles, ``(?:a{32}){32}`` (1024) does not, and
  ``(?:a{500}){3}`` (1500) does not. For ``{m,}`` (unbounded max), RE2 uses ``m``
  as the factor; only ``*`` and ``+`` (min ≤ 1) contribute factor 1, and ``{0}``
  or ``{0,}`` contribute factor 1.

Everything else the ``Expr`` subset admits -- literals, ``.``, anchors,
alternation, groups, character classes, the shared escapes, ``\xHH`` -- RE2
compiles. Whether it *means* the same thing is a separate question about the
data, not the pattern: see the portable-text guard in
:mod:`remora.compile.sql`.

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
        or ``None`` when RE2 can compile the pattern.
    """
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
