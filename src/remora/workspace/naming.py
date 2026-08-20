"""Field abbrev -> SQL column name, the frozen workspace naming policy.

Policy
------
1. The **full** abbrev is used — no parent stripping. Unlike Python attribute
   names (:mod:`remora.codegen.mangle`, where ``tcp.port`` lives on ``TCP`` and
   may safely be ``port``), columns share one flat namespace inside ``pkts``,
   so ``tcp.port`` and ``udp.port`` must stay distinct.
2. The name is lowercased. DuckDB identifiers compare case-insensitively, so
   ``ip.Src`` and ``ip.src`` name the *same* column; lowercasing surfaces such
   pairs as collisions instead of letting one silently overwrite the other.
3. Every character that is not ASCII alphanumeric becomes ``_``.
4. A leading digit gets an ``f_`` prefix so the name is legal unquoted.

Generated SQL always quotes identifiers, so SQL reserved words need no special
casing here.

Collisions
----------
Like the attribute policy, this mapping is **not injective**: ``tcp.port`` and
``tcp_port`` both yield ``tcp_port``. :func:`find_collisions` reports every
column claimed by more than one abbrev; callers materializing a field set must
check and refuse rather than silently drop a field.

This module is the single definition of the policy: issue #26 (FType -> column
types) imports it instead of restating it, so the schema layer and the type
layer cannot disagree about column names.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

__all__ = ["SKELETON_ABBREVS", "SKELETON_COLUMNS", "column_name", "find_collisions"]


def column_name(abbrev: str) -> str:
    """Map a tshark field abbrev to a workspace column name (see module docs).

    Args:
        abbrev: Full tshark field abbrev, e.g. ``"tcp.port"``.

    Returns:
        The column name, e.g. ``"tcp_port"``.

    Raises:
        ValueError: If ``abbrev`` is empty.
    """
    if not abbrev:
        raise ValueError("cannot derive a column name from an empty field abbrev")
    name = "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in abbrev).lower()
    if name[0].isdigit():
        name = "f_" + name
    return name


SKELETON_COLUMNS: Final[frozenset[str]] = frozenset({"frame_number", "frame_time"})
"""Columns ``pkts`` is created with — the row key, reserved from materializing.

These are the ``frame.number`` / ``frame.time`` columns of the ``pkts``
skeleton, already present in every workspace, so a field set asking for them
needs no column added. :func:`find_collisions` will not flag them (they collide
with nothing), which is why the reservation is stated here rather than left for
``ALTER TABLE`` to discover.
"""


SKELETON_ABBREVS: Final[frozenset[str]] = frozenset({"frame.number", "frame.time"})
"""Field abbrevs whose data the ``pkts`` row key already holds.

The abbrev side of :data:`SKELETON_COLUMNS`. Materializing one of these adds no
column (#31 drops them from the projection), and querying one needs no
``meta.fields`` entry (#35 treats them as always available), so both layers read
the set from here rather than restating it.
"""


def find_collisions(abbrevs: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Group abbrevs that share a column name.

    Args:
        abbrevs: Field abbrevs to check. Duplicates of one abbrev are not a
            collision — only *distinct* abbrevs mapping to one column are.

    Returns:
        Mapping of column name to the sorted distinct abbrevs claiming it,
        containing only columns claimed more than once. Empty when the field
        set is safe to materialize.
    """
    claimed: dict[str, set[str]] = {}
    for abbrev in abbrevs:
        claimed.setdefault(column_name(abbrev), set()).add(abbrev)
    return {column: tuple(sorted(owners)) for column, owners in claimed.items() if len(owners) > 1}
