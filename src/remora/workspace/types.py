"""FType -> DuckDB column type and the codecs either side of storage.

:mod:`remora.values` owns one direction — raw tshark text to a Python value.
This module owns the other — that Python value to and from what DuckDB stores.
It covers exactly :data:`remora.values.FTYPE_TABLE`'s ftype universe, and
``tests/test_workspace_types.py`` holds the two in step.

The mapping is **frozen**: a workspace file written by one remora is read by
the next, so changing a column type is a storage-format change, not a tweak.

Type mapping
------------
========================  ===========  =========================  ==================
ftype                     DuckDB       Arrow (for #31)            Stored value
========================  ===========  =========================  ==================
FT_IPv4                   UINTEGER     uint32                     int(address)
FT_IPv6                   UHUGEINT     decimal128(38, 0)          int(address)
FT_ETHER, FT_BYTES        BLOB         binary                     bytes
FT_BOOLEAN                BOOLEAN      bool                       bool
FT_ABSOLUTE_TIME          TIMESTAMP    timestamp[us]              naive UTC datetime
FT_RELATIVE_TIME          INTERVAL     month_day_nano_interval    timedelta
FT_DOUBLE, FT_FLOAT       DOUBLE       double                     float
FT_UINT8, FT_CHAR         UTINYINT     uint8                      int
FT_UINT16                 USMALLINT    uint16                     int
FT_UINT24, FT_UINT32,     UINTEGER     uint32                     int
FT_FRAMENUM
FT_UINT40 .. FT_UINT64    UBIGINT      uint64                     int
FT_INT8                   TINYINT      int8                       int
FT_INT16                  SMALLINT     int16                      int
FT_INT24, FT_INT32        INTEGER      int32                      int
FT_INT40 .. FT_INT64      BIGINT       int64                      int
FT_STRING, FT_STRINGZ,    VARCHAR      string                     str
FT_NONE, FT_STRINGZPAD,
FT_UINT_STRING, FT_EUI64,
FT_OID, FT_GUID, FT_AX25
========================  ===========  =========================  ==================

A multi-value field's column is the scalar type's DuckDB ``LIST`` (``T[]``,
Arrow ``list<T>``) — see :func:`column_sql_type`.

The Arrow column is documentation for issue #31, which may build record
batches; this module deliberately imports neither duckdb nor pyarrow, so it
names SQL types as plain strings and encodes to plain Python values. One
warning for #31: DuckDB exports ``UHUGEINT`` through Arrow as
``decimal128(38, 0)``, and the export reads the value as **signed**. On duckdb
1.5.5 + pyarrow 25, every ``FT_IPv6`` address with the high bit set — anything
in ``8000::/1`` — comes back reinterpreted as its two's-complement negative:
``8000::`` as ``-170141183460469231731687303715884105728`` and
``ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`` as ``-1``.

The boundary is 2^127, not decimal128's 38-digit range:
``7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`` is 1.70e38, already past 10^38, and
round-trips exactly, while ``8000::`` — one larger — does not. So this is not a
top-of-the-range corner case. It is all of ``fe80::/10`` link-local and all of
``ff00::/8`` multicast, which appear in essentially every real capture: an
``ff02::1`` row silently arrives as a negative integer.

The hazard is the Arrow export path only. Stored and read back through DuckDB
itself the same values are exact (``tests/test_workspace_types.py`` pins the
full-width address), so ``UHUGEINT`` is the right column type; #31 must simply
not route ``FT_IPv6`` columns through an Arrow record batch until this is
confirmed fixed upstream.

Frozen decisions
----------------
**Addresses are integers, and integers keep their exact width.** IPs are stored
as their integer form so subnet matching is a ``BETWEEN`` over an ordered
column, which DuckDB's zone maps can skip row groups on (epic #43); a text
column would force a per-row parse. Narrow ftypes keep narrow column types for
the same reason — a blanket ``BIGINT`` would cost 8x the bytes on ``FT_UINT8``
and widen every zone map's range.

**FT_FLOAT is DOUBLE, not FLOAT.** :mod:`remora.values` parses ``FT_FLOAT``
with :func:`float`, i.e. to a Python double. Storing it as ``FLOAT`` would
round every value on the way in and make the round trip lossy.

**FT_RELATIVE_TIME is INTERVAL.** DuckDB's ``INTERVAL`` round-trips
:class:`datetime.timedelta` natively, and a ``timedelta`` never carries a month
component — the part of an interval whose length depends on the date it is
added to — so the ambiguity that usually argues against ``INTERVAL`` cannot
arise here.

**FT_ETHER is BLOB.** :mod:`remora.values` yields exactly 6 raw bytes, not
text; ``BLOB`` stores them as they are, so equality and ordering stay byte-exact
without re-formatting on every read.

**Timestamps are TIMESTAMP, never TIMESTAMPTZ.** DuckDB renders
``TIMESTAMPTZ`` through the session time zone, so one file would print
different timestamps on different machines and the #36 semantics suite could
not assert on them. Instead an aware datetime is converted to naive UTC on the
way in (:func:`to_db_timestamp`) and re-tagged as aware UTC on the way out
(:func:`from_db_timestamp`); a naive datetime handed in is assumed to already
be UTC and is never read as local time. :mod:`remora.workspace.schema` uses the
same pair for its catalog columns.

Unknown ftypes fall back to ``VARCHAR`` with identity codecs, mirroring
:func:`remora.values.get_info`'s fallback to ``str``, so an exotic dissector
type degrades to text instead of failing.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final

from remora.values import FTYPE_TABLE, convert
from remora.workspace.naming import column_name

__all__ = [
    "COLUMN_TYPES",
    "ColumnSpec",
    "ColumnType",
    "column_spec",
    "column_sql_type",
    "from_db_timestamp",
    "get_column_type",
    "to_db_timestamp",
]


@dataclass(frozen=True)
class ColumnType:
    """DuckDB column type and codec for one tshark ftype.

    Attributes:
        sql_type: DuckDB type of the scalar column, e.g. ``"UINTEGER"``.
        encode: Parsed Python value -> value bound into DuckDB.
        decode: Value read from DuckDB -> Python value.
    """

    sql_type: str
    encode: Callable[[Any], Any]
    decode: Callable[[Any], Any]


def _identity(value: Any) -> Any:
    return value


def to_db_timestamp(value: datetime) -> datetime:
    """Convert an aware datetime to the naive UTC DuckDB stores.

    A naive datetime is assumed to already be UTC and passes through unchanged
    — it is never interpreted as local time.

    Args:
        value: The timestamp to store.

    Returns:
        The same instant as a naive UTC datetime.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def from_db_timestamp(value: datetime) -> datetime:
    """Re-tag a naive UTC timestamp read from DuckDB as aware UTC.

    Args:
        value: The naive timestamp read back from a ``TIMESTAMP`` column.

    Returns:
        The same instant, tagged as UTC.
    """
    return value.replace(tzinfo=timezone.utc)


def _to_address_int(value: Any) -> int:
    """Encode an IPv4Address/IPv6Address as the integer the column holds."""
    return int(value)


def _to_ipv4(value: Any) -> IPv4Address:
    return IPv4Address(value)


def _to_ipv6(value: Any) -> IPv6Address:
    return IPv6Address(value)


_VARCHAR: Final[ColumnType] = ColumnType("VARCHAR", _identity, _identity)
_BLOB: Final[ColumnType] = ColumnType("BLOB", _identity, _identity)
_DOUBLE: Final[ColumnType] = ColumnType("DOUBLE", _identity, _identity)

# The integer width policy, owned here rather than derived from values.py:
# values.py only knows these are all `int`, and the width is exactly the part
# it does not carry.
_INT_WIDTHS: Final[Mapping[str, tuple[str, ...]]] = {
    "UTINYINT": ("FT_UINT8", "FT_CHAR"),
    "USMALLINT": ("FT_UINT16",),
    "UINTEGER": ("FT_UINT24", "FT_UINT32", "FT_FRAMENUM"),
    "UBIGINT": ("FT_UINT40", "FT_UINT48", "FT_UINT56", "FT_UINT64"),
    "TINYINT": ("FT_INT8",),
    "SMALLINT": ("FT_INT16",),
    "INTEGER": ("FT_INT24", "FT_INT32"),
    "BIGINT": ("FT_INT40", "FT_INT48", "FT_INT56", "FT_INT64"),
}

COLUMN_TYPES: Final[Mapping[str, ColumnType]] = {
    "FT_IPv4": ColumnType("UINTEGER", _to_address_int, _to_ipv4),
    "FT_IPv6": ColumnType("UHUGEINT", _to_address_int, _to_ipv6),
    "FT_ETHER": _BLOB,
    "FT_BYTES": _BLOB,
    "FT_BOOLEAN": ColumnType("BOOLEAN", _identity, _identity),
    "FT_ABSOLUTE_TIME": ColumnType("TIMESTAMP", to_db_timestamp, from_db_timestamp),
    "FT_RELATIVE_TIME": ColumnType("INTERVAL", _identity, _identity),
    "FT_DOUBLE": _DOUBLE,
    "FT_FLOAT": _DOUBLE,
    # Every ftype values.py carries as str, read from there rather than listed,
    # so a str ftype added there cannot silently fall out of this table.
    **{ftype: _VARCHAR for ftype, info in FTYPE_TABLE.items() if info.py_type is str},
    **{
        ftype: ColumnType(sql_type, _identity, _identity)
        for sql_type, ftypes in _INT_WIDTHS.items()
        for ftype in ftypes
    },
}
"""Every ftype :data:`remora.values.FTYPE_TABLE` knows, mapped to its column."""


def get_column_type(ftype: str) -> ColumnType:
    """Look up the column type for an ftype; unknown ftypes fall back to VARCHAR.

    Args:
        ftype: tshark ftype name, e.g. ``"FT_IPv4"``.

    Returns:
        The frozen column type and codec pair.
    """
    return COLUMN_TYPES.get(ftype, _VARCHAR)


def column_sql_type(ftype: str, multi: bool = False) -> str:
    """DuckDB type for a column holding this ftype.

    Args:
        ftype: tshark ftype name, e.g. ``"FT_UINT16"``.
        multi: Whether the field can occur more than once per packet, in which
            case the column holds a DuckDB ``LIST`` of the scalar type.

    Returns:
        The SQL type, e.g. ``"USMALLINT"`` or ``"USMALLINT[]"``.
    """
    sql_type = get_column_type(ftype).sql_type
    return f"{sql_type}[]" if multi else sql_type


@dataclass(frozen=True)
class ColumnSpec:
    """One projected field's column: name, type, and codec.

    Built by :func:`column_spec`, which is the single call the materialize
    pipeline (#31) needs per field. Collision checking is not done here —
    :func:`remora.workspace.naming.find_collisions` covers a whole field set at
    once, which is where that check belongs.

    Attributes:
        abbrev: Full tshark field abbrev, e.g. ``"tcp.port"``.
        column_name: Column in ``pkts``, from
            :func:`remora.workspace.naming.column_name`.
        ftype: tshark ftype name, e.g. ``"FT_UINT16"``.
        multi: Whether the field can occur more than once per packet.
        sql_type: SQL type of the column, from :func:`column_sql_type`.
    """

    abbrev: str
    column_name: str
    ftype: str
    multi: bool
    sql_type: str

    def encode_raw(self, raw: Sequence[str]) -> Any:
        """Encode a field's raw tshark occurrences into one column value.

        ``raw`` is what :meth:`remora.fields.RawPacket.get_raw` returns, so
        ``()`` means the field is absent.

        Absence is ``None`` for a scalar column and ``[]`` for a multi column —
        never ``NULL`` in a list column, because ``list_contains(NULL, x)`` is
        ``NULL`` while ``list_contains([], x)`` is ``false``, and the latter is
        what the predicate backend means by "an absent field never matches".

        Args:
            raw: The field's occurrences as tshark emitted them, in order.

        Returns:
            The value to bind into the column.

        Raises:
            ValueError: If a scalar field has more than one occurrence (declare
                it multi-value instead — keeping the first would silently drop
                data), or if the raw text is malformed for the ftype.
        """
        encode = get_column_type(self.ftype).encode
        if self.multi:
            return [encode(convert(self.ftype, text)) for text in raw]
        if not raw:
            return None
        if len(raw) > 1:
            raise ValueError(
                f"{self.abbrev} is declared scalar but occurred {len(raw)} times "
                f"in one packet; declare it multi-value to keep every occurrence"
            )
        return encode(convert(self.ftype, raw[0]))

    def decode(self, stored: Any) -> Any:
        """Decode a value read back from this column into its Python form.

        The inverse of :meth:`encode_raw` past the text stage: it yields the
        Python value :mod:`remora.values` parses to, not the raw tshark text.

        Absence survives the round trip — ``NULL`` in a scalar column decodes to
        ``None``, and an empty list stays empty. A ``NULL`` read from a multi
        column decodes to ``()`` as well: :meth:`encode_raw` never writes one,
        but a column added to rows that predate it is back-filled with ``NULL``,
        and callers should see that as "no occurrences" rather than ``None``.

        Args:
            stored: The value read from the column.

        Returns:
            ``T | None`` for a scalar column, ``tuple[T, ...]`` for a multi one
            — the same shapes instance access on a protocol view returns.
        """
        entry = get_column_type(self.ftype)
        if self.multi:
            return () if stored is None else tuple(entry.decode(item) for item in stored)
        return None if stored is None else entry.decode(stored)


def column_spec(abbrev: str, ftype: str, multi: bool = False) -> ColumnSpec:
    """Build the :class:`ColumnSpec` for one projected field.

    Args:
        abbrev: Full tshark field abbrev, e.g. ``"tcp.port"``.
        ftype: tshark ftype name, e.g. ``"FT_UINT16"``. An unknown one degrades
            to ``VARCHAR`` with identity codecs, as everywhere else here.
        multi: Whether the field can occur more than once per packet.

    Returns:
        The column's name, type and codec, ready for
        :func:`remora.workspace.schema.add_field_column`.

    Raises:
        ValueError: If ``abbrev`` is empty (from
            :func:`remora.workspace.naming.column_name`).
    """
    return ColumnSpec(
        abbrev=abbrev,
        column_name=column_name(abbrev),
        ftype=ftype,
        multi=multi,
        sql_type=column_sql_type(ftype, multi),
    )
