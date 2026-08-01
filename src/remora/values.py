"""Typed value conversion for tshark field types (ftypes).

tshark emits every field value as text; this module is the single source of
truth mapping tshark ftype names (e.g. ``"FT_IPv4"``) to Python types and
parse functions.

Malformed-input policy
----------------------
Every parse function raises :class:`ValueError` on malformed input — loud
beats silent. Callers that want a lenient fallback must catch it explicitly.

Type mapping
------------
========================  ==========================  =======================================
ftype                     Python type                 Accepted text forms
========================  ==========================  =======================================
FT_IPv4                   ipaddress.IPv4Address       dotted quad, e.g. ``"10.0.0.1"``
FT_IPv6                   ipaddress.IPv6Address       RFC 4291 text, e.g. ``"2001:db8::1"``
FT_ETHER                  bytes (exactly 6)           ``"aa:bb:cc:dd:ee:ff"`` or ``"aabbccddeeff"``
FT_BYTES                  bytes                       colon-hex ``"aa:bb:cc"`` or contiguous hex
FT_UINT8..FT_UINT64,      int                         decimal (``"31"``) and hex (``"0x1f"``)
FT_INT8..FT_INT64,
FT_FRAMENUM, FT_CHAR
FT_BOOLEAN                bool                        ``{"1", "True", "true"}`` -> ``True``;
                                                      ``{"0", "False", "false"}`` -> ``False``
FT_ABSOLUTE_TIME          datetime (aware, UTC)       epoch seconds, e.g. ``"1625097600.123456789"``
FT_RELATIVE_TIME          timedelta                   seconds, e.g. ``"0.000123"``
FT_DOUBLE, FT_FLOAT       float                       anything :func:`float` accepts
FT_STRING, FT_STRINGZ,    str                         identity (returned unchanged)
FT_NONE
========================  ==========================  =======================================

Unknown ftypes fall back to ``str`` (identity), so new or exotic dissector
types degrade gracefully instead of failing.

Precision note: epoch timestamps may carry nanosecond precision; Python's
:class:`datetime.datetime` and :class:`datetime.timedelta` resolve to
microseconds, so sub-microsecond digits are **truncated** (not rounded).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class FTypeInfo(Generic[T]):
    """Target Python type and parse function for one tshark ftype."""

    py_type: type[T]
    parse: Callable[[str], T]
    """Raw tshark text -> value; raises ValueError on malformed input."""


def _identity(raw: str) -> str:
    return raw


def _parse_int(raw: str) -> int:
    """Parse a decimal ("31") or hex ("0x1f") integer, with optional sign."""
    text = raw.strip()
    body = text[1:] if text[:1] in {"+", "-"} else text
    if body[:2].lower() == "0x":
        return int(text, 16)
    return int(text, 10)


def _parse_bytes(raw: str) -> bytes:
    """Parse colon-separated ("aa:bb:cc") or contiguous ("aabbcc") hex bytes."""
    text = raw.strip().replace(":", "")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"invalid byte string: {raw!r}") from None


def _parse_ether(raw: str) -> bytes:
    """Parse a MAC address ("aa:bb:cc:dd:ee:ff") into exactly 6 bytes."""
    value = _parse_bytes(raw)
    if len(value) != 6:
        raise ValueError(f"invalid MAC address (need 6 bytes, got {len(value)}): {raw!r}")
    return value


_TRUE_LITERALS = frozenset({"1", "True", "true"})
_FALSE_LITERALS = frozenset({"0", "False", "false"})


def _parse_bool(raw: str) -> bool:
    if raw in _TRUE_LITERALS:
        return True
    if raw in _FALSE_LITERALS:
        return False
    raise ValueError(f"invalid boolean: {raw!r}")


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _parse_epoch_parts(raw: str) -> tuple[int, int, int]:
    """Split epoch-style seconds text into (sign, whole seconds, microseconds).

    Sub-microsecond digits are truncated. Raises ValueError on malformed input.
    """
    text = raw.strip()
    sign = 1
    if text[:1] in {"+", "-"}:
        if text[0] == "-":
            sign = -1
        text = text[1:]
    seconds_part, _, frac_part = text.partition(".")
    if not seconds_part and not frac_part:
        raise ValueError(f"invalid epoch seconds: {raw!r}")
    if seconds_part and not (seconds_part.isascii() and seconds_part.isdigit()):
        raise ValueError(f"invalid epoch seconds: {raw!r}")
    if frac_part and not (frac_part.isascii() and frac_part.isdigit()):
        raise ValueError(f"invalid epoch seconds: {raw!r}")
    seconds = int(seconds_part) if seconds_part else 0
    micros = int(frac_part[:6].ljust(6, "0")) if frac_part else 0
    return sign, seconds, micros


def _parse_absolute_time(raw: str) -> datetime:
    """Parse epoch seconds into an aware UTC datetime (microsecond precision)."""
    sign, seconds, micros = _parse_epoch_parts(raw)
    return _EPOCH + timedelta(seconds=sign * seconds, microseconds=sign * micros)


def _parse_relative_time(raw: str) -> timedelta:
    """Parse epoch-style seconds into a timedelta (microsecond precision)."""
    sign, seconds, micros = _parse_epoch_parts(raw)
    return timedelta(seconds=sign * seconds, microseconds=sign * micros)


_STR_INFO: FTypeInfo[str] = FTypeInfo(str, _identity)
_INT_INFO: FTypeInfo[int] = FTypeInfo(int, _parse_int)

_INT_FTYPES = (
    "FT_UINT8",
    "FT_UINT16",
    "FT_UINT24",
    "FT_UINT32",
    "FT_UINT40",
    "FT_UINT48",
    "FT_UINT56",
    "FT_UINT64",
    "FT_INT8",
    "FT_INT16",
    "FT_INT24",
    "FT_INT32",
    "FT_INT40",
    "FT_INT48",
    "FT_INT56",
    "FT_INT64",
    "FT_FRAMENUM",
    "FT_CHAR",
)

FTYPE_TABLE: Mapping[str, FTypeInfo[Any]] = {
    "FT_IPv4": FTypeInfo(IPv4Address, IPv4Address),
    "FT_IPv6": FTypeInfo(IPv6Address, IPv6Address),
    "FT_ETHER": FTypeInfo(bytes, _parse_ether),
    "FT_BYTES": FTypeInfo(bytes, _parse_bytes),
    "FT_BOOLEAN": FTypeInfo(bool, _parse_bool),
    "FT_ABSOLUTE_TIME": FTypeInfo(datetime, _parse_absolute_time),
    "FT_RELATIVE_TIME": FTypeInfo(timedelta, _parse_relative_time),
    "FT_DOUBLE": FTypeInfo(float, float),
    "FT_FLOAT": FTypeInfo(float, float),
    "FT_STRING": _STR_INFO,
    "FT_STRINGZ": _STR_INFO,
    "FT_NONE": _STR_INFO,
    **{name: _INT_INFO for name in _INT_FTYPES},
}


def get_info(ftype: str) -> FTypeInfo[Any]:
    """Look up conversion info for an ftype; unknown ftypes fall back to str."""
    return FTYPE_TABLE.get(ftype, _STR_INFO)


def convert(ftype: str, raw: str) -> object:
    """Convert raw tshark text to the ftype's Python value.

    Raises ValueError on malformed input.
    """
    return get_info(ftype).parse(raw)


def coerce_literal(ftype: str, value: object) -> object:
    """Normalize a user-supplied comparison literal to the field's Python type.

    - Values already of the field's Python type pass through unchanged.
    - ``str`` values are parsed with the field's parse function (which raises
      ValueError on malformed input).
    - ``int`` values are widened to ``float`` for float fields.
    - Anything else raises TypeError. ``bool`` literals are rejected for
      non-boolean fields (``bool`` is a subclass of ``int``, but ``True`` is
      almost certainly a mistake as an integer-field literal).
    """
    info = get_info(ftype)
    py_type = info.py_type
    if py_type is not bool and isinstance(value, bool):
        raise TypeError(
            f"bool literal {value!r} is not valid for {ftype} (expects {py_type.__name__})"
        )
    if isinstance(value, py_type):
        return value
    if isinstance(value, str):
        return info.parse(value)
    if py_type is float and isinstance(value, int):
        return float(value)
    raise TypeError(
        f"cannot coerce {type(value).__name__} literal {value!r} for {ftype} "
        f"(expects {py_type.__name__} or str)"
    )
