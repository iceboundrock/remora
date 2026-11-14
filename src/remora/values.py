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
FT_ABSOLUTE_TIME          datetime (aware, UTC)       epoch seconds (``"1625097600.123456789"``,
                                                      pre-epoch as tshark prints it; see below);
                                                      ISO 8601 with an explicit offset
                                                      (``"2021-07-01T00:00:00.123456789Z"``,
                                                      ``"...-0700"``, ``"...+05:30"``);
                                                      tshark's pre-4.6 rendering in UTC
                                                      (``"Jul  1, 2021 00:00:00.123456789 UTC"``);
                                                      ``"NULL"`` (the zero time) -> the epoch
FT_RELATIVE_TIME          timedelta                   seconds, e.g. ``"0.000123"``
FT_EUI64                  bytes (exactly 8)           ``"02:11:22:33:44:55:66:77"`` or
                                                      ``"0211223344556677"``
FT_GUID                   uuid.UUID                   ``"ab30317f-1a78-4dc4-8ff8-24d0d3715d86"``
                                                      (either case)
FT_DOUBLE, FT_FLOAT       float                       anything :func:`float` accepts
FT_STRING, FT_STRINGZ,    str                         identity (returned unchanged)
FT_NONE, FT_STRINGZPAD,
FT_UINT_STRING, FT_OID,
FT_AX25
========================  ==========================  =======================================

GUIDs and EUI-64s (issue #69)
-----------------------------
Both are read from the text tshark prints, never from wire bytes: a GUID is
the 8-4-4-4-12 hex form and an EUI-64 is eight colon-separated hex pairs, in
``-T fields`` and ``-T ek`` alike, on 4.2.2 and 4.6.9. A dissector that reads a
little-endian GUID off the wire (``dhcp.client_id.uuid``) has already swapped
it into the printed form, so the :class:`uuid.UUID` is the one Wireshark shows.
An EUI-64's bytes are in printed order, first pair first, which is also the
order that makes ``bytes`` comparison agree with Wireshark's.

Only those forms (plus contiguous hex for an EUI-64, as for ``FT_ETHER``) are
accepted. :class:`uuid.UUID` itself would also take braces, a ``urn:uuid:``
prefix and hyphens anywhere, and :meth:`bytes.fromhex` takes spaces between
pairs; none of those is a rendering tshark produces, so they raise. A ``bytes``
literal for an EUI-64 field must be exactly 8 bytes long, the same check the
text form gets.

``FT_OID``, ``FT_UINT_STRING``, ``FT_STRINGZPAD`` and ``FT_AX25`` stay ``str``
by decision (#69); the other three are text on the wire or in the display. An
OID is the numeric dotted text tshark prints in both readers (``"1.3.6.1.2.1"``,
never a resolved name), so ``<`` compares it as text, not arc by arc. #149
measured it and recommends an ``OID`` value object; ``docs/semantics.md`` has
the renderings and the recommendation.

Unknown ftypes fall back to ``str`` (identity), so new or exotic dissector
types degrade gracefully instead of failing.

Absolute times: why four forms
-------------------------------
tshark renders one ``FT_ABSOLUTE_TIME`` value differently depending on the
reader mode, the field's display base and the tshark version (measured on
4.2.2, 4.4.19 and 4.6.9; ``docs/semantics.md`` has the table):

- ``-T ek`` renders every absolute time as ISO 8601 UTC (``...Z``), on every
  version, ``frame.time_epoch`` included.
- ``-T fields`` renders a field whose display is Unix time as epoch seconds,
  and every other display as text: ISO 8601 with an offset on 4.6, and
  ``"Nov 14, 2023 22:13:20.000000000 UTC"`` before it. A local-time display
  carries the *local* zone, so before 4.6 it is a zone abbreviation
  (``MST``, ``IST``) that names no offset unambiguously, and from 4.6 an
  offset only as reliable as the platform's ``%z``; Remora pins the ``TZ`` of
  the tshark it spawns to UTC (:mod:`remora.reader.process`) so the zone is
  always ``UTC``.
- The NTP display renders the zero time as ``"NULL"`` in ``-T fields``, where
  ``-T ek`` renders the same value as the epoch.

Each accepted form names its instant unambiguously, so accepting all of them
loses nothing: a timestamp with no offset, or with a zone abbreviation other
than ``UTC``, still raises.

Pre-epoch times: tshark prints epoch seconds as the signed whole seconds of
its normalized ``nstime_t`` followed by the non-negative nanoseconds, so
``"-1.500000000"`` is -1 s + 0.5 s, half a second *before* the epoch, which is
what ``-T ek`` prints as ``1969-12-31T23:59:59.500000000Z``. The reader path
(:func:`convert`, and :attr:`FTypeInfo.parse`) reads it that way. A user
literal is an ordinary signed decimal, so :func:`coerce_literal` reads the same
``"-1.5"`` as one and a half seconds before the epoch. A ``-`` before a zero
whole part (``"-0.5"``) can only be the fraction's own sign, and both read it
as negative.

Precision note: epoch timestamps may carry nanosecond precision; Python's
:class:`datetime.datetime` and :class:`datetime.timedelta` resolve to
microseconds, so sub-microsecond digits are **truncated** (not rounded).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Generic, TypeVar
from uuid import UUID

__all__ = ["FTYPE_TABLE", "FTypeInfo", "coerce_literal", "convert", "get_info"]

T = TypeVar("T")


@dataclass(frozen=True)
class FTypeInfo(Generic[T]):
    """Target Python type and parse function for one tshark ftype."""

    py_type: type[T]
    parse: Callable[[str], T]
    """Raw tshark text -> value; raises ValueError on malformed input."""
    parse_literal: Callable[[str], T] | None = None
    """User literal text -> value, where it must read differently from what
    tshark prints; ``None`` means :attr:`parse` serves both. Only
    ``FT_ABSOLUTE_TIME`` needs it: see :func:`_parse_absolute_time_literal`."""
    check_literal: Callable[[T], T] | None = None
    """Validates a user literal that is already of :attr:`py_type`; raises
    ValueError. ``None`` accepts any value of the type. Only ``FT_EUI64`` needs
    it, because ``bytes`` alone does not say how many."""


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


#: An EUI-64 as tshark prints it (eight colon-separated pairs), or as 16
#: contiguous hex digits. Nothing looser: see the module docstring.
_EUI64_TEXT = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){7}|[0-9A-Fa-f]{16}", re.ASCII)

_EUI64_LENGTH = 8


def _parse_eui64(raw: str) -> bytes:
    """Parse an EUI-64 (``"02:11:22:33:44:55:66:77"``) into exactly 8 bytes."""
    text = raw.strip()
    if _EUI64_TEXT.fullmatch(text) is None:
        raise ValueError(
            f"invalid EUI-64 (need 8 colon-separated hex pairs or 16 hex digits): {raw!r}"
        )
    return bytes.fromhex(text.replace(":", ""))


def _check_eui64(value: bytes) -> bytes:
    """Refuse a ``bytes`` EUI-64 literal that is not exactly 8 bytes long."""
    if len(value) != _EUI64_LENGTH:
        raise ValueError(f"invalid EUI-64 (need 8 bytes, got {len(value)}): {value!r}")
    return value


#: A GUID as tshark prints it: 8-4-4-4-12 hex digits, in either case.
_GUID_TEXT = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", re.ASCII
)


def _parse_guid(raw: str) -> UUID:
    """Parse a GUID (``"ab30317f-1a78-4dc4-8ff8-24d0d3715d86"``) into a UUID."""
    text = raw.strip()
    if _GUID_TEXT.fullmatch(text) is None:
        raise ValueError(f"invalid GUID (need 8-4-4-4-12 hex digits): {raw!r}")
    return UUID(text)


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


#: ISO 8601 as tshark writes it: ``-T ek`` on every version (``Z``), and from
#: 4.6 ``-T fields`` for any non-Unix display (``Z`` or ``±HHMM``). The offset
#: is mandatory: a timestamp without one is local time, which names no instant.
_ISO_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:(Z)|([+-])(\d{2}):?(\d{2}))",
    re.ASCII,
)

#: tshark's ``-T fields`` rendering before 4.6: ``"Nov  5, 2023 00:00:05.1 UTC"``.
#: The day is space-padded, and the zone is an abbreviation. Only ``UTC`` is
#: accepted: abbreviations are not unique (``IST`` and ``CST`` each name
#: several offsets), so a table of the rest would be a table of guesses.
_LEGACY_TIME = re.compile(
    r"([A-Z][a-z]{2}) +(\d{1,2}), (\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? (\S+)",
    re.ASCII,
)

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

#: What the NTP display base renders for the zero time in ``-T fields``; ek
#: renders the same value as the epoch.
_NULL_TIME = "NULL"


def _micros(frac: str | None) -> int:
    """Fraction digits -> microseconds, sub-microsecond digits truncated."""
    return int(frac[:6].ljust(6, "0")) if frac else 0


def _parse_absolute_time(raw: str) -> datetime:
    """Parse any tshark rendering of an absolute time into an aware UTC datetime.

    Accepted: epoch seconds, ISO 8601 with an explicit offset, tshark's pre-4.6
    ``"Mon D, YYYY HH:MM:SS.f UTC"`` text, and ``"NULL"``. See the module
    docstring for which reader and version produce which, and for how a
    pre-epoch ``"-1.500000000"`` reads. Microsecond precision.
    """
    return _absolute_time_or_value_error(raw, signed_decimal=False)


def _parse_absolute_time_literal(raw: str) -> datetime:
    """:func:`_parse_absolute_time` for a user literal: epoch seconds are a signed decimal.

    tshark prints ``-1.500000000`` for the instant 0.5 s before the epoch
    (signed whole seconds, then a non-negative fraction), but a user writing
    ``"-1.5"`` means 1.5 s before it. Every other form reads the same in both.
    """
    return _absolute_time_or_value_error(raw, signed_decimal=True)


def _absolute_time_or_value_error(raw: str, *, signed_decimal: bool) -> datetime:
    try:
        return _absolute_time_of(raw.strip(), signed_decimal=signed_decimal)
    except (ValueError, OverflowError) as exc:
        # OverflowError is a date outside datetime's years 1..9999: malformed
        # input all the same, and this module's contract is ValueError.
        raise ValueError(f"invalid absolute time {raw!r}: {exc}") from None


def _offset_of(sign: str, hours: str, minutes: str) -> timedelta:
    """An ISO 8601 ``±HH[:]MM`` offset, refusing minutes ``timedelta`` would carry."""
    # timedelta(minutes=60) is silently an hour, so "+0060" would read as
    # "+0100"; the regex admits two digits, so the range is checked here.
    if int(minutes) > 59:
        raise ValueError(f"offset minutes {minutes!r} out of range 00..59")
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    return -offset if sign == "-" else offset


def _absolute_time_of(text: str, *, signed_decimal: bool) -> datetime:
    """Stripped text -> datetime; raises without naming the text.

    *signed_decimal* reads negative epoch seconds as a user literal rather
    than as tshark's rendering (see :func:`_parse_absolute_time_literal`).
    """
    if text == _NULL_TIME:
        return _EPOCH
    iso = _ISO_TIME.fullmatch(text)
    if iso is not None:
        year, month, day, hour, minute, second, frac, zulu, sign, off_h, off_m = iso.groups()
        offset = timedelta(0) if zulu else _offset_of(sign, off_h, off_m)
        local = datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            _micros(frac),
            tzinfo=timezone(offset),
        )
        return local.astimezone(timezone.utc)
    legacy = _LEGACY_TIME.fullmatch(text)
    if legacy is not None:
        month_name, day, year, hour, minute, second, frac, zone = legacy.groups()
        if zone != "UTC":
            raise ValueError(
                f"local time with zone abbreviation {zone!r}; abbreviations are not "
                "unique UTC offsets, so only UTC is read (tshark renders a local-time "
                "field this way before 4.6 unless its TZ is UTC, which Remora pins "
                "for the tshark it spawns)"
            )
        if month_name not in _MONTHS:
            raise ValueError(f"unknown month {month_name!r}")
        return datetime(
            int(year),
            _MONTHS[month_name],
            int(day),
            int(hour),
            int(minute),
            int(second),
            _micros(frac),
            tzinfo=timezone.utc,
        )
    try:
        sign, seconds, micros = _parse_epoch_parts(text)
    except ValueError:
        raise ValueError(
            'expected epoch seconds, ISO 8601 with an offset, "Mon D, YYYY HH:MM:SS UTC" or "NULL"'
        ) from None
    if sign > 0 or seconds == 0 or signed_decimal:
        return _EPOCH + timedelta(seconds=sign * seconds, microseconds=sign * micros)
    # tshark's rendering of a normalized nstime_t before the epoch: the whole
    # seconds carry the sign and the fraction is added, so "-1.500000000" is
    # -1 s + 0.5 s. Truncating the added fraction to microseconds moves the
    # instant toward the past, as truncating the fraction of the ISO form ek
    # prints for it does ("23:59:59.999999999Z" for "-1.999999999"), so the
    # two readers agree to the microsecond.
    return _EPOCH + timedelta(seconds=-seconds, microseconds=micros)


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

_STR_FTYPES = (
    # Surfaced by the issue #19 core protocol set, and kept as ``str`` by the
    # issue #69 decision: listing them makes the choice deliberate rather than
    # accidental, so `test_every_ftype_is_known` can hold the line on genuinely
    # unrecognized ftypes. The OID type #149 recommends is in docs/semantics.md;
    # the other three are text. Changing any of them changes the shipped static
    # type of every field that uses it.
    "FT_OID",  # snmp, tls
    "FT_UINT_STRING",  # ssh
    "FT_STRINGZPAD",  # dhcp, stp
    "FT_AX25",  # arp
)

FTYPE_TABLE: Mapping[str, FTypeInfo[Any]] = {
    "FT_IPv4": FTypeInfo(IPv4Address, IPv4Address),
    "FT_IPv6": FTypeInfo(IPv6Address, IPv6Address),
    "FT_ETHER": FTypeInfo(bytes, _parse_ether),
    "FT_BYTES": FTypeInfo(bytes, _parse_bytes),
    "FT_EUI64": FTypeInfo(bytes, _parse_eui64, check_literal=_check_eui64),
    "FT_GUID": FTypeInfo(UUID, _parse_guid),
    "FT_BOOLEAN": FTypeInfo(bool, _parse_bool),
    "FT_ABSOLUTE_TIME": FTypeInfo(datetime, _parse_absolute_time, _parse_absolute_time_literal),
    "FT_RELATIVE_TIME": FTypeInfo(timedelta, _parse_relative_time),
    "FT_DOUBLE": FTypeInfo(float, float),
    "FT_FLOAT": FTypeInfo(float, float),
    "FT_STRING": _STR_INFO,
    "FT_STRINGZ": _STR_INFO,
    "FT_NONE": _STR_INFO,
    **{name: _STR_INFO for name in _STR_FTYPES},
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

    - Values already of the field's Python type pass through unchanged, once
      the ftype's literal check accepts them (an ``FT_EUI64`` ``bytes`` literal
      must be 8 bytes long; ValueError otherwise).
    - ``str`` values are parsed with the field's literal parse function, which
      is its parse function except where a user literal must read differently
      from tshark's rendering (``FT_ABSOLUTE_TIME``'s negative epoch seconds);
      it raises ValueError on malformed input.
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
        return value if info.check_literal is None else info.check_literal(value)
    if isinstance(value, str):
        return (info.parse_literal or info.parse)(value)
    if py_type is float and isinstance(value, int):
        return float(value)
    raise TypeError(
        f"cannot coerce {type(value).__name__} literal {value!r} for {ftype} "
        f"(expects {py_type.__name__} or str)"
    )
