"""Tests for remora.values: typed value conversion for tshark field types."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from remora.values import FTYPE_TABLE, FTypeInfo, coerce_literal, convert, get_info

_INT_FTYPES = [
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
]

_ALL_FTYPES = [
    *_INT_FTYPES,
    "FT_IPv4",
    "FT_IPv6",
    "FT_ETHER",
    "FT_BYTES",
    "FT_BOOLEAN",
    "FT_ABSOLUTE_TIME",
    "FT_RELATIVE_TIME",
    "FT_DOUBLE",
    "FT_FLOAT",
    "FT_STRING",
    "FT_STRINGZ",
    "FT_NONE",
    # Explicit str mappings for the ftypes the issue #19 core set surfaced
    # (previously reached str via the unknown-ftype fallback); see issue #69.
    "FT_EUI64",
    "FT_OID",
    "FT_UINT_STRING",
    "FT_GUID",
    "FT_STRINGZPAD",
    "FT_AX25",
]

_EXPECTED_PY_TYPES: dict[str, type] = {
    **{name: int for name in _INT_FTYPES},
    "FT_IPv4": IPv4Address,
    "FT_IPv6": IPv6Address,
    "FT_ETHER": bytes,
    "FT_BYTES": bytes,
    "FT_BOOLEAN": bool,
    "FT_ABSOLUTE_TIME": datetime,
    "FT_RELATIVE_TIME": timedelta,
    "FT_DOUBLE": float,
    "FT_FLOAT": float,
    "FT_STRING": str,
    "FT_STRINGZ": str,
    "FT_NONE": str,
    "FT_EUI64": str,
    "FT_OID": str,
    "FT_UINT_STRING": str,
    "FT_GUID": str,
    "FT_STRINGZPAD": str,
    "FT_AX25": str,
}


class TestTable:
    def test_expected_types_cover_exactly_the_module_table(self) -> None:
        """Bidirectional completeness: an ftype added to (or removed from)
        FTYPE_TABLE fails here until the test's expectations are updated."""
        assert set(_EXPECTED_PY_TYPES) == set(FTYPE_TABLE)
        assert set(_ALL_FTYPES) == set(FTYPE_TABLE)

    @pytest.mark.parametrize("ftype", _ALL_FTYPES)
    def test_every_ftype_has_converter_and_target_type(self, ftype: str) -> None:
        info = FTYPE_TABLE[ftype]
        assert info.py_type is _EXPECTED_PY_TYPES[ftype]
        assert callable(info.parse)

    def test_get_info_returns_table_entry(self) -> None:
        assert get_info("FT_IPv4") is FTYPE_TABLE["FT_IPv4"]

    def test_unknown_ftype_falls_back_to_str(self) -> None:
        info = get_info("FT_SOMETHING_NEW")
        assert info.py_type is str
        assert info.parse("raw text") == "raw text"
        assert convert("FT_SOMETHING_NEW", "10.0.0.1") == "10.0.0.1"


class TestIntegers:
    @pytest.mark.parametrize("ftype", _INT_FTYPES)
    def test_decimal(self, ftype: str) -> None:
        assert convert(ftype, "31") == 31

    @pytest.mark.parametrize("ftype", _INT_FTYPES)
    def test_hex(self, ftype: str) -> None:
        assert convert(ftype, "0x1f") == 31

    def test_hex_uppercase_prefix_and_digits(self) -> None:
        assert convert("FT_UINT32", "0X1F") == 31

    def test_negative_decimal(self) -> None:
        assert convert("FT_INT32", "-42") == -42

    def test_negative_hex(self) -> None:
        assert convert("FT_INT8", "-0x1f") == -31

    def test_zero(self) -> None:
        assert convert("FT_UINT8", "0") == 0

    def test_whitespace_tolerated(self) -> None:
        assert convert("FT_UINT16", " 7 ") == 7

    @pytest.mark.parametrize("raw", ["", "abc", "0x", "1.5", "1f", "0xzz"])
    def test_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_UINT32", raw)

    @pytest.mark.parametrize("value", [0, 31, 255, -128, 2**63])
    def test_round_trip(self, value: int) -> None:
        assert convert("FT_UINT64", str(value)) == value
        assert convert("FT_UINT64", hex(value) if value >= 0 else f"-{hex(-value)}") == value


class TestBoolean:
    @pytest.mark.parametrize("raw", ["1", "True", "true"])
    def test_true_literals(self, raw: str) -> None:
        assert convert("FT_BOOLEAN", raw) is True

    @pytest.mark.parametrize("raw", ["0", "False", "false"])
    def test_false_literals(self, raw: str) -> None:
        assert convert("FT_BOOLEAN", raw) is False

    @pytest.mark.parametrize("raw", ["", "yes", "no", "TRUE", "FALSE", "2", " 1"])
    def test_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_BOOLEAN", raw)

    @pytest.mark.parametrize("value", [True, False])
    def test_round_trip(self, value: bool) -> None:
        assert convert("FT_BOOLEAN", str(value)) is value


class TestIPAddresses:
    def test_ipv4(self) -> None:
        assert convert("FT_IPv4", "10.0.0.1") == IPv4Address("10.0.0.1")

    def test_ipv6(self) -> None:
        assert convert("FT_IPv6", "2001:db8::1") == IPv6Address("2001:db8::1")

    @pytest.mark.parametrize("raw", ["", "10.0.0", "256.0.0.1", "not-an-ip"])
    def test_malformed_ipv4_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_IPv4", raw)

    @pytest.mark.parametrize("raw", ["", "2001:db8::zz", "10.0.0.1.2"])
    def test_malformed_ipv6_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_IPv6", raw)

    def test_round_trip(self) -> None:
        v4 = IPv4Address("192.168.1.254")
        v6 = IPv6Address("fe80::1")
        assert convert("FT_IPv4", str(v4)) == v4
        assert convert("FT_IPv6", str(v6)) == v6


class TestBytes:
    def test_ether_colon_hex(self) -> None:
        assert convert("FT_ETHER", "aa:bb:cc:dd:ee:ff") == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_ether_contiguous_hex(self) -> None:
        assert convert("FT_ETHER", "aabbccddeeff") == b"\xaa\xbb\xcc\xdd\xee\xff"

    @pytest.mark.parametrize("raw", ["", "aa:bb:cc", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff"])
    def test_ether_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_ETHER", raw)

    def test_bytes_colon_hex(self) -> None:
        assert convert("FT_BYTES", "aa:bb:cc") == b"\xaa\xbb\xcc"

    def test_bytes_contiguous_hex(self) -> None:
        assert convert("FT_BYTES", "aabbcc") == b"\xaa\xbb\xcc"

    def test_bytes_empty_is_empty(self) -> None:
        assert convert("FT_BYTES", "") == b""

    @pytest.mark.parametrize("raw", ["a", "aa:b", "zz", "0xaa"])
    def test_bytes_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_BYTES", raw)

    def test_round_trip(self) -> None:
        mac = b"\x00\x11\x22\x33\x44\x55"
        assert convert("FT_ETHER", ":".join(f"{b:02x}" for b in mac)) == mac
        payload = b"\xde\xad\xbe\xef"
        assert convert("FT_BYTES", payload.hex()) == payload
        assert convert("FT_BYTES", payload.hex(":")) == payload


class TestAbsoluteTime:
    def test_epoch_seconds_with_nanoseconds_truncates_to_micros(self) -> None:
        value = convert("FT_ABSOLUTE_TIME", "1625097600.123456789")
        assert value == datetime(2021, 7, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)

    def test_result_is_aware_utc(self) -> None:
        value = convert("FT_ABSOLUTE_TIME", "1625097600")
        assert isinstance(value, datetime)
        assert value.tzinfo == timezone.utc

    def test_integer_seconds(self) -> None:
        assert convert("FT_ABSOLUTE_TIME", "0") == datetime(1970, 1, 1, tzinfo=timezone.utc)

    def test_pre_epoch(self) -> None:
        value = convert("FT_ABSOLUTE_TIME", "-1.5")
        assert value == datetime(1969, 12, 31, 23, 59, 58, 500000, tzinfo=timezone.utc)

    @pytest.mark.parametrize("raw", ["", ".", "abc", "1.2.3", "1e9", "0x10"])
    def test_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_ABSOLUTE_TIME", raw)

    def test_round_trip(self) -> None:
        original = datetime(2021, 7, 1, 12, 34, 56, 789012, tzinfo=timezone.utc)
        assert convert("FT_ABSOLUTE_TIME", f"{original.timestamp():.6f}") == original


#: The instant every rendering in TestAbsoluteTimeRenderings names: what
#: tshark prints for frame 1 of tests/data/sample.pcap (epoch 1700000000).
_SAMPLE_FRAME_1 = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)


class TestAbsoluteTimeRenderings:
    """Every form tshark renders an absolute time in (issue #117).

    Measured on 4.2.2, 4.4.19 and 4.6.9; docs/semantics.md has the table of
    which reader, display base and version prints which.
    """

    @pytest.mark.parametrize(
        "raw",
        [
            # -T ek, every display base and version, frame.time_epoch included.
            "2023-11-14T22:13:20.000000000Z",
            # -T fields, UTC display base, 4.6.
            "2023-11-14T22:13:20Z",
            # -T fields, local display base, 4.6: the local offset, compact
            # (America/Los_Angeles on that date, then TZ pinned to UTC).
            "2023-11-14T14:13:20.000000000-0800",
            "2023-11-14T22:13:20.000000000+0000",
            # The extended offset spelling ISO 8601 also allows.
            "2023-11-15T03:43:20.000000000+05:30",
            # -T fields before 4.6, UTC display base or TZ pinned to UTC.
            "Nov 14, 2023 22:13:20.000000000 UTC",
            "Nov 14, 2023 22:13:20 UTC",
            # -T fields, Unix display base, every version.
            "1700000000.000000000",
        ],
    )
    def test_each_rendering_reads_as_the_same_instant(self, raw: str) -> None:
        assert convert("FT_ABSOLUTE_TIME", raw) == _SAMPLE_FRAME_1

    @pytest.mark.parametrize(
        "raw",
        [
            "2023-11-14T14:13:20.123456789-0800",
            "Nov 14, 2023 22:13:20.123456789 UTC",
        ],
    )
    def test_result_is_utc_and_truncated_to_micros(self, raw: str) -> None:
        value = convert("FT_ABSOLUTE_TIME", raw)
        assert isinstance(value, datetime)
        assert value.tzinfo == timezone.utc
        assert value == _SAMPLE_FRAME_1.replace(microsecond=123456)

    def test_pre_46_rendering_space_pads_a_single_digit_day(self) -> None:
        # tshark prints the day with %2d: "Nov  5", two spaces.
        value = convert("FT_ABSOLUTE_TIME", "Nov  5, 2023 00:00:05.500000000 UTC")
        assert value == datetime(2023, 11, 5, 0, 0, 5, 500000, tzinfo=timezone.utc)

    def test_null_is_the_zero_time(self) -> None:
        # The NTP display base prints the zero time as NULL in -T fields; -T ek
        # prints the same value as the epoch, so that is what NULL reads as.
        assert convert("FT_ABSOLUTE_TIME", "NULL") == datetime(1970, 1, 1, tzinfo=timezone.utc)

    @pytest.mark.parametrize("zone", ["MST", "MDT", "IST", "CET", "GMT", "America"])
    def test_a_pre_46_local_zone_abbreviation_is_refused(self, zone: str) -> None:
        # The abbreviation names no unique offset (IST is three), so reading it
        # would be a guess; only UTC is unambiguous. "America" is what a zone
        # name renders as where tzdata is missing.
        with pytest.raises(ValueError, match=f"zone abbreviation '{zone}'"):
            convert("FT_ABSOLUTE_TIME", f"Nov 14, 2023 15:13:20.000000000 {zone}")

    @pytest.mark.parametrize(
        "raw",
        [
            # No offset: local time, which names no instant.
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20.000000000",
            # Shapes tshark never prints for an absolute time.
            "2023-11-14 22:13:20Z",
            "2023-11-14T22:13:20+07",
            "Nov 14 2023 22:13:20 UTC",
            "Foo 14, 2023 22:13:20 UTC",
            "null",
            "Null",
            # Field-level nonsense that matches a pattern's shape.
            "2023-13-01T00:00:00Z",
            "2023-02-30T00:00:00Z",
            "2023-11-14T24:00:00Z",
            "2023-11-14T22:13:20+2400",
            "Nov 31, 2023 22:13:20 UTC",
        ],
    )
    def test_malformed_raises_value_error_naming_the_text(self, raw: str) -> None:
        with pytest.raises(ValueError, match=re.escape(repr(raw))):
            convert("FT_ABSOLUTE_TIME", raw)

    @pytest.mark.parametrize(
        "raw",
        ["0001-01-01T00:00:00+0100", "9999-12-31T23:59:59-0100", "99999999999999999"],
    )
    def test_out_of_range_is_value_error_not_overflow_error(self, raw: str) -> None:
        # datetime spans years 1..9999; past either end the arithmetic raises
        # OverflowError, which would break the module's ValueError contract.
        with pytest.raises(ValueError, match="invalid absolute time"):
            convert("FT_ABSOLUTE_TIME", raw)

    def test_coerce_literal_reads_an_iso_string(self) -> None:
        # coerce_literal parses str literals with the same function, so a user
        # can write the form tshark prints.
        literal = coerce_literal("FT_ABSOLUTE_TIME", "2023-11-14T22:13:20Z")
        assert literal == _SAMPLE_FRAME_1


class TestRelativeTime:
    def test_fractional_seconds(self) -> None:
        assert convert("FT_RELATIVE_TIME", "1.5") == timedelta(seconds=1, microseconds=500000)

    def test_nanoseconds_truncate_to_micros(self) -> None:
        assert convert("FT_RELATIVE_TIME", "0.000123999") == timedelta(microseconds=123)

    def test_negative(self) -> None:
        assert convert("FT_RELATIVE_TIME", "-2.25") == timedelta(seconds=-2.25)

    @pytest.mark.parametrize("raw", ["", ".", "abc", "1.2.3"])
    def test_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_RELATIVE_TIME", raw)

    def test_round_trip(self) -> None:
        original = timedelta(seconds=3, microseconds=250000)
        assert convert("FT_RELATIVE_TIME", f"{original.total_seconds():.6f}") == original


class TestFloats:
    @pytest.mark.parametrize("ftype", ["FT_DOUBLE", "FT_FLOAT"])
    def test_parse(self, ftype: str) -> None:
        assert convert(ftype, "3.14") == pytest.approx(3.14)
        assert convert(ftype, "-1e-3") == pytest.approx(-0.001)

    @pytest.mark.parametrize("raw", ["", "abc", "1..2"])
    def test_malformed_raises_value_error(self, raw: str) -> None:
        with pytest.raises(ValueError):
            convert("FT_DOUBLE", raw)

    def test_round_trip(self) -> None:
        value = 12345.6789
        assert convert("FT_DOUBLE", repr(value)) == value


class TestStrings:
    @pytest.mark.parametrize("ftype", ["FT_STRING", "FT_STRINGZ", "FT_NONE"])
    def test_identity(self, ftype: str) -> None:
        assert convert(ftype, "hello world") == "hello world"
        assert convert(ftype, "") == ""


class TestCoerceLiteral:
    def test_str_parsed_to_field_type(self) -> None:
        assert coerce_literal("FT_IPv4", "10.0.0.1") == IPv4Address("10.0.0.1")
        assert coerce_literal("FT_UINT16", "0x1f") == 31
        assert coerce_literal("FT_BOOLEAN", "true") is True

    def test_already_typed_passes_through(self) -> None:
        addr = IPv4Address("10.0.0.1")
        assert coerce_literal("FT_IPv4", addr) is addr
        assert coerce_literal("FT_UINT32", 80) == 80
        assert coerce_literal("FT_BOOLEAN", True) is True
        assert coerce_literal("FT_ETHER", b"\x00\x01\x02\x03\x04\x05") == bytes(range(6))
        now = datetime.now(tz=timezone.utc)
        assert coerce_literal("FT_ABSOLUTE_TIME", now) is now

    def test_int_widens_to_float_field(self) -> None:
        value = coerce_literal("FT_DOUBLE", 10)
        assert value == 10.0
        assert isinstance(value, float)

    def test_incompatible_type_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            coerce_literal("FT_IPv4", 42)
        with pytest.raises(TypeError):
            coerce_literal("FT_UINT32", 1.5)
        with pytest.raises(TypeError):
            coerce_literal("FT_STRING", 42)

    def test_bool_rejected_for_non_bool_fields(self) -> None:
        with pytest.raises(TypeError):
            coerce_literal("FT_UINT8", True)

    def test_parse_failure_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            coerce_literal("FT_IPv4", "not-an-ip")

    def test_unknown_ftype_falls_back_to_str(self) -> None:
        assert coerce_literal("FT_MYSTERY", "anything") == "anything"
        with pytest.raises(TypeError):
            coerce_literal("FT_MYSTERY", 42)


def test_ftypeinfo_is_frozen_and_generic() -> None:
    info: FTypeInfo[int] = FTypeInfo(int, int)
    field_name = "py_type"
    with pytest.raises(AttributeError):
        setattr(info, field_name, str)
