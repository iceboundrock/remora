"""Tests for Field/MultiField dual-mode descriptors, FieldRef, and packet contracts.

The ``assert_type`` calls are the static half of the acceptance criteria: they
are verified when mypy checks this file and are no-ops at runtime.
"""

from __future__ import annotations

from ipaddress import IPv4Address

import pytest
from typing_extensions import assert_type

from remora.expr import Comparison, Expr, Not
from remora.fields import (
    Field,
    FieldNotProjectedError,
    FieldRef,
    MultiField,
    RawPacket,
)


class FakePacket:
    """Minimal RawPacket: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())


SRC_REF = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
PORT_REF = FieldRef[int]("tcp.port", "FT_UINT16", True)
TTL_REF = FieldRef[int]("ip.ttl", "FT_UINT8", False)


class FakeProto:
    """Stands in for a protocol class; #11's ProtocolBase builds these lazily."""

    _remora_packet: RawPacket

    src = Field(SRC_REF)
    port = MultiField(PORT_REF)
    ttl = Field(TTL_REF)

    def __init__(self, packet: RawPacket) -> None:
        self._remora_packet = packet


def _proto(data: dict[str, tuple[str, ...]]) -> FakeProto:
    return FakeProto(FakePacket(data))


class TestClassAccess:
    def test_returns_the_field_ref(self) -> None:
        assert FakeProto.src is SRC_REF
        assert FakeProto.port is PORT_REF

    def test_static_types(self) -> None:
        assert_type(FakeProto.src, FieldRef[IPv4Address])
        assert_type(FakeProto.port, FieldRef[int])

    def test_ref_carries_metadata(self) -> None:
        assert FakeProto.src.name == "ip.src"
        assert FakeProto.src.ftype == "FT_IPv4"
        assert FakeProto.src.multi is False
        assert FakeProto.port.multi is True

    def test_usable_in_expr_construction(self) -> None:
        e = FakeProto.src == "10.0.0.1"
        assert isinstance(e, Comparison)
        assert e.field.name == "ip.src"
        ne = FakeProto.port != 443
        assert isinstance(ne, Not)
        both: Expr = (FakeProto.src == "10.0.0.1") & (FakeProto.port == 443)
        assert isinstance(both, Expr)

    def test_hash_and_repr(self) -> None:
        assert hash(SRC_REF) == hash("ip.src")
        assert repr(SRC_REF) == "<FieldRef ip.src (FT_IPv4)>"
        assert repr(PORT_REF) == "<FieldRef tcp.port (FT_UINT16, multi)>"


class TestScalarInstanceAccess:
    def test_present_value_is_converted(self) -> None:
        pkt = _proto({"ip.src": ("10.0.0.1",), "ip.ttl": ("0x40",)})
        assert pkt.src == IPv4Address("10.0.0.1")
        assert pkt.ttl == 64

    def test_absent_is_none(self) -> None:
        assert _proto({}).src is None

    def test_static_types(self) -> None:
        pkt = _proto({})
        assert_type(pkt.src, IPv4Address | None)
        assert_type(pkt.ttl, int | None)

    def test_multiple_occurrences_first_wins(self) -> None:
        pkt = _proto({"ip.ttl": ("1", "2")})
        assert pkt.ttl == 1

    def test_malformed_raw_raises_value_error(self) -> None:
        pkt = _proto({"ip.ttl": ("not-a-number",)})
        with pytest.raises(ValueError, match="not-a-number"):
            _ = pkt.ttl


class TestMultiInstanceAccess:
    def test_occurrences_become_tuple(self) -> None:
        pkt = _proto({"tcp.port": ("443", "51234")})
        assert pkt.port == (443, 51234)

    def test_absent_is_empty_tuple(self) -> None:
        assert _proto({}).port == ()

    def test_static_types(self) -> None:
        pkt = _proto({})
        assert_type(pkt.port, tuple[int, ...])

    def test_single_occurrence_is_one_tuple(self) -> None:
        assert _proto({"tcp.port": ("80",)}).port == (80,)


class TestContracts:
    def test_fake_packet_satisfies_raw_packet(self) -> None:
        assert isinstance(FakePacket({}), RawPacket)

    def test_field_not_projected_error_is_key_error(self) -> None:
        assert issubclass(FieldNotProjectedError, KeyError)

    def test_absent_vs_empty_string_are_distinct(self) -> None:
        """() is absent -> None; ("",) is a present empty value (parsed as "")."""
        name_ref = FieldRef[str]("dns.qry.name", "FT_STRING", False)

        class P:
            _remora_packet: RawPacket
            name = Field(name_ref)

            def __init__(self, packet: RawPacket) -> None:
                self._remora_packet = packet

        assert P(FakePacket({})).name is None
        assert P(FakePacket({"dns.qry.name": ("",)})).name == ""
