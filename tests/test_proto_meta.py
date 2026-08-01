"""Tests for ProtocolMeta lazy field materialization and ProtocolBase views."""

from __future__ import annotations

import time
from ipaddress import IPv4Address
from unittest import mock

import pytest

from conftest import FakePacket
from remora.expr import Comparison, Not
from remora.fields import Field, FieldRef, MultiField
from remora.proto import _meta
from remora.proto._meta import FieldTable, ProtocolBase


def make_proto(name: str, table: FieldTable) -> type[ProtocolBase]:
    """Build a fresh protocol class per test so descriptor caches don't leak."""
    return type(name, (ProtocolBase,), {"_proto_": name.lower(), "_table_": table})


IP_TABLE: FieldTable = {
    "src": ("ip.src", "FT_IPv4", 0),
    "dst": ("ip.dst", "FT_IPv4", 0),
    "ttl": ("ip.ttl", "FT_UINT8", 0),
}
TCP_TABLE: FieldTable = {
    "port": ("tcp.port", "FT_UINT16", 1),
    "srcport": ("tcp.srcport", "FT_UINT16", 0),
}


class TestLazyMaterialization:
    def test_no_descriptors_exist_before_access(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        assert "src" not in ip.__dict__

    def test_class_access_returns_field_ref(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        ref = ip.src
        assert isinstance(ref, FieldRef)
        assert ref.name == "ip.src"
        assert ref.ftype == "FT_IPv4"
        assert ref.multi is False

    def test_descriptor_constructed_once_and_cached(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        with mock.patch.object(_meta, "Field", wraps=Field) as counted:
            first = ip.src
            second = ip.src
            third = ip.src
        assert counted.call_count == 1
        assert first is second is third  # the cached descriptor serves one FieldRef
        assert isinstance(ip.__dict__["src"], Field)

    def test_multi_spec_materializes_multifield(self) -> None:
        tcp = make_proto("TCP", TCP_TABLE)
        assert tcp.port.multi is True
        assert isinstance(tcp.__dict__["port"], MultiField)
        assert tcp.srcport.multi is False
        assert isinstance(tcp.__dict__["srcport"], Field)

    def test_unknown_attribute_names_protocol_and_attribute(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        with pytest.raises(AttributeError, match=r"'IP'.*'nope'"):
            _ = ip.nope

    def test_underscore_names_are_reserved(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        with pytest.raises(AttributeError):
            _ = ip._not_a_field


class TestDir:
    def test_dir_lists_all_fields_without_materializing(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        listed = dir(ip)
        assert {"src", "dst", "ttl"} <= set(listed)
        assert "src" not in ip.__dict__  # no Field was constructed

    def test_dir_still_includes_regular_attributes(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        assert "_table_" in dir(ip) or "_proto_" in dir(ip)


class TestExprConstruction:
    def test_class_access_builds_expr(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        e = ip.src == "10.0.0.1"
        assert isinstance(e, Comparison)
        assert e.field.name == "ip.src"
        ne = ip.ttl != 64
        assert isinstance(ne, Not)


class TestInstanceAccess:
    def test_dual_mode_contract_scalar(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        pkt = ip(FakePacket({"ip.src": ("10.0.0.1",), "ip.ttl": ("64",)}))
        assert pkt.src == IPv4Address("10.0.0.1")
        assert pkt.ttl == 64
        assert pkt.dst is None

    def test_dual_mode_contract_multi(self) -> None:
        tcp = make_proto("TCP", TCP_TABLE)
        pkt = tcp(FakePacket({"tcp.port": ("443", "51234")}))
        assert pkt.port == (443, 51234)
        assert tcp(FakePacket({})).port == ()

    def test_instance_access_before_any_class_access(self) -> None:
        """Instance path alone must trigger materialization (ProtocolBase.__getattr__)."""
        ip = make_proto("IP", IP_TABLE)
        pkt = ip(FakePacket({"ip.src": ("10.0.0.1",)}))
        assert pkt.src == IPv4Address("10.0.0.1")
        assert isinstance(ip.__dict__["src"], Field)

    def test_instance_access_after_class_access_uses_cache(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        _ = ip.src  # materialize via class path
        pkt = ip(FakePacket({"ip.src": ("10.0.0.1",)}))
        assert pkt.src == IPv4Address("10.0.0.1")

    def test_unknown_instance_attribute_raises(self) -> None:
        ip = make_proto("IP", IP_TABLE)
        pkt = ip(FakePacket({}))
        with pytest.raises(AttributeError, match="nope"):
            _ = pkt.nope


class TestImportCostBudget:
    """A synthetic 10,000-field protocol must be effectively free until touched.

    Generous ceilings to avoid CI flakes: the point is 'no per-field work',
    not micro-benchmarks — eager construction of 10k descriptors would blow
    these budgets by orders of magnitude.
    """

    def test_ten_thousand_fields_class_creation_and_one_access(self) -> None:
        table: FieldTable = {
            f"field_{i}": (f"big.field_{i}", "FT_UINT32", 0) for i in range(10_000)
        }
        start = time.perf_counter()
        big = make_proto("BIG", table)
        creation = time.perf_counter() - start

        start = time.perf_counter()
        ref = big.field_9999
        first_access = time.perf_counter() - start

        assert ref.name == "big.field_9999"
        assert creation < 0.5, f"class creation took {creation:.3f}s — per-field work at import?"
        assert first_access < 0.05, f"one field access took {first_access:.4f}s"
        assert len([k for k in big.__dict__ if k.startswith("field_")]) == 1  # only the touched one
