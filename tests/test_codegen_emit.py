"""Tests for emitting paired protocol modules (runtime .py + stub .pyi)."""

from __future__ import annotations

import pytest

from remora.codegen.emit import EmittedModule, emit_protocol, mangle_protocol
from remora.codegen.parse import FieldDef, Protocol


class TestMangleProtocol:
    def test_plain_abbrev_passes_through(self) -> None:
        assert mangle_protocol("udp") == "udp"

    def test_uppercase_is_lowered(self) -> None:
        assert mangle_protocol("TCP") == "tcp"

    def test_hyphens_become_underscores(self) -> None:
        assert mangle_protocol("acf-can") == "acf_can"

    def test_dots_become_underscores(self) -> None:
        assert mangle_protocol("mp2t.af") == "mp2t_af"

    def test_leading_digit_gets_p_prefix(self) -> None:
        assert mangle_protocol("6lowpan") == "p_6lowpan"

    def test_leading_underscore_result_gets_p_prefix(self) -> None:
        assert mangle_protocol("-ws") == "p_ws"

    def test_keyword_gets_trailing_underscore(self) -> None:
        assert mangle_protocol("class") == "class_"

    def test_empty_abbrev_raises(self) -> None:
        with pytest.raises(ValueError):
            mangle_protocol("")


def make_field(abbrev: str, ftype: str, parent: str) -> FieldDef:
    return FieldDef(name=abbrev, abbrev=abbrev, ftype=ftype, parent=parent, base="")


UDP_PROTO = Protocol(name="User Datagram Protocol", abbrev="udp")
UDP_FIELDS = [
    make_field("udp.srcport", "FT_UINT16", "udp"),
    make_field("udp.port", "FT_UINT16", "udp"),
    make_field("udp.checksum.status", "FT_UINT8", "udp"),
    make_field("udp.time_delta", "FT_RELATIVE_TIME", "udp"),
]

EXPECTED_UDP_PY = '''"""Generated protocol module for tshark layer ``udp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["UDP"]


class UDP(ProtocolBase):
    """User Datagram Protocol (tshark layer ``udp``)."""

    _proto_ = "udp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("udp.srcport", "FT_UINT16", 0),
        "port": ("udp.port", "FT_UINT16", 1),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
    }
'''

EXPECTED_UDP_PYI = """from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    srcport: Field[int]
    port: MultiField[int]
    checksum_status: Field[int]
    time_delta: Field[timedelta]
"""


def emit_udp() -> EmittedModule:
    return emit_protocol(UDP_PROTO, UDP_FIELDS, multi=frozenset({"udp.port"}))


class TestEmitHappyPath:
    def test_module_and_class_names(self) -> None:
        emitted = emit_udp()
        assert emitted.module_name == "udp"
        assert emitted.class_name == "UDP"
        assert emitted.warnings == ()

    def test_py_source_is_exact(self) -> None:
        assert emit_udp().py_source == EXPECTED_UDP_PY

    def test_pyi_source_is_exact(self) -> None:
        assert emit_udp().pyi_source == EXPECTED_UDP_PYI

    def test_ipaddress_types_are_imported(self) -> None:
        proto = Protocol(name="Internet Protocol Version 4", abbrev="ip")
        fields = [
            make_field("ip.src", "FT_IPv4", "ip"),
            make_field("ip.host", "FT_IPv6", "ip"),
        ]
        pyi = emit_protocol(proto, fields).pyi_source
        assert pyi.startswith("from ipaddress import IPv4Address, IPv6Address\n\n")
        assert "    src: Field[IPv4Address]\n" in pyi
        assert "    host: Field[IPv6Address]\n" in pyi

    def test_scalar_only_protocol_imports_only_field(self) -> None:
        proto = Protocol(name="Ethernet", abbrev="eth")
        pyi = emit_protocol(proto, [make_field("eth.type", "FT_UINT16", "eth")]).pyi_source
        assert "MultiField" not in pyi
        assert "from remora.fields import Field\n" in pyi
        assert "from datetime import" not in pyi
        assert "from ipaddress import" not in pyi

    def test_multi_only_protocol_imports_only_multifield(self) -> None:
        proto = Protocol(name="Domain Name System", abbrev="dns")
        fields = [make_field("dns.a", "FT_IPv4", "dns")]
        pyi = emit_protocol(proto, fields, multi=frozenset({"dns.a"})).pyi_source
        assert "from remora.fields import MultiField\n" in pyi
        assert "    a: MultiField[IPv4Address]\n" in pyi
