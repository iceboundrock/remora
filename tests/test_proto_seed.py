"""Pairing tests for the hand-written seed protocol modules (issue #13).

The seed ``.py`` modules are dumb compact tables in the frozen format the M2
generator (issue #14) will emit; the sibling ``.pyi`` stubs shadow them for
type checkers. These tests parse each stub with ``ast`` and cross-check it
against the runtime ``_table_`` in both directions, so the pair cannot drift.

The ``assert_type`` calls are the static half of the acceptance criteria:
they are verified when mypy checks this file and are no-ops at runtime.
"""

from __future__ import annotations

import ast
import pathlib
from ipaddress import IPv4Address
from types import ModuleType
from typing import TypeVar, cast

import pytest
from typing_extensions import assert_type

from conftest import FakePacket
from remora import values
from remora.expr import Comparison
from remora.fields import FieldRef, Packet
from remora.proto import DNS, IP, TCP
from remora.proto import dns as dns_mod
from remora.proto import eth as eth_mod
from remora.proto import ip as ip_mod
from remora.proto import tcp as tcp_mod
from remora.proto import udp as udp_mod
from remora.proto._meta import ProtocolBase

SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
    (ip_mod, ip_mod.IP),
    (tcp_mod, tcp_mod.TCP),
    (udp_mod, udp_mod.UDP),
    (dns_mod, dns_mod.DNS),
]

seed_params = pytest.mark.parametrize(
    ("module", "cls"), SEEDS, ids=[cls.__name__ for _, cls in SEEDS]
)


def stub_fields(module: ModuleType) -> dict[str, tuple[str, str]]:
    """Parse a module's ``.pyi``: attr name -> (descriptor name, inner type name)."""
    assert module.__file__ is not None
    stub_path = pathlib.Path(module.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(), filename=str(stub_path))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    assert len(classes) == 1, f"expected exactly one class in {stub_path}"
    fields: dict[str, tuple[str, str]] = {}
    for item in classes[0].body:
        if not isinstance(item, ast.AnnAssign):
            continue
        assert isinstance(item.target, ast.Name)
        annotation = item.annotation
        assert isinstance(annotation, ast.Subscript), f"{item.target.id}: not Field[T]"
        assert isinstance(annotation.value, ast.Name)
        assert isinstance(annotation.slice, ast.Name)
        fields[item.target.id] = (annotation.value.id, annotation.slice.id)
    return fields


@seed_params
class TestStubTablePairing:
    def test_stub_and_table_declare_the_same_attributes(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stub_attrs = set(stub_fields(module))
        table_attrs = set(cls._table_)
        assert stub_attrs - table_attrs == set(), "stub declares fields missing from _table_"
        assert table_attrs - stub_attrs == set(), "_table_ has fields missing from the stub"

    def test_multiplicity_matches_descriptor_class(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stubs = stub_fields(module)
        for attr, (_, _, multi) in cls._table_.items():
            expected = "MultiField" if multi else "Field"
            declared = stubs[attr][0]
            assert declared == expected, f"{attr}: multi={multi} but stub says {declared}"

    def test_stub_inner_type_matches_ftype(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stubs = stub_fields(module)
        for attr, (_, ftype, _) in cls._table_.items():
            expected = values.get_info(ftype).py_type.__name__
            assert stubs[attr][1] == expected, f"{attr}: {ftype} parses to {expected}"

    def test_every_ftype_is_known(self, module: ModuleType, cls: type[ProtocolBase]) -> None:
        for attr, (_, ftype, _) in cls._table_.items():
            assert ftype in values.FTYPE_TABLE, f"{attr}: unknown ftype {ftype!r}"

    def test_attr_names_follow_seed_naming_convention(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        """The hand-written seeds derive attrs as dots-to-underscores (typo guard).

        This is a convention of the seed modules only, not part of the frozen
        compact-table format: ``_meta.py`` stores the full tshark name precisely
        so that generated modules (issue #14) may deviate, e.g. to escape Python
        keywords (``*.class`` cannot flatten to ``class``). When the M2 emitter
        replaces the seeds, its output encodes whatever rule it adopts.
        """
        prefix = f"{cls._proto_}."
        for attr, (tshark_name, _, _) in cls._table_.items():
            assert tshark_name.startswith(prefix), f"{attr}: {tshark_name!r} lacks {prefix!r}"
            derived = tshark_name.removeprefix(prefix).replace(".", "_")
            assert attr == derived, f"{attr!r} != derived {derived!r}"

    def test_proto_matches_module_name(self, module: ModuleType, cls: type[ProtocolBase]) -> None:
        assert module.__name__.rsplit(".", 1)[-1] == cls._proto_


P = TypeVar("P", bound=ProtocolBase)


class FullFakePacket:
    """Packet test double: raw access plus ``pkt[Proto]`` typed views."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())

    def __getitem__(self, proto: type[P]) -> P:
        return proto(self)


def check_packet_protocol_typing(pkt: Packet) -> None:
    """Static half of the ``pkt[TCP]`` acceptance criterion; body checked by mypy."""
    assert_type(pkt[TCP].srcport, int | None)
    assert_type(pkt[IP].src, IPv4Address | None)
    assert_type(pkt[TCP].port, tuple[int, ...])


class TestAcceptance:
    """Runtime + static checks for the issue #13 acceptance criteria."""

    def test_ip_src_class_access_is_field_ref(self) -> None:
        ref = IP.src
        assert isinstance(ref, FieldRef)
        assert ref.name == "ip.src"
        assert ref.ftype == "FT_IPv4"
        assert_type(IP.src, FieldRef[IPv4Address])

    def test_ip_instance_access_parses_or_none(self) -> None:
        view = IP(FakePacket({"ip.src": ("10.0.0.1",)}))
        assert_type(view.src, IPv4Address | None)
        assert view.src == IPv4Address("10.0.0.1")
        assert view.dst is None

    def test_tcp_port_is_multi_valued(self) -> None:
        view = TCP(FakePacket({"tcp.port": ("443", "51234")}))
        assert_type(view.port, tuple[int, ...])
        assert view.port == (443, 51234)
        assert TCP(FakePacket({})).port == ()

    def test_tcp_port_comparison_builds_expr(self) -> None:
        e = TCP.port == 443
        assert isinstance(e, Comparison)
        assert e.field.name == "tcp.port"
        assert_type(e, Comparison)

    def test_dns_answers_are_tuples(self) -> None:
        view = DNS(FakePacket({"dns.a": ("1.2.3.4", "5.6.7.8")}))
        assert view.a == (IPv4Address("1.2.3.4"), IPv4Address("5.6.7.8"))

    def test_packet_view_access(self) -> None:
        pkt = FullFakePacket({"tcp.srcport": ("443",)})
        view = pkt[TCP]
        assert_type(view.srcport, int | None)
        assert view.srcport == 443
        check_packet_protocol_typing(cast(Packet, pkt))
