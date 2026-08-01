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
from types import ModuleType

import pytest

from remora import values
from remora.proto import eth as eth_mod
from remora.proto._meta import ProtocolBase

SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
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

    def test_attr_names_derive_from_tshark_names(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        prefix = f"{cls._proto_}."
        for attr, (tshark_name, _, _) in cls._table_.items():
            assert tshark_name.startswith(prefix), f"{attr}: {tshark_name!r} lacks {prefix!r}"
            derived = tshark_name.removeprefix(prefix).replace(".", "_")
            assert attr == derived, f"{attr!r} != derived {derived!r}"

    def test_proto_matches_module_name(self, module: ModuleType, cls: type[ProtocolBase]) -> None:
        assert module.__name__.rsplit(".", 1)[-1] == cls._proto_
