"""Core/extras packaging (issue #22): import UX for extras-only protocols."""

from __future__ import annotations

import importlib

import pytest

import remora.proto
from remora.proto._extras import EXTRAS_MODULES


def test_extras_map_has_the_seed_assignments() -> None:
    assert EXTRAS_MODULES["wlan"] == "wireless"
    assert EXTRAS_MODULES["dnp3"] == "industrial"
    assert EXTRAS_MODULES["diameter"] == "telecom"


def test_missing_extra_raises_naming_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import_module = importlib.import_module

    def fake_import_module(name: str, package: str | None = None) -> object:
        if name == "remora.proto.wlan":
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    with pytest.raises(ImportError, match=r"pip install 'remora\[wireless\]'"):
        _ = remora.proto.WLAN


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError):
        _ = remora.proto.NOPE
