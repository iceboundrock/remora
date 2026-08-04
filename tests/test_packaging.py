"""Core/extras packaging (issue #22): import UX for extras-only protocols."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

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
    with pytest.raises(AttributeError, match=r"module 'remora\.proto' has no attribute 'NOPE'"):
        _ = remora.proto.NOPE


def test_misspelled_case_is_not_an_extras_lookup() -> None:
    """Only ``wlan`` and ``WLAN`` resolve; other spellings are typos, not extras."""
    with pytest.raises(AttributeError, match=r"has no attribute 'Wlan'"):
        _ = remora.proto.Wlan


def test_extras_merge_when_packages_src_on_path() -> None:
    """extend_path merges an extras source root into remora.proto (issue #22)."""
    repo = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(repo / "src"), str(repo / "packages/remora-wireless/src")]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import remora.proto; cls = remora.proto.WLAN; "
            "assert cls._proto_ == 'wlan', cls; "
            "from remora.proto import wlan; assert cls is wlan.WLAN",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
