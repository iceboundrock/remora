"""Byte-for-byte reproducibility of the checked-in pcap fixtures (issue #20).

Loads tests/fixtures/make_fixtures.py by path (tests/ is not a package),
rebuilds each pcap in-process, and compares against the committed bytes.
Pure struct packing with fixed timestamps — no tshark needed, so this runs
in the regular (non-integration) suite.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "make_fixtures", FIXTURES_DIR / "make_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tcp_mixed_is_reproducible() -> None:
    generator = _load_generator()
    assert generator.build_tcp_mixed() == (FIXTURES_DIR / "tcp_mixed.pcap").read_bytes()


def test_dns_multi_is_reproducible() -> None:
    generator = _load_generator()
    assert generator.build_dns_multi() == (FIXTURES_DIR / "dns_multi.pcap").read_bytes()
