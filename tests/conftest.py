"""Shared test doubles and the CI dependency guard for the remora test suite."""

from __future__ import annotations

import importlib
import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Refuse to run at all when a CI-required optional dependency is missing.

    duckdb ships as the optional ``remora[workspace]`` extra, so every workspace
    module skips cleanly without it — which is right locally and wrong in CI,
    where a broken install would silently skip the whole M4 suite instead of
    failing. ``REMORA_REQUIRE_DUCKDB`` (set in .github/workflows/ci.yml, beside
    ``REMORA_REQUIRE_TSHARK``) turns that skip into a hard stop here, once, for
    every workspace test rather than only the ones that remember to check.

    The check is a real ``import``, not ``find_spec``: a spec proves the module
    can be *found*, and every suite this guards skips on ``importorskip``, which
    fires when the module cannot be *imported*. A duckdb whose wheel is present
    but whose native library will not load therefore satisfies ``find_spec`` and
    skips every workspace suite — precisely the silent-skip this exists to
    refuse. Importing it here is also what the run is about to do anyway.
    """
    if not os.environ.get("REMORA_REQUIRE_DUCKDB"):
        return
    try:
        importlib.import_module("duckdb")
    except ImportError as error:
        raise pytest.UsageError(
            f"REMORA_REQUIRE_DUCKDB is set but duckdb is not importable ({error}); "
            "install it with: pip install 'remora[workspace]'"
        ) from error


class FakePacket:
    """Minimal RawPacket test double: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())
