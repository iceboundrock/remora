"""Shared test doubles and the CI dependency guard for the remora test suite."""

from __future__ import annotations

import importlib.util
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
    """
    if os.environ.get("REMORA_REQUIRE_DUCKDB") and importlib.util.find_spec("duckdb") is None:
        raise pytest.UsageError(
            "REMORA_REQUIRE_DUCKDB is set but duckdb is not importable; "
            "install it with: pip install 'remora[workspace]'"
        )


class FakePacket:
    """Minimal RawPacket test double: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())
