"""Shared test doubles for the remora test suite."""

from __future__ import annotations


class FakePacket:
    """Minimal RawPacket test double: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())
