"""The ``-T ek`` fallback reader: whole-packet materialization.

When a query contains an opaque lambda, the set of fields it needs cannot be
determined ahead of time, so the ``-T fields`` projection is impossible. Remora
then falls back to ``-T ek`` (newline-delimited JSON, one object per packet)
and materializes whole packets: :class:`EkPacket` stores the parsed ``layers``
dict and normalizes values to the shared :class:`~remora.fields.RawPacket`
raw-string-tuple contract lazily, on each ``get_raw`` call.

ek output format (verified against tshark 4.6.7)
------------------------------------------------
Each packet produces two lines: an index/action metadata line such as
``{"index":{"_index":"packets-2023-11-14"}}`` (skipped) and a data line
``{"timestamp": ..., "layers": {...}}``. Within ``layers``:

- **Key mapping**: field ``a.b.c`` of layer ``a`` appears in ``layers["a"]``
  under key ``"a_a_b_c"`` — the layer name, an underscore, then the full field
  name with dots replaced by underscores (e.g. ``ip.src`` ->
  ``layers["ip"]["ip_ip_src"]``, ``tcp.flags.syn`` ->
  ``layers["tcp"]["tcp_tcp_flags_syn"]``).
- **Scalars** are JSON strings — tshark 4.6 stringifies even numeric fields
  (``"ip_ip_ttl": "64"``). JSON numbers are still normalized defensively for
  other versions/configurations.
- **FT_BOOLEAN** fields are JSON ``true``/``false``.
- **Multi-occurrence** fields are JSON arrays in wire order
  (``"tcp_tcp_port": ["51234", "443"]``). Nested arrays were never observed;
  if one appears it is flattened recursively (defensive policy).
- **JSON null** appears on value-less generated fields (e.g.
  ``tcp.connection.syn`` inside expert info) — normalized to *absent*.
- **Nested dicts** hold subtree fields (e.g. ``layers["tcp"]["_ws_expert"]``
  contains ``"tcp_tcp_connection_syn"``), so a missing top-level key falls
  back to a depth-first search of nested dicts (and dicts inside arrays).

Values stay RAW STRINGS here — typed conversion happens downstream in the
descriptors / predicate backend via :mod:`remora.values`. Booleans normalize
to ``"1"``/``"0"``; note real ``-T fields`` output spells them
``"True"``/``"False"``, but ``values._parse_bool`` accepts both spellings, so
the two readers convert to identical Python values.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator
from typing import Any, TypeVar, cast

__all__ = ["EkPacket", "EkReader", "ek_argv"]

P = TypeVar("P")

#: Sentinel distinguishing "key absent" from a present JSON ``null``.
_MISSING: Any = object()


def ek_argv() -> list[str]:
    """tshark argv fragment selecting ek output: ``["-T", "ek"]``."""
    return ["-T", "ek"]


def _normalize(value: object) -> tuple[str, ...]:
    """Normalize one ek JSON value to the RawPacket raw-string-tuple contract."""
    if value is None:
        return ()
    # bool before int: bool is a subclass of int in Python.
    if isinstance(value, bool):
        return ("1",) if value else ("0",)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (int, float)):
        # str() of a JSON integer has no trailing ".0"; floats keep their form.
        return (str(value),)
    if isinstance(value, list):
        # Elements are strings in practice; recurse so an unobserved nested
        # array flattens instead of failing, and null elements vanish.
        return tuple(occurrence for element in value for occurrence in _normalize(element))
    # Nested dicts are subtree containers, not field values -> absent.
    return ()


def _find(container: dict[str, Any], key: str) -> object:
    """Depth-first lookup of ``key``: direct hit first, then nested dicts.

    Nested dicts (and dicts inside arrays) hold subtree fields such as expert
    info; a direct hit always wins. Returns ``_MISSING`` when absent.
    """
    if key in container:
        return container[key]
    for value in container.values():
        if isinstance(value, dict):
            found = _find(value, key)
            if found is not _MISSING:
                return found
        elif isinstance(value, list):
            for element in value:
                if isinstance(element, dict):
                    found = _find(element, key)
                    if found is not _MISSING:
                        return found
    return _MISSING


class EkPacket:
    """One parsed ek data line, satisfying the full Packet contract lazily.

    Stores the parsed ``layers`` dict as-is; ``get_raw`` maps field names to
    ek keys and normalizes values on demand. ek packets are complete (every
    dissected field is present in the JSON), so an unknown field is simply
    absent (``()``) — never :class:`~remora.fields.FieldNotProjectedError`.
    """

    __slots__ = ("_layers",)

    def __init__(self, layers: dict[str, Any]) -> None:
        self._layers = layers

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        """Raw string occurrences of ``field_name`` in wire order; ``()`` if absent."""
        layer_name = field_name.split(".", 1)[0]
        layer = self._layers.get(layer_name)
        if not isinstance(layer, dict):
            return ()
        key = layer_name + "_" + field_name.replace(".", "_")
        value = _find(layer, key)
        if value is _MISSING:
            return ()
        return _normalize(value)

    def __getitem__(self, proto: type[P]) -> P:
        """Typed protocol view: ``pkt[IP]`` returns ``IP(pkt)``."""
        # Protocol classes take the raw packet as their sole constructor
        # argument; type[P] alone cannot express that, hence the cast.
        ctor = cast("Callable[[EkPacket], P]", proto)
        return ctor(self)

    def __repr__(self) -> str:
        return f"<EkPacket layers={sorted(self._layers)}>"


class EkReader:
    """Iterate :class:`EkPacket` over raw ek stdout lines.

    ``lines`` is any iterable of already-decoded lines — typically a
    :class:`~remora.reader.process.TsharkProcess` — and is consumed lazily;
    iterating a second time re-iterates the underlying source (a one-shot
    source therefore yields nothing the second time).

    Index/action metadata lines (JSON objects without a ``"layers"`` key) and
    blank lines are skipped. Any other line that is not a JSON object with a
    ``"layers"`` dict raises :class:`ValueError` naming the 1-based line
    number — loud beats silent.
    """

    __slots__ = ("_lines",)

    def __init__(self, lines: Iterable[str]) -> None:
        self._lines = lines

    def __iter__(self) -> Iterator[EkPacket]:
        for lineno, line in enumerate(self._lines, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed ek JSON on line {lineno}: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(
                    f"malformed ek output on line {lineno}: expected a JSON object, "
                    f"got {type(obj).__name__}"
                )
            layers = obj.get("layers", _MISSING)
            if layers is _MISSING:
                continue  # index/action metadata line
            if not isinstance(layers, dict):
                raise ValueError(
                    f"malformed ek output on line {lineno}: 'layers' is not a JSON object"
                )
            yield EkPacket(layers)
