"""Field descriptors, field references, and the packet access contracts.

This module is the contract hub between the expression IR (:mod:`remora.expr`),
the readers, the predicate backend, and the protocol classes:

- :class:`RawPacket` is the minimal packet contract — ``get_raw(name)`` returns
  raw string occurrences, with ``()`` meaning *absent*.
- :class:`FieldRef` is the class-access handle for a field; its comparison
  operators (inherited from :class:`remora.expr.FieldExprOps`) build ``Expr``
  trees. It satisfies :class:`remora.expr.FieldLike` structurally.
- :class:`Field` / :class:`MultiField` are the dual-mode descriptors
  (architecture decision): class access ``IP.src`` yields a
  ``FieldRef[IPv4Address]`` for building expressions; instance access
  ``pkt[IP].src`` yields the parsed value — ``T | None`` for scalar fields,
  ``tuple[T, ...]`` for multi-occurrence fields (``()`` when absent).

Multiplicity lives in the descriptor *class* (two classes rather than a flag)
because it changes the instance-access return type, which ``@overload`` can
only express per class.
"""

from __future__ import annotations

from typing import Any, Generic, Protocol, TypeVar, overload, runtime_checkable

from remora import values as _values
from remora.expr import FieldExprOps

__all__ = [
    "Field",
    "FieldNotProjectedError",
    "FieldRef",
    "MultiField",
    "Packet",
    "PacketCarrier",
    "RawPacket",
]

T = TypeVar("T")
P = TypeVar("P")


class FieldNotProjectedError(KeyError):
    """A fields-mode row was asked for a field outside its projection.

    Raised only by projection-limited packets (the ``-T fields`` reader);
    ek-mode packets never raise — an unknown field is simply absent (``()``).
    """


@runtime_checkable
class RawPacket(Protocol):
    """Minimal packet contract consumed by descriptors and the predicate backend.

    ``get_raw`` returns the RAW STRING occurrences of a field, in wire order:

    - absent field          -> ``()``  (this is how ``None`` is modeled)
    - present, single value -> ``("value",)``
    - present, multi-value  -> ``("v1", "v2")``
    """

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        """Raw string occurrences of *field_name* in wire order (``()`` if absent)."""
        ...


class Packet(RawPacket, Protocol):
    """Full user-facing packet: raw access plus typed protocol views.

    ``pkt[IP]`` returns an instance of the protocol class itself, so the
    stub-declared descriptors type instance access naturally.
    """

    def __getitem__(self, proto: type[P]) -> P: ...


class PacketCarrier(Protocol):
    """Anything holding a raw packet under ``_remora_packet``.

    Protocol *instances* (built by ``ProtocolBase``, issue #11) satisfy this;
    descriptors use it for instance-mode ``__get__`` without importing the
    metaclass module (which imports this one).
    """

    _remora_packet: RawPacket


class FieldRef(FieldExprOps, Generic[T]):
    """Class-access handle for one tshark field; builds ``Expr`` on comparison.

    The comparison operators, ``present()``, and ``__hash__`` (by field name)
    come from :class:`FieldExprOps`, so expression semantics live in one place.
    ``T`` is the parsed Python type carried for static typing only.
    """

    __slots__ = ("_ftype", "_multi", "_name")

    def __init__(self, name: str, ftype: str, multi: bool) -> None:
        self._name = name
        self._ftype = ftype
        self._multi = multi

    @property
    def name(self) -> str:
        """Canonical tshark field name, e.g. ``"ip.src"``."""
        return self._name

    @property
    def ftype(self) -> str:
        """The tshark field type name, e.g. ``"FT_IPv4"``."""
        return self._ftype

    @property
    def multi(self) -> bool:
        """True if the field can occur multiple times per packet."""
        return self._multi

    def __repr__(self) -> str:
        multi = ", multi" if self._multi else ""
        return f"<FieldRef {self._name} ({self._ftype}{multi})>"


class _FieldBase(Generic[T]):
    """Shared plumbing for the two descriptor classes."""

    __slots__ = ("_parse", "ref")

    def __init__(self, ref: FieldRef[T]) -> None:
        self.ref = ref
        self._parse = _values.get_info(ref.ftype).parse

    def _raw(self, obj: PacketCarrier) -> tuple[str, ...]:
        return obj._remora_packet.get_raw(self.ref.name)


class Field(_FieldBase[T]):
    """Scalar field descriptor: dual-mode ``__get__``.

    Class access returns the :class:`FieldRef`; instance access returns the
    parsed value or ``None`` when the field is absent. A ref declared
    ``multi=True`` is rejected at construction — silently keeping only the
    first occurrence would drop data; declare such fields with
    :class:`MultiField`. (Unexpected extra occurrences of a scalar-declared
    field at runtime still resolve to the first one.)
    """

    __slots__ = ()

    def __init__(self, ref: FieldRef[T]) -> None:
        if ref.multi:
            raise ValueError(
                f"field {ref.name!r} is multi-valued; declare it with MultiField, "
                "not Field (a scalar view would silently drop occurrences)"
            )
        super().__init__(ref)

    @overload
    def __get__(self, obj: None, objtype: type[Any]) -> FieldRef[T]: ...

    @overload
    def __get__(self, obj: PacketCarrier, objtype: type[Any] | None = None) -> T | None: ...

    def __get__(
        self, obj: PacketCarrier | None, objtype: type[Any] | None = None
    ) -> FieldRef[T] | T | None:
        if obj is None:
            return self.ref
        raws = self._raw(obj)
        if not raws:
            return None
        parsed: T = self._parse(raws[0])
        return parsed


class MultiField(_FieldBase[T]):
    """Multi-occurrence field descriptor: instance access yields ``tuple[T, ...]``.

    An absent field is the empty tuple, so iteration and ``in`` checks work
    without a ``None`` guard.
    """

    __slots__ = ()

    @overload
    def __get__(self, obj: None, objtype: type[Any]) -> FieldRef[T]: ...

    @overload
    def __get__(self, obj: PacketCarrier, objtype: type[Any] | None = None) -> tuple[T, ...]: ...

    def __get__(
        self, obj: PacketCarrier | None, objtype: type[Any] | None = None
    ) -> FieldRef[T] | tuple[T, ...]:
        if obj is None:
            return self.ref
        return tuple(self._parse(raw) for raw in self._raw(obj))
