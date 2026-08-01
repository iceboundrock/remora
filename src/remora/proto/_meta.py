"""Protocol metaclass with lazy field materialization.

Some protocols declare tens of thousands of fields. Architecture decision:
protocol classes carry only a compact runtime table (attribute name ->
``(tshark_name, ftype, multi)``); a :class:`~remora.fields.Field` /
:class:`~remora.fields.MultiField` descriptor is constructed on *first
access* via :meth:`ProtocolMeta.__getattr__` and cached in the class dict, so
importing a generated module does no per-field work and costs nothing until a
field is actually touched.

Two lookup paths need care:

- **Class access** (``IP.src``): missing attributes reach the *metaclass*
  ``__getattr__``, which materializes the descriptor, caches it with
  ``setattr``, and returns descriptor ``__get__(None, cls)`` — a ``FieldRef``.
  Subsequent accesses hit the cached descriptor directly; the metaclass hook
  never fires again for that name.
- **Instance access** (``pkt[IP].src``): the metaclass is *not* consulted for
  instance attributes, so :class:`ProtocolBase` defines its own
  ``__getattr__`` that forces class-level materialization and then re-invokes
  the descriptor in instance mode.

The table format is frozen: it is exactly what the code generator (issue #14)
will emit, and what the hand-written seed modules (issue #13) follow.
Attribute names may differ from tshark names (``dns.qry.name`` -> attribute
``qry_name``), which is why the full tshark name is stored rather than
derived.
"""

from __future__ import annotations

from typing import Any, ClassVar

from remora.fields import Field, FieldRef, MultiField, RawPacket

__all__ = ["FieldSpec", "FieldTable", "ProtocolBase", "ProtocolMeta"]

#: One field's metadata: (tshark_name, ftype, multi) — e.g. ("ip.src", "FT_IPv4", 0).
#: ``multi`` is 0/1 rather than bool to keep generated tables compact and dumb.
FieldSpec = tuple[str, str, int]

#: Attribute name -> spec. Plain dict in generated/seed modules.
FieldTable = dict[str, FieldSpec]


class ProtocolMeta(type):
    """Materializes ``Field``/``MultiField`` descriptors lazily from ``_table_``."""

    def __getattr__(cls, name: str) -> Any:
        # Underscore names are reserved (``_proto_``, ``_table_``, dunders) and
        # never field attributes; refusing them here also breaks the recursion
        # that would occur looking up ``_table_`` on a class that lacks it.
        if name.startswith("_"):
            raise AttributeError(f"protocol {cls.__name__!r} has no attribute {name!r}")
        # _table_ resolves via normal MRO lookup; ProtocolBase defaults it to
        # an empty table. (A subclass that sets its own _table_ replaces the
        # parent's — tables are whole-class data, not merged.)
        table: FieldTable = cls._table_
        spec = table.get(name)
        if spec is None:
            raise AttributeError(f"protocol {cls.__name__!r} has no field {name!r}")
        tshark_name, ftype, multi = spec
        ref: FieldRef[Any] = FieldRef(tshark_name, ftype, bool(multi))
        descriptor = MultiField(ref) if multi else Field(ref)
        # Cache in the class dict: every later access — class or instance —
        # takes the normal descriptor path without re-entering this hook.
        setattr(cls, name, descriptor)
        return descriptor.__get__(None, cls)

    def __dir__(cls) -> list[str]:
        """List all table fields without materializing any descriptor."""
        table: FieldTable = cls._table_
        return sorted(set(super().__dir__()) | table.keys())


class ProtocolBase(metaclass=ProtocolMeta):
    """Base class for protocol classes; instances are per-packet views.

    Subclasses set ``_proto_`` (tshark layer name) and ``_table_`` (the
    compact field table). ``SomeProto(packet)`` binds a
    :class:`~remora.fields.RawPacket`; attribute access then follows the
    dual-mode descriptor contract from :mod:`remora.fields`.
    """

    _proto_: ClassVar[str] = ""
    _table_: ClassVar[FieldTable] = {}

    __slots__ = ("_remora_packet",)

    def __init__(self, packet: RawPacket) -> None:
        self._remora_packet = packet

    def __getattr__(self, name: str) -> Any:
        # Reached only when normal lookup fails, i.e. the descriptor is not
        # materialized yet. Trigger class-level materialization (which raises
        # AttributeError for unknown names), then run the now-cached
        # descriptor in instance mode.
        getattr(type(self), name)
        for klass in type(self).__mro__:
            descriptor = klass.__dict__.get(name)
            if descriptor is not None:
                get = descriptor.__get__
                result: Any = get(self, type(self))
                return result
        raise AttributeError(  # pragma: no cover - materialization always caches
            f"protocol {type(self).__name__!r} has no field {name!r}"
        )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} view of {self._remora_packet!r}>"
