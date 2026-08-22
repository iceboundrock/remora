"""The public Capture query surface: the M1 end-to-end tracer bullet.

``Capture`` wires the pieces together: ``.filter()`` accumulates query terms
into an immutable builder; iteration plans the query
(:func:`remora.planner.make_plan`), assembles a tshark argv, spawns a
:class:`~remora.reader.process.TsharkProcess`, wraps its stdout in the
mode-appropriate reader, and yields packets that pass the residual predicate.

M1 has no projection API, so ``plan()`` is always called with ``select=None``
and live plans are always ek-mode; the fields-mode execution branch below is
what the planner emits once a select/projection API exists, and is covered by
unit tests injecting a fields-mode plan.

Lifecycle: the ``try/finally`` in ``__iter__`` guarantees ``close()`` on the
subprocess however iteration ends — exhaustion, early ``break``, a consumer
exception, or the generator being GC'd — so no tshark orphans outlive a query.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeAlias, cast

from remora.expr import Expr
from remora.fields import Packet
from remora.planner import Plan, QueryTerm, make_plan
from remora.reader.ek_reader import EkReader, ek_argv
from remora.reader.fields_reader import FieldsReader, escaping_is_reversible, fields_argv
from remora.reader.process import TsharkProcess, probe_tshark_version

__all__ = ["Capture", "CaptureFilter"]

#: A query term: an ``Expr`` built from field comparisons, or an opaque
#: predicate over the full packet. Opaque callables receive ``Packet`` (not
#: bare ``RawPacket``): they only ever run in ek mode, whose packets support
#: ``pkt[Proto]`` views.
CaptureFilter: TypeAlias = Expr | Callable[[Packet], bool]


def _resolve_tshark(explicit: str | None) -> str:
    """Resolve the tshark binary: explicit arg, then $TSHARK, then PATH."""
    if explicit is not None:
        return explicit
    return os.environ.get("TSHARK") or "tshark"


def _build_argv(tshark: str, path: Path, plan: Plan) -> list[str]:
    """Assemble the full tshark argv for *plan* over the pcap at *path*."""
    argv = [tshark, "-r", str(path)]
    if plan.dfilter is not None:
        argv += ["-Y", plan.dfilter]
    if plan.mode == "fields":
        assert plan.projection is not None  # Plan invariant: fields => projection
        argv += fields_argv(plan.projection)
    else:
        argv += ek_argv()
    return argv


class Capture:
    """A lazily-executed, immutable query over one pcap file.

    ``filter()`` returns a NEW ``Capture`` with the terms appended (the
    original is unchanged), so partial queries can be shared and extended.
    Iteration executes the query: each ``for`` loop spawns a fresh tshark
    subprocess and yields packets supporting ``pkt[IP].src`` typed access.
    """

    __slots__ = ("_path", "_terms", "_tshark", "_tshark_version", "_version_known")

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        tshark: str | None = None,
        tshark_version: str | None = None,
    ) -> None:
        self._path = Path(path)
        self._tshark = _resolve_tshark(tshark)
        self._terms: tuple[CaptureFilter, ...] = ()
        # Only consulted in fields mode, to decide whether tshark's value
        # escaping can be inverted (see fields_reader's module docstring).
        # Passing it explicitly skips the probe; leaving it None probes once,
        # lazily, and only if a fields-mode plan actually runs.
        self._tshark_version = tshark_version
        self._version_known = tshark_version is not None

    def filter(self, *terms: CaptureFilter) -> Capture:
        """A new ``Capture`` with *terms* AND-ed onto the existing ones."""
        clone = Capture(self._path, tshark=self._tshark)
        clone._terms = self._terms + terms
        # Carry the probe across the clone so a filter chain probes at most
        # once; an explicit version is carried for the same reason.
        clone._tshark_version = self._tshark_version
        clone._version_known = self._version_known
        return clone

    def _resolved_tshark_version(self) -> str | None:
        """The binary's version, probed at most once per ``Capture``."""
        if not self._version_known:
            self._tshark_version = probe_tshark_version(self._tshark)
            self._version_known = True
        return self._tshark_version

    def plan(self) -> Plan:
        """The query plan iteration would execute (inspectable, side-effect free)."""
        # A residual lambda only ever runs in ek mode (opaque terms force it),
        # where every packet satisfies the full Packet protocol — so widening
        # the callable's parameter from Packet to RawPacket here is sound.
        return make_plan(cast("tuple[QueryTerm, ...]", self._terms), select=None)

    def __iter__(self) -> Iterator[Packet]:
        plan = self.plan()
        process = TsharkProcess(_build_argv(self._tshark, self._path, plan))
        try:
            reader: Iterator[Packet]
            if plan.mode == "fields":
                assert plan.projection is not None  # Plan invariant
                reader = iter(
                    FieldsReader(
                        process,
                        plan.projection,
                        unescape_values=escaping_is_reversible(self._resolved_tshark_version()),
                    )
                )
            else:
                reader = iter(EkReader(process))
            residual = plan.residual
            for packet in reader:
                if residual is None or residual(packet):
                    yield packet
        finally:
            process.close()

    def __repr__(self) -> str:
        return f"<Capture {str(self._path)!r} terms={len(self._terms)}>"
