"""The public Capture query surface: the M1 end-to-end tracer bullet.

``Capture`` wires the pieces together: ``.filter()`` accumulates query terms
into an immutable builder; iteration plans the query
(:func:`remora.planner.make_plan`), assembles a tshark argv, spawns a
:class:`~remora.reader.process.TsharkProcess`, wraps its stdout in the
mode-appropriate reader, and yields packets that pass the residual predicate.

``select()`` is the projection API (#105), and it is what makes the planner's
``-T fields`` branch reachable from the public surface: a ``Capture`` carrying
a projection plans to fields mode, where tshark renders only the named columns,
instead of the ``-T ek`` whole-packet NDJSON a bare ``Capture`` falls back to.
Without a projection ``plan()`` passes ``select=None`` and the plan is ek-mode,
which is also what an opaque callable term forces regardless of any projection
— nothing bounds the fields an arbitrary lambda reads, so it must be handed all
of them.

The two modes differ in exactly one observable way, and it is deliberate: a
field *outside* a fields-mode projection raises ``FieldNotProjectedError``,
because not having asked for a field is a caller bug rather than field absence,
while ek mode has no projection to be outside of and answers every field name.
Absence itself is unchanged either way — ``()`` from ``get_raw``, ``None`` from
scalar instance access, ``()`` from multi instance access.

Lifecycle: the ``try/finally`` in ``__iter__`` guarantees ``close()`` on the
subprocess however iteration ends — exhaustion, early ``break``, a consumer
exception, or the generator being GC'd — so no tshark orphans outlive a query.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeAlias, cast

from remora.expr import Expr
from remora.fields import FieldRef, Packet
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

    ``filter()`` and ``select()`` each return a NEW ``Capture`` with the terms
    or fields appended (the original is unchanged), so partial queries can be
    shared and extended. Iteration executes the query: each ``for`` loop spawns
    a fresh tshark subprocess and yields packets supporting ``pkt[IP].src``
    typed access.

    A ``Capture`` with no ``select()`` reads whole packets (``-T ek``) and so
    answers any field name; one carrying a projection reads only its columns
    (``-T fields``) and raises ``FieldNotProjectedError`` for anything else.
    See :meth:`select` and the module docstring for why that is the one
    difference between the two modes.

    "Immutable" is about the *query*: the terms, the path and the binary
    never change after construction. The one mutable field is a memo —
    :meth:`_resolved_tshark_version` caches the `tshark --version` probe on
    first fields-mode use, so a `Capture` reused across loops probes once
    rather than per iteration. It is unobservable through the public API (the
    probe is deterministic for a given binary, and an explicit
    ``tshark_version=`` skips it entirely), which is why it does not make the
    object stateful in any sense a caller has to reason about.

    Not thread-safe, and no more so because of that memo: two threads racing
    the first iteration may both probe, then store the same answer. Nothing
    else here is synchronized either, so share a `Capture` across threads
    only if you would have anyway.
    """

    __slots__ = ("_path", "_select", "_terms", "_tshark", "_tshark_version", "_version_known")

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
        self._select: tuple[FieldRef[Any], ...] = ()
        # Only consulted in fields mode, to decide whether tshark's value
        # escaping can be inverted (see fields_reader's module docstring).
        # Passing it explicitly skips the probe; leaving it None probes once,
        # lazily, and only if a fields-mode plan actually runs.
        self._tshark_version = tshark_version
        self._version_known = tshark_version is not None

    def _clone(
        self, terms: tuple[CaptureFilter, ...], select: tuple[FieldRef[Any], ...]
    ) -> Capture:
        """A new ``Capture`` on this pcap carrying *terms* and *select*."""
        clone = Capture(self._path, tshark=self._tshark)
        clone._terms = terms
        clone._select = select
        # Carry the probe across the clone so a chain of filter()/select()
        # calls probes at most once; an explicit version is carried likewise.
        clone._tshark_version = self._tshark_version
        clone._version_known = self._version_known
        return clone

    def filter(self, *terms: CaptureFilter) -> Capture:
        """A new ``Capture`` with *terms* AND-ed onto the existing ones."""
        return self._clone(self._terms + terms, self._select)

    def select(self, *fields: FieldRef[Any]) -> Capture:
        """A new ``Capture`` projecting *fields* on top of those already chosen.

        A ``Capture`` carrying a projection plans to ``-T fields``, so tshark
        renders only the named columns rather than every field of every packet
        as ``-T ek`` NDJSON. Fields a *residual* ``Expr`` needs are added to the
        projection by the planner, so a projection only has to name what the
        consumer itself reads — and fields of a *pushed* conjunct are not
        projected at all unless selected, since tshark has already filtered on
        them.

        Two things do not follow from calling this, both by planner design
        (:func:`remora.planner.make_plan`) rather than by anything decided here:

        * an opaque callable term still forces ek mode, projection or not.
          Nothing can bound the fields an arbitrary lambda reads, so the
          planner must hand it all of them; a projection alongside one is
          honoured as far as it can be (every named field is readable) but
          buys no ``-T fields`` run. ``plan().mode`` says which happened.
        * ``select()`` with no arguments is a no-op rather than "project
          nothing". An empty projection and no projection at all are one
          state, and that state means ek mode — ``-T fields`` with no ``-e``
          is a degenerate argv emitting blank lines, so it stays unreachable
          by construction rather than by a check.

        Args:
            fields: Class-access field references, e.g. ``IP.src``. Duplicates
                of one field name collapse, and the projection keeps the order
                fields were first named in.

        Returns:
            A new :class:`Capture`; this one is unchanged.
        """
        return self._clone(self._terms, self._select + fields)

    def _resolved_tshark_version(self) -> str | None:
        """The binary's version, probed at most once per ``Capture``.

        This is the memo the class docstring carves out of "immutable": it
        writes ``_tshark_version``/``_version_known`` on first call. The
        probe never raises (see :func:`probe_tshark_version`), so a failure
        memoizes ``None`` — the conservative answer — rather than retrying
        a broken binary on every iteration.
        """
        if not self._version_known:
            self._tshark_version = probe_tshark_version(self._tshark)
            self._version_known = True
        return self._tshark_version

    def plan(self) -> Plan:
        """The query plan iteration would execute (inspectable, side-effect free)."""
        # A residual lambda only ever runs in ek mode (opaque terms force it),
        # where every packet satisfies the full Packet protocol — so widening
        # the callable's parameter from Packet to RawPacket here is sound.
        #
        # `or None` is the whole no-projection/empty-projection identification:
        # make_plan reads None as "the consumer may read any field" and returns
        # an ek plan, which is exactly what an unselected Capture means.
        return make_plan(cast("tuple[QueryTerm, ...]", self._terms), select=self._select or None)

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
        projection = "all" if not self._select else ", ".join(ref.name for ref in self._select)
        return f"<Capture {str(self._path)!r} terms={len(self._terms)} select={projection}>"
