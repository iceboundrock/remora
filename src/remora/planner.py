r"""Two-level pushdown query planner.

Architecture decision: pushable conjuncts become a ``-Y`` display filter;
when the query's field set is statically known the reader projects with
``-T fields``; opaque lambdas force the ``-T ek`` fallback. This module only
*decides* — it executes nothing and never spawns tshark.

Planning algorithm
------------------
1. Every :class:`~remora.expr.Expr` term is flattened through
   :func:`~remora.expr.conjuncts` (so one ``(a) & (b)`` term equals two
   terms); anything that is not an ``Expr`` is an opaque callable and goes
   straight to the residual.
2. Each ``Expr`` conjunct is tried against the display-filter backend. On
   success it is *pushed* (tshark will filter on it); on
   :class:`~remora.compile.dfilter.UnsupportedExprError` it becomes a
   residual ``Expr``, compiled with the Python predicate backend. User
   errors — malformed literals raising ``ValueError``/``TypeError`` — are
   deliberately NOT caught; they surface from :func:`make_plan`.
3. ``dfilter`` joins the pushed strings with ``&&`` (each parenthesized);
   ``None`` when nothing was pushed.
4. ``residual`` is the short-circuit AND-composition of two groups, each in
   original order: first every residual-``Expr`` predicate, then every opaque
   callable — cheap compiled predicates run before arbitrary user lambdas
   regardless of how the terms were interleaved. ``None`` when there are none.
5. Mode: ``"ek"`` if any opaque callable is present OR ``select`` is None
   (M1's Capture has no projection API yet, so the consumer may access
   arbitrary fields); otherwise ``"fields"`` with a projection of the
   selected fields plus the fields referenced by residual ``Expr``\s,
   deduplicated by field name (select order first, then residual-field
   order). Fields of *pushed* conjuncts are not projected — tshark already
   filtered on them — unless they are also selected: no over-projection.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr, conjuncts, field_refs
from remora.fields import FieldRef, RawPacket

__all__ = ["Mode", "Plan", "QueryTerm", "make_plan"]

QueryTerm: TypeAlias = Expr | Callable[[RawPacket], bool]
Mode: TypeAlias = Literal["fields", "ek"]


class _AndResidual:
    """AND-composition of residual predicates: short-circuit, left-to-right."""

    __slots__ = ("_predicates",)

    def __init__(self, predicates: tuple[Callable[[RawPacket], bool], ...]) -> None:
        self._predicates = predicates

    @property
    def conjunct_count(self) -> int:
        return len(self._predicates)

    def __call__(self, packet: RawPacket) -> bool:
        return all(predicate(packet) for predicate in self._predicates)


def _residual_conjuncts(residual: Callable[[RawPacket], bool]) -> int:
    """Number of conjuncts a residual composes (1 for a bare callable)."""
    if isinstance(residual, _AndResidual):
        return residual.conjunct_count
    return 1


@dataclass(frozen=True, eq=False, slots=True)
class Plan:
    """Inspectable output of :func:`make_plan` — decisions only, no execution."""

    dfilter: str | None
    """``-Y`` display-filter string; None if nothing was pushed down."""

    mode: Mode
    """Reader mode: ``"fields"`` (``-T fields`` projection) or ``"ek"``."""

    projection: tuple[FieldRef[Any], ...] | None
    """Fields the reader must emit; None iff ``mode == "ek"``."""

    residual: Callable[[RawPacket], bool] | None
    """Python-side predicate for what could not be pushed; None if everything
    was pushed."""

    def explain(self) -> str:
        """Readable multi-line description of the plan."""
        lines = [
            f"mode: {self.mode}",
            f"dfilter (-Y): {self.dfilter if self.dfilter is not None else '(none)'}",
        ]
        if self.projection is None:
            lines.append("projection: (all fields — ek mode)")
        else:
            names = ", ".join(ref.name for ref in self.projection)
            lines.append(f"projection: {names if names else '(no fields)'}")
        if self.residual is None:
            lines.append("residual: none")
        else:
            lines.append(f"residual: {_residual_conjuncts(self.residual)} conjunct(s)")
        return "\n".join(lines)

    def __repr__(self) -> str:
        dfilter = "none" if self.dfilter is None else repr(self.dfilter)
        if self.projection is None:
            projection = "all"
        else:
            projection = "[{}]".format(", ".join(ref.name for ref in self.projection))
        residual = (
            "none" if self.residual is None else f"{_residual_conjuncts(self.residual)} conjunct(s)"
        )
        return (
            f"<Plan mode={self.mode} dfilter={dfilter} projection={projection} residual={residual}>"
        )


def make_plan(
    terms: Sequence[QueryTerm],
    *,
    select: Sequence[FieldRef[Any]] | None = None,
) -> Plan:
    """Plan a query: split ``terms`` into pushed-down and residual parts.

    ``terms`` are AND-ed together. ``select`` is the statically known field
    set the consumer will read, or None when unknown (forces ek mode).

    User errors (malformed literals such as ``IP.src == "not-an-ip"``) raise
    ``ValueError``/``TypeError`` here — only
    :class:`~remora.compile.dfilter.UnsupportedExprError` routes a conjunct
    to the residual.
    """
    pushed: list[str] = []
    residual_exprs: list[Expr] = []
    opaque: list[Callable[[RawPacket], bool]] = []

    for term in terms:
        if not isinstance(term, Expr):
            if not callable(term):
                raise TypeError(
                    f"query term must be an Expr or a callable predicate, not {type(term).__name__}"
                )
            opaque.append(term)
            continue
        for conjunct in conjuncts(term):
            try:
                pushed.append(compile_dfilter(conjunct))
            except UnsupportedExprError:
                residual_exprs.append(conjunct)

    dfilter = " && ".join(f"({clause})" for clause in pushed) if pushed else None

    predicates: list[Callable[[RawPacket], bool]] = [
        compile_predicate(expr) for expr in residual_exprs
    ]
    predicates.extend(opaque)
    residual = _AndResidual(tuple(predicates)) if predicates else None

    if opaque or select is None:
        return Plan(dfilter=dfilter, mode="ek", projection=None, residual=residual)

    projected: dict[str, FieldRef[Any]] = {}
    for ref in select:
        projected.setdefault(ref.name, ref)
    for expr in residual_exprs:
        for field in field_refs(expr):
            # field_refs yields the FieldLike protocol; normalize to a real
            # FieldRef from its metadata so any structural FieldLike is safe
            # in the projection. Dedup is by name (FieldRef is unhashable).
            if field.name not in projected:
                projected[field.name] = FieldRef(field.name, field.ftype, field.multi)
    return Plan(
        dfilter=dfilter,
        mode="fields",
        projection=tuple(projected.values()),
        residual=residual,
    )
