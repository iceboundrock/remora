"""Analyst annotations on packets and streams (issue #30).

Mutable analyst data — tagging packets and streams with findings — is one of
the reasons the workspace uses DuckDB native storage instead of immutable
Parquet: a finding is written back beside the packets it is about, and stays
queryable with plain SQL alongside them.

Record shape
------------
The layout's ``main.annotations`` table (#25) is used exactly as it stands —
no column is added, renamed or retyped, so ``SCHEMA_VERSION`` stays 1:

==================  ====================================================
Column              Holds
==================  ====================================================
``annotation_id``   Row key, assigned by :func:`add_annotation`.
``scope``           ``'packet'`` or ``'stream'`` (:data:`ANNOTATION_SCOPES`).
``target_id``       ``pkts.frame_number`` or ``streams.stream_id``.
``key``             Short label, e.g. ``'verdict'``. Never empty.
``value``           Free-form body, or ``NULL`` for a bare tag.
``created_at``      When the annotation was written (naive UTC).
==================  ====================================================

``annotation_id`` is assigned as ``max(annotation_id) + 1`` *inside the
caller's transaction* rather than from a sequence, because a sequence would
be a layout change no existing workspace could acquire — ``create_schema`` is
``IF NOT EXISTS``-only and an opener runs it only on an empty database, so a
workspace written before the sequence existed would never gain it. Like
``pkts.frame_number``, the id is therefore unique by *convention*: DuckDB's
exclusive file lock serializes writers across processes, but two threads in
one process can hold two ``Workspace.write()`` transactions at once, and
those can compute the same next id. Callers annotating from several threads
must serialize their writes.

Capture identity
----------------
``main.pkts`` has no capture column — ``frame_number`` is its row key, unique
within the workspace and ascending in capture order — so one workspace holds
one capture, and the workspace file *is* the capture identity a packet
annotation is keyed against. That is why the API takes a frame number and no
identity string: there is no second capture in the file for one to
disambiguate. Which capture the file holds stays recoverable from
``meta.cache_keys`` (``pcap_path`` and ``pcap_fingerprint``, via
:func:`remora.workspace.schema.read_cache_key`). Should a workspace ever hold
more than one capture, annotations would need a capture column: a new column
in :func:`remora.workspace.schema.iter_ddl` and a ``SCHEMA_VERSION`` bump,
because there is no migration path.

Survival and the orphan policy: kept-but-flagged
------------------------------------------------
Annotations live in their own table keyed by frame number, so
re-materializing a capture — adding projected columns to ``pkts`` with
:func:`remora.workspace.schema.add_field_column`, or rewriting ``pkts`` rows
entirely — never touches them. A re-materialization under a *narrower*
display filter, though, can leave an annotation whose frame is no longer in
``pkts``.

Such an annotation is **kept and flagged**, never deleted. Annotations are
analyst findings, often the most expensive data in the workspace; a filter
change must not destroy them, and a filter widened again restores the
packets they point at. :func:`list_annotations` computes
:attr:`AnnotationRecord.orphaned` at read time — true when no row in
``pkts`` (or ``streams``) carries the annotation's ``target_id`` — and
:func:`delete_orphan_annotations` is the explicit cleanup a caller can run
when it really does want them gone.

Connections are supplied by the caller — this module never opens one, because
connection and lock ownership belongs to ``Workspace`` (#28), whose
:meth:`~remora.workspace.workspace.Workspace.add_annotation` and siblings wrap
each of these calls in exactly one short transaction. It therefore imports
duckdb only for typing and stays importable without it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final, Literal

from remora.workspace.types import from_db_timestamp, to_db_timestamp

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "ANNOTATION_SCOPES",
    "AnnotationRecord",
    "AnnotationScope",
    "add_annotation",
    "delete_orphan_annotations",
    "list_annotations",
    "remove_annotation",
    "remove_annotations",
]

AnnotationScope = Literal["packet", "stream"]
"""What an annotation is attached to: a packet (frame) or a stream."""

ANNOTATION_SCOPES: Final[tuple[AnnotationScope, ...]] = ("packet", "stream")
"""Every legal scope, for runtime validation of values mypy cannot see."""

# True when the annotation's target is not in the workspace any more. An
# EXISTS subquery rather than a LEFT JOIN on purpose: pkts has no PRIMARY KEY
# (frame_number is unique by convention only), and a join would fan one
# annotation out into several rows if a frame number ever repeated. Both
# references are schema-qualified within the current database, like every
# other probe in this package.
_ORPHANED: Final[str] = """
    CASE a.scope
        WHEN 'packet' THEN NOT EXISTS (
            SELECT 1 FROM main.pkts AS p WHERE p.frame_number = a.target_id
        )
        WHEN 'stream' THEN NOT EXISTS (
            SELECT 1 FROM main.streams AS s WHERE s.stream_id = a.target_id
        )
        ELSE FALSE
    END
"""


@dataclass(frozen=True)
class AnnotationRecord:
    """One annotation, as :func:`list_annotations` reads it back.

    Attributes:
        annotation_id: Row key assigned by :func:`add_annotation`.
        scope: ``"packet"`` or ``"stream"``.
        target_id: ``pkts.frame_number`` or ``streams.stream_id``.
        key: Short label, e.g. ``"verdict"``.
        value: Free-form body, or ``None`` for a bare tag.
        created_at: When the annotation was written (aware, UTC).
        orphaned: Whether the target row is missing from the workspace.
            Derived at read time, not stored: a re-materialization under a
            narrower filter can orphan an annotation, and a wider one can
            un-orphan it again.
    """

    annotation_id: int
    scope: AnnotationScope
    target_id: int
    key: str
    value: str | None
    created_at: datetime
    orphaned: bool = False


def _check_scope(scope: str) -> None:
    """Refuse a scope outside :data:`ANNOTATION_SCOPES`."""
    if scope not in ANNOTATION_SCOPES:
        raise ValueError(f"annotation scope must be one of {ANNOTATION_SCOPES}, not {scope!r}")


def _as_scope(value: Any) -> AnnotationScope:
    """Narrow a scope string read from storage to :data:`AnnotationScope`."""
    _check_scope(value)
    scope: AnnotationScope = value
    return scope


def _filters(
    scope: AnnotationScope | None, target_id: int | None, key: str | None
) -> tuple[str, list[Any]]:
    """Build the shared WHERE clause and its bound parameters.

    Args:
        scope: Restrict to one scope, or ``None`` for both.
        target_id: Restrict to one frame number / stream id.
        key: Restrict to one label.

    Returns:
        The clause (empty string when unfiltered) and its parameters.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if scope is not None:
        _check_scope(scope)
        clauses.append("a.scope = ?")
        params.append(scope)
    if target_id is not None:
        clauses.append("a.target_id = ?")
        params.append(target_id)
    if key is not None:
        clauses.append('a."key" = ?')
        params.append(key)
    return (" WHERE " + " AND ".join(clauses) if clauses else "", params)


def add_annotation(
    con: DuckDBPyConnection,
    scope: AnnotationScope,
    target_id: int,
    key: str,
    value: str | None = None,
    *,
    created_at: datetime | None = None,
) -> int:
    """Attach an annotation to a packet or a stream.

    The target does not have to exist: annotating a frame that a later,
    narrower materialization removes is exactly the orphan case this module
    keeps and flags rather than refusing.

    Args:
        con: A read-write connection to the workspace.
        scope: ``"packet"`` (``target_id`` is a frame number) or
            ``"stream"`` (``target_id`` is a stream id).
        target_id: The frame number or stream id being annotated.
        key: Short label, e.g. ``"verdict"``. Must not be empty.
        value: Free-form body, or ``None`` for a bare tag.
        created_at: When the annotation was made; defaults to now. A naive
            datetime is taken to be UTC already.

    Returns:
        The new ``annotation_id``.

    Raises:
        ValueError: If ``scope`` is not a legal scope, or ``key`` is empty.
    """
    _check_scope(scope)
    if not key:
        raise ValueError("an annotation key must not be empty")
    stamp = datetime.now(timezone.utc) if created_at is None else created_at
    row = con.execute("SELECT coalesce(max(annotation_id), 0) + 1 FROM main.annotations").fetchone()
    annotation_id = 1 if row is None else int(row[0])
    con.execute(
        "INSERT INTO main.annotations "
        '(annotation_id, scope, target_id, "key", value, created_at) '
        "VALUES (?, ?, ?, ?, ?, ?)",
        [annotation_id, scope, target_id, key, value, to_db_timestamp(stamp)],
    )
    return annotation_id


def list_annotations(
    con: DuckDBPyConnection,
    *,
    scope: AnnotationScope | None = None,
    target_id: int | None = None,
    key: str | None = None,
) -> tuple[AnnotationRecord, ...]:
    """Read annotations, ascending by id, each flagged for orphanhood.

    Anything past this — grouping, counting, joining annotations onto
    packets — is plain SQL over ``main.annotations`` and deliberately not
    wrapped here.

    Args:
        con: An open connection to the workspace. Works in ro mode.
        scope: Restrict to one scope, or ``None`` for both.
        target_id: Restrict to one frame number / stream id.
        key: Restrict to one label.

    Returns:
        Matching annotations, ascending by ``annotation_id``.

    Raises:
        ValueError: If ``scope`` is not a legal scope, or a stored scope is
            not one this library knows.
    """
    where, params = _filters(scope, target_id, key)
    rows = con.execute(
        'SELECT a.annotation_id, a.scope, a.target_id, a."key", a.value, a.created_at, '
        f"{_ORPHANED} AS orphaned "
        f"FROM main.annotations AS a{where} ORDER BY a.annotation_id",
        params,
    ).fetchall()
    return tuple(
        AnnotationRecord(
            annotation_id=int(row[0]),
            scope=_as_scope(row[1]),
            target_id=int(row[2]),
            key=row[3],
            value=row[4],
            created_at=from_db_timestamp(row[5]),
            orphaned=bool(row[6]),
        )
        for row in rows
    )


def remove_annotation(con: DuckDBPyConnection, annotation_id: int) -> bool:
    """Remove one annotation by id.

    Removal by id is the precise form: an id names exactly one annotation,
    so nothing else can be caught by accident. Removing a whole label or a
    whole target is :func:`remove_annotations`.

    Args:
        con: A read-write connection to the workspace.
        annotation_id: The id :func:`add_annotation` returned.

    Returns:
        Whether a row was removed. ``False`` means the id was not there —
        not an error, so a repeated remove is idempotent.
    """
    row = con.execute(
        "DELETE FROM main.annotations WHERE annotation_id = ?", [annotation_id]
    ).fetchone()
    return row is not None and int(row[0]) > 0


def remove_annotations(
    con: DuckDBPyConnection,
    *,
    scope: AnnotationScope | None = None,
    target_id: int | None = None,
    key: str | None = None,
) -> int:
    """Remove every annotation matching the given filters.

    At least one filter is required. An unfiltered call would silently wipe
    every finding in the workspace, which is too destructive to be the
    meaning of a call with no arguments; a caller who really wants that can
    say so in SQL.

    Args:
        con: A read-write connection to the workspace.
        scope: Restrict to one scope.
        target_id: Restrict to one frame number / stream id.
        key: Restrict to one label.

    Returns:
        How many annotations were removed.

    Raises:
        ValueError: If no filter is given, or ``scope`` is not a legal scope.
    """
    if scope is None and target_id is None and key is None:
        raise ValueError(
            "remove_annotations needs at least one of scope, target_id or key; "
            "removing every annotation must be spelled out in SQL"
        )
    where, params = _filters(scope, target_id, key)
    row = con.execute(f"DELETE FROM main.annotations AS a{where}", params).fetchone()
    return 0 if row is None else int(row[0])


def delete_orphan_annotations(con: DuckDBPyConnection) -> int:
    """Remove annotations whose packet or stream is no longer in the workspace.

    The explicit half of the kept-but-flagged policy: nothing deletes an
    orphan on its own, because a re-materialization under a wider filter can
    bring its target back. Call this when the current ``pkts``/``streams``
    contents are the ones to keep.

    Args:
        con: A read-write connection to the workspace.

    Returns:
        How many orphaned annotations were removed.
    """
    row = con.execute(f"DELETE FROM main.annotations AS a WHERE {_ORPHANED}").fetchone()
    return 0 if row is None else int(row[0])
