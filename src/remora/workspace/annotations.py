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

``annotation_id`` comes from a monotonic high-water mark stored in
``meta.info`` under ``next_annotation_id`` — a row in the key/value catalog
table every v1 workspace already has, so nothing about the layout changes and
``SCHEMA_VERSION`` stays 1. A sequence would be the obvious allocator and is
not available: ``create_schema`` is ``IF NOT EXISTS``-only and an opener runs
it only on an empty database, so a workspace written before a sequence existed
could never acquire one.

The mark only ever moves forward, so **ids are never reused**. Deleting the
highest-numbered annotation does not free its id, an id held across a deletion
can never come to name a different finding, and :func:`remove_annotation` with
a stale id matches nothing and returns ``False``.

Reading and advancing the mark happen *inside the caller's transaction*, so
two same-process ``Workspace.write()`` transactions racing the allocator both
write that one row: DuckDB refuses the loser loudly rather than letting the
two share an id — ``duckdb.TransactionException`` when both update an existing
mark, ``duckdb.ConstraintException`` on ``meta.info``'s primary key when both
seed a missing one, and both derive from ``duckdb.Error``. The losing add
rolls back whole, writing no annotation; whether to retry it is the caller's
decision. Writers in other processes were already serialized by DuckDB's
exclusive file lock.

A workspace written before this key existed has no mark, and what happens then
depends on whether it holds annotations:

* **Empty ``main.annotations``** — the only state a real upgraded file can be
  in, since every ``SCHEMA_VERSION`` 1 file released remora ever wrote predates
  this API — is seeded silently: the first :func:`add_annotation` writes the
  mark and returns id 1, with no ceremony asked of the caller.
* **Rows present but no mark** is refused with
  :exc:`~remora.workspace.errors.WorkspaceError`. The past high-water mark
  cannot be reconstructed from the surviving rows: an id that was issued and
  later deleted leaves no trace, so no computed seed — ``max(annotation_id) +
  1`` included — can be proven to exceed every id ever issued, and guessing one
  would silently break the never-reused guarantee above. Remora therefore does
  not guess. The escape is explicit and the caller's: set the mark by hand to a
  value known to exceed every id ever issued, e.g. inside
  ``Workspace.write()``::

      INSERT INTO meta.info (key, value) VALUES ('next_annotation_id', '100')

  The floor for that value is ``SELECT max(annotation_id) + 1 FROM
  main.annotations``, and it has to go higher if ids were ever deleted:
  ``main.annotations`` has no primary key, so a value chosen too low silently
  hands out ids that already exist rather than failing on a constraint. The
  refusal itself modifies nothing.

Once written, the mark row is part of the workspace's integrity, not a cache:
nothing in this API ever deletes it, and removing annotations leaves it exactly
where it stood. Deleting it by hand over an *empty* ``main.annotations`` is
catalog corruption remora cannot detect — that state is indistinguishable from
a fresh workspace, so the next :func:`add_annotation` re-seeds at 1 and the
never-reused guarantee is void for every id issued before the deletion.

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
when it really does want them gone. ``main.streams`` is unpopulated until
#33 lands stream semantics, so every stream annotation currently reads as
``orphaned=True`` and :func:`delete_orphan_annotations` removes all of them.

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

from remora.workspace.errors import WorkspaceError
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

_NEXT_ID_KEY: Final[str] = "next_annotation_id"
"""``meta.info`` key holding the annotation id high-water mark."""

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


def _allocate_annotation_id(con: DuckDBPyConnection) -> int:
    """Take the next id from the ``meta.info`` high-water mark and advance it.

    Runs inside the caller's transaction, which is what makes the mark an
    allocator rather than a hint: the read, the advance and the annotation
    row all commit together, so a committed id is never handed out twice and
    two racing transactions conflict on the mark row instead of sharing an id
    (see the module docstring).

    A workspace with no mark yet — one written before this key existed — is
    seeded only when ``main.annotations`` is empty, which is the only state a
    real upgraded file can be in. Rows without a mark are refused instead of
    seeded: the ids already handed out and since deleted are unrecoverable, so
    no computed seed can be proven to exceed them.

    Args:
        con: A read-write connection to the workspace, inside a transaction.

    Returns:
        The id to write the next annotation under.

    Raises:
        WorkspaceError: If ``main.annotations`` holds rows but the mark is
            missing. Nothing is modified; the message names the manual escape.
    """
    row = con.execute("SELECT value FROM meta.info WHERE key = ?", [_NEXT_ID_KEY]).fetchone()
    if row is not None:
        next_id = int(row[0])
        con.execute(
            "UPDATE meta.info SET value = ? WHERE key = ?",
            [str(next_id + 1), _NEXT_ID_KEY],
        )
        return next_id
    if con.execute("SELECT 1 FROM main.annotations LIMIT 1").fetchone() is not None:
        raise WorkspaceError(
            "this workspace holds annotation rows but no next_annotation_id mark in "
            "meta.info, so the deleted-id history is unrecoverable: an id that was "
            "issued and later deleted leaves no trace, and no seed computed from the "
            "surviving rows can be proven to exceed every id ever issued, so remora "
            "will not guess at the cost of the never-reused guarantee. Set the mark "
            "by hand to a value you know exceeds every id ever issued, e.g. inside "
            "Workspace.write(): INSERT INTO meta.info (key, value) VALUES "
            "('next_annotation_id', '<N>'). Choose <N> at minimum "
            "SELECT max(annotation_id) + 1 FROM main.annotations, and higher if ids "
            "were ever deleted: main.annotations has no primary key, so a too-low "
            "<N> silently duplicates ids rather than failing. Nothing has been "
            "modified."
        )
    # Empty table: seed silently. The INSERT is what makes a concurrent seed
    # fail loudly on meta.info's primary key rather than share id 1.
    con.execute("INSERT INTO meta.info (key, value) VALUES (?, ?)", [_NEXT_ID_KEY, "2"])
    return 1


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
        con: A read-write connection to the workspace, **inside a
            transaction the caller drives** — ``Workspace.write()`` provides
            exactly that. The id allocator reads the high-water mark and
            advances it in two statements, so it is safe against a
            concurrent allocation only when both land in one transaction
            that can conflict as a unit. On an autocommit connection the
            read and the advance are separate implicit transactions, and two
            callers can still read the same mark and silently share an id.
        scope: ``"packet"`` (``target_id`` is a frame number) or
            ``"stream"`` (``target_id`` is a stream id).
        target_id: The frame number or stream id being annotated.
        key: Short label, e.g. ``"verdict"``. Must not be empty.
        value: Free-form body, or ``None`` for a bare tag.
        created_at: When the annotation was made; defaults to now. A naive
            datetime is taken to be UTC already.

    Returns:
        The new ``annotation_id``, taken from the high-water mark described
        in the module docstring: monotonic, and never reused.

    Raises:
        ValueError: If ``scope`` is not a legal scope, or ``key`` is empty.
        WorkspaceError: If the workspace holds annotation rows but no
            ``next_annotation_id`` mark. The deleted-id history is
            unrecoverable there, so no seed can honour the never-reused
            guarantee; the message names the manual escape (see the module
            docstring). Nothing is modified.
        duckdb.Error: If ``con`` is inside a transaction and another
            transaction in this process is allocating an id at the same time
            — ``TransactionException`` or ``ConstraintException`` on the mark
            row. The whole add rolls back; no annotation is written and no id
            is shared. This is the guarantee an autocommit ``con`` gives up:
            there the race is not detected and no error is raised.
    """
    _check_scope(scope)
    if not key:
        raise ValueError("an annotation key must not be empty")
    stamp = datetime.now(timezone.utc) if created_at is None else created_at
    annotation_id = _allocate_annotation_id(con)
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
        target_id: Restrict to one frame number or stream id. Frame numbers
            and stream ids are separate namespaces that overlap, so ``None``
            scope with a given ``target_id`` matches annotations in both
            scopes; pass ``scope`` to mean one.
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

    Removal by id is the precise form: ids come from a monotonic high-water
    mark and are never reused (see the module docstring), so an id names at
    most one annotation for the workspace's whole life and a stale one — an
    id whose annotation is already gone — matches nothing rather than some
    later finding. Removing a whole label or a whole target is
    :func:`remove_annotations`.

    Args:
        con: A read-write connection to the workspace.
        annotation_id: The id :func:`add_annotation` returned.

    Returns:
        Whether a row was removed. ``False`` means the id was not there —
        not an error, so a repeated remove is idempotent, and so is a remove
        with an id held across an earlier deletion.
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
        scope: Restrict to one scope, or ``None`` for both.
        target_id: Restrict to one frame number or stream id. Frame numbers
            and stream ids are separate namespaces that overlap, so ``None``
            scope with a given ``target_id`` matches annotations in both
            scopes; pass ``scope`` to mean one. It matters most on this
            destructive call.
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
    contents are the ones to keep. ``main.streams`` is unpopulated until #33
    lands stream semantics, so every stream annotation currently reads as
    orphaned and this call removes all of them.

    Args:
        con: A read-write connection to the workspace.

    Returns:
        How many orphaned annotations were removed.
    """
    row = con.execute(f"DELETE FROM main.annotations AS a WHERE {_ORPHANED}").fetchone()
    return 0 if row is None else int(row[0])
