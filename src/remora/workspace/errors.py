"""Exceptions raised by the workspace layer."""

from __future__ import annotations

__all__ = [
    "ColumnNameCollisionError",
    "FieldDeclarationMismatchError",
    "FieldNotMaterializedError",
    "MaterializationMismatchError",
    "MissingStreamFieldsError",
    "SchemaVersionError",
    "WorkspaceError",
    "WorkspaceModeError",
]


class WorkspaceError(Exception):
    """Base class for every workspace failure."""


class SchemaVersionError(WorkspaceError):
    """A workspace file's schema version is unusable by this library version."""


class ColumnNameCollisionError(WorkspaceError):
    """Two distinct field abbrevs mangle to one column name."""


class WorkspaceModeError(WorkspaceError):
    """A write API was called on a workspace opened read-only."""


class MaterializationMismatchError(WorkspaceError):
    """A materialize request disagrees with what the workspace already holds.

    Raised when every cache-key component but the field set must match for
    reuse and one of them does not — a different capture, display filter,
    tshark version or tshark argument vector. The message names each component
    that changed. Reuse is refused rather than silently rematerialized: see
    :func:`remora.workspace.materialize.materialize_into` for the policy.
    """


class FieldNotMaterializedError(WorkspaceError):
    """A query referenced a field the workspace holds no column for.

    Raised by :mod:`remora.workspace.query` before anything is compiled or
    executed, so a missing field reads as "re-materialize including it" rather
    than as DuckDB's raw ``column not found``.
    """


class FieldDeclarationMismatchError(WorkspaceError):
    """A field reference's ftype/multiplicity disagrees with the stored column.

    The stored ``meta.fields`` declaration is what the column actually holds, so
    a reference that disagrees with it would compile a predicate against the
    wrong column shape. Raised by :mod:`remora.workspace.query` in the same
    validation pass as :class:`FieldNotMaterializedError`, turning what would
    otherwise leak out as a raw duckdb ``ConversionException`` /
    ``BinderException`` into a refusal naming both declarations.
    """


class MissingStreamFieldsError(WorkspaceError):
    """Sessionization needs fields this workspace never materialized.

    Raised before any SQL runs over ``pkts``, so the message names the exact
    abbrevs to add to ``materialize()``'s field set instead of surfacing as a
    DuckDB "column not found".

    Attributes:
        missing: The required abbrevs absent from ``meta.fields``, sorted.
    """

    def __init__(self, message: str, missing: tuple[str, ...]) -> None:
        super().__init__(message)
        self.missing = missing
