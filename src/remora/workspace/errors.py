"""Exceptions raised by the workspace layer."""

from __future__ import annotations

__all__ = [
    "ColumnNameCollisionError",
    "MaterializationMismatchError",
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
