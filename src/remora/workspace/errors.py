"""Exceptions raised by the workspace layer."""

from __future__ import annotations

__all__ = [
    "ColumnNameCollisionError",
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
