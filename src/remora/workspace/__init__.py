"""DuckDB materialized workspace (M4).

The workspace persists projected tshark output in DuckDB native storage. This
package owns the storage layout (:mod:`remora.workspace.schema`) and the
column-name policy (:mod:`remora.workspace.naming`); connection and lock
ownership arrives with the ``Workspace`` class (issue #28).

DuckDB is an optional dependency — install it with ``pip install
'remora[workspace]'``. The modules here are import-pure: they annotate
connections under ``typing.TYPE_CHECKING`` and never import duckdb at runtime,
so they can be imported (and type-checked) without it.
"""

from remora.workspace.errors import (
    ColumnNameCollisionError,
    SchemaVersionError,
    WorkspaceError,
)
from remora.workspace.naming import column_name, find_collisions

__all__ = [
    "ColumnNameCollisionError",
    "SchemaVersionError",
    "WorkspaceError",
    "column_name",
    "find_collisions",
]
