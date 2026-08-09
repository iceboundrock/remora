"""DuckDB materialized workspace (M4).

The workspace persists projected tshark output in DuckDB native storage. This
package owns the storage layout (:mod:`remora.workspace.schema`), the
column-name policy (:mod:`remora.workspace.naming`) and the ftype -> column
type map (:mod:`remora.workspace.types`); connection and lock ownership
arrives with the ``Workspace`` class (issue #28).

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
from remora.workspace.naming import SKELETON_COLUMNS, column_name, find_collisions
from remora.workspace.schema import (
    SCHEMA_VERSION,
    CacheKeyRecord,
    FieldRecord,
    add_field_column,
    check_compatible,
    create_schema,
    iter_ddl,
    read_cache_key,
    read_fields,
    read_schema_version,
    record_cache_key,
    register_fields,
)
from remora.workspace.types import (
    COLUMN_TYPES,
    ColumnSpec,
    ColumnType,
    column_spec,
    column_sql_type,
    from_db_timestamp,
    get_column_type,
    to_db_timestamp,
)

__all__ = [
    "COLUMN_TYPES",
    "SCHEMA_VERSION",
    "SKELETON_COLUMNS",
    "CacheKeyRecord",
    "ColumnNameCollisionError",
    "ColumnSpec",
    "ColumnType",
    "FieldRecord",
    "SchemaVersionError",
    "WorkspaceError",
    "add_field_column",
    "check_compatible",
    "column_name",
    "column_spec",
    "column_sql_type",
    "create_schema",
    "find_collisions",
    "from_db_timestamp",
    "get_column_type",
    "iter_ddl",
    "read_cache_key",
    "read_fields",
    "read_schema_version",
    "record_cache_key",
    "register_fields",
    "to_db_timestamp",
]
