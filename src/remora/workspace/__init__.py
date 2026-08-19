"""DuckDB materialized workspace (M4).

The workspace persists projected tshark output in DuckDB native storage. This
package owns the storage layout (:mod:`remora.workspace.schema`), the
column-name policy (:mod:`remora.workspace.naming`), the ftype -> column
type map (:mod:`remora.workspace.types`), the cache-key computation
(:mod:`remora.workspace.cachekey`), and the analyst-annotation API
(:mod:`remora.workspace.annotations`); connection and lock ownership lives in
:mod:`remora.workspace.workspace`'s ``Workspace`` class (#28).

DuckDB is an optional dependency — install it with ``pip install
'remora[workspace]'``. The modules here are import-pure: they annotate
connections under ``typing.TYPE_CHECKING``, so importing this package never
imports duckdb and every module can be imported (and type-checked) without it.
duckdb is imported at runtime in exactly one place — the connect helper in
:mod:`remora.workspace.workspace`, and only when a connection is actually
opened.
"""

from remora.workspace.annotations import (
    ANNOTATION_SCOPES,
    AnnotationRecord,
    AnnotationScope,
    add_annotation,
    delete_orphan_annotations,
    list_annotations,
    remove_annotation,
    remove_annotations,
)
from remora.workspace.cachekey import (
    CACHE_KEY_VERSION,
    FINGERPRINT_VERSION,
    PROBE_BYTES,
    PcapFingerprint,
    fingerprint_pcap,
    make_cache_key,
)
from remora.workspace.errors import (
    ColumnNameCollisionError,
    SchemaVersionError,
    WorkspaceError,
    WorkspaceModeError,
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
from remora.workspace.workspace import Workspace

__all__ = [
    "ANNOTATION_SCOPES",
    "CACHE_KEY_VERSION",
    "COLUMN_TYPES",
    "FINGERPRINT_VERSION",
    "PROBE_BYTES",
    "SCHEMA_VERSION",
    "SKELETON_COLUMNS",
    "AnnotationRecord",
    "AnnotationScope",
    "CacheKeyRecord",
    "ColumnNameCollisionError",
    "ColumnSpec",
    "ColumnType",
    "FieldRecord",
    "PcapFingerprint",
    "SchemaVersionError",
    "Workspace",
    "WorkspaceError",
    "WorkspaceModeError",
    "add_annotation",
    "add_field_column",
    "check_compatible",
    "column_name",
    "column_spec",
    "column_sql_type",
    "create_schema",
    "delete_orphan_annotations",
    "find_collisions",
    "fingerprint_pcap",
    "from_db_timestamp",
    "get_column_type",
    "iter_ddl",
    "list_annotations",
    "make_cache_key",
    "read_cache_key",
    "read_fields",
    "read_schema_version",
    "record_cache_key",
    "register_fields",
    "remove_annotation",
    "remove_annotations",
    "to_db_timestamp",
]
