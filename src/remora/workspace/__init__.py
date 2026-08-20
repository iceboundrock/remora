"""DuckDB materialized workspace (M4).

The workspace persists projected tshark output in DuckDB native storage. This
package owns the storage layout (:mod:`remora.workspace.schema`), the
column-name policy (:mod:`remora.workspace.naming`), the ftype -> column
type map (:mod:`remora.workspace.types`), the cache-key computation
(:mod:`remora.workspace.cachekey`), the streaming materialize pipeline
(:mod:`remora.workspace.materialize`), stream sessionization
(:mod:`remora.workspace.streams`), the analyst-annotation API
(:mod:`remora.workspace.annotations`), the cache-side query surface
(:mod:`remora.workspace.query`), cross-capture correlation and aliasing
(:mod:`remora.workspace.attach`), and the Parquet export
(:mod:`remora.workspace.export`); connection and lock ownership lives in
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
from remora.workspace.attach import (
    RESERVED_ALIASES,
    Attachment,
    apply_attachments,
    attach_database,
    attached_databases,
    detach_database,
    validate_alias,
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
    FieldDeclarationMismatchError,
    FieldNotMaterializedError,
    MaterializationMismatchError,
    MissingStreamFieldsError,
    SchemaVersionError,
    WorkspaceAliasError,
    WorkspaceError,
    WorkspaceModeError,
)
from remora.workspace.export import EXPORTABLE_TABLES, TEXT_EXPORTED_TYPES, export_parquet
from remora.workspace.materialize import (
    MaterializeOutcome,
    MaterializeResult,
    TsharkRunner,
    detect_tshark_version,
    materialize_into,
)
from remora.workspace.naming import (
    SKELETON_ABBREVS,
    SKELETON_COLUMNS,
    column_name,
    find_collisions,
)
from remora.workspace.query import Query, Row
from remora.workspace.schema import (
    SCHEMA_VERSION,
    CacheKeyRecord,
    FieldRecord,
    add_field_column,
    check_compatible,
    create_schema,
    delete_cache_key,
    find_covering_cache_key,
    iter_ddl,
    qualify,
    read_cache_key,
    read_cache_keys,
    read_fields,
    read_schema_version,
    record_cache_key,
    register_fields,
)
from remora.workspace.streams import (
    REQUIRED_FIELDS,
    STREAM_PROTOCOLS,
    StreamsResult,
    build_streams,
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
    "EXPORTABLE_TABLES",
    "FINGERPRINT_VERSION",
    "PROBE_BYTES",
    "REQUIRED_FIELDS",
    "RESERVED_ALIASES",
    "SCHEMA_VERSION",
    "SKELETON_ABBREVS",
    "SKELETON_COLUMNS",
    "STREAM_PROTOCOLS",
    "TEXT_EXPORTED_TYPES",
    "AnnotationRecord",
    "AnnotationScope",
    "Attachment",
    "CacheKeyRecord",
    "ColumnNameCollisionError",
    "ColumnSpec",
    "ColumnType",
    "FieldDeclarationMismatchError",
    "FieldNotMaterializedError",
    "FieldRecord",
    "MaterializationMismatchError",
    "MaterializeOutcome",
    "MaterializeResult",
    "MissingStreamFieldsError",
    "PcapFingerprint",
    "Query",
    "Row",
    "SchemaVersionError",
    "StreamsResult",
    "TsharkRunner",
    "Workspace",
    "WorkspaceAliasError",
    "WorkspaceError",
    "WorkspaceModeError",
    "add_annotation",
    "add_field_column",
    "apply_attachments",
    "attach_database",
    "attached_databases",
    "build_streams",
    "check_compatible",
    "column_name",
    "column_spec",
    "column_sql_type",
    "create_schema",
    "delete_cache_key",
    "delete_orphan_annotations",
    "detach_database",
    "detect_tshark_version",
    "export_parquet",
    "find_collisions",
    "find_covering_cache_key",
    "fingerprint_pcap",
    "from_db_timestamp",
    "get_column_type",
    "iter_ddl",
    "list_annotations",
    "make_cache_key",
    "materialize_into",
    "qualify",
    "read_cache_key",
    "read_cache_keys",
    "read_fields",
    "read_schema_version",
    "record_cache_key",
    "register_fields",
    "remove_annotation",
    "remove_annotations",
    "to_db_timestamp",
    "validate_alias",
]
