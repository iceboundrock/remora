"""Code generation from ``tshark -G fields`` dumps (M2, epic #41)."""

from remora.codegen.emit import EmittedModule, EmitWarning, emit_protocol, mangle_protocol
from remora.codegen.fingerprint import (
    Artifact,
    CheckReport,
    CodegenConfig,
    Fingerprint,
    add_header,
    check_artifacts,
    generate_artifacts,
    load_config,
    make_fingerprint,
    parse_header,
    render_header,
)
from remora.codegen.mangle import mangle_field
from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    ParseWarning,
    Protocol,
    parse_fields_dump,
)

__all__ = [
    "Artifact",
    "CheckReport",
    "CodegenConfig",
    "EmitWarning",
    "EmittedModule",
    "FieldDef",
    "FieldDictionary",
    "Fingerprint",
    "ParseWarning",
    "Protocol",
    "add_header",
    "check_artifacts",
    "emit_protocol",
    "generate_artifacts",
    "load_config",
    "make_fingerprint",
    "mangle_field",
    "mangle_protocol",
    "parse_fields_dump",
    "parse_header",
    "render_header",
]
