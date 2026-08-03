"""Code generation from ``tshark -G fields`` dumps (M2, epic #41)."""

from remora.codegen.emit import EmittedModule, EmitWarning, emit_protocol, mangle_protocol
from remora.codegen.mangle import mangle_field
from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    ParseWarning,
    Protocol,
    parse_fields_dump,
)

__all__ = [
    "EmitWarning",
    "EmittedModule",
    "FieldDef",
    "FieldDictionary",
    "ParseWarning",
    "Protocol",
    "emit_protocol",
    "mangle_field",
    "mangle_protocol",
    "parse_fields_dump",
]
