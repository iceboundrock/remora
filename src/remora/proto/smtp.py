# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``smtp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["SMTP"]


class SMTP(ProtocolBase):
    """Simple Mail Transfer Protocol (tshark layer ``smtp``)."""

    _proto_ = "smtp"
    _table_: ClassVar[FieldTable] = {
        "req": ("smtp.req", "FT_BOOLEAN", 0),
        "rsp": ("smtp.rsp", "FT_BOOLEAN", 0),
        "message": ("smtp.message", "FT_STRING", 0),
        "command_line": ("smtp.command_line", "FT_STRING", 0),
        "req_command": ("smtp.req.command", "FT_STRING", 0),
        "req_parameter": ("smtp.req.parameter", "FT_STRING", 0),
        "response": ("smtp.response", "FT_STRING", 0),
        "response_code": ("smtp.response.code", "FT_UINT32", 0),
        "rsp_parameter": ("smtp.rsp.parameter", "FT_STRING", 0),
        "auth_username": ("smtp.auth.username", "FT_STRING", 0),
        "auth_password": ("smtp.auth.password", "FT_STRING", 0),
        "auth_username_password": ("smtp.auth.username_password", "FT_STRING", 0),
        "eom": ("smtp.eom", "FT_NONE", 0),
        "data_fragments": ("smtp.data.fragments", "FT_NONE", 0),
        "data_fragment": ("smtp.data.fragment", "FT_FRAMENUM", 0),
        "data_fragment_overlap": ("smtp.data.fragment.overlap", "FT_BOOLEAN", 0),
        "data_fragment_overlap_conflicts": ("smtp.data.fragment.overlap.conflicts", "FT_BOOLEAN", 0),
        "data_fragment_multiple_tails": ("smtp.data.fragment.multiple_tails", "FT_BOOLEAN", 0),
        "data_fragment_too_long_fragment": ("smtp.data.fragment.too_long_fragment", "FT_BOOLEAN", 0),
        "data_fragment_error": ("smtp.data.fragment.error", "FT_FRAMENUM", 0),
        "data_fragment_count": ("smtp.data.fragment.count", "FT_UINT32", 0),
        "data_reassembled_in": ("smtp.data.reassembled.in", "FT_FRAMENUM", 0),
        "data_reassembled_length": ("smtp.data.reassembled.length", "FT_UINT32", 0),
        "base64_decode": ("smtp.base64_decode", "FT_NONE", 0),
        "response_code_unexpected": ("smtp.response.code.unexpected", "FT_NONE", 0),
    }
