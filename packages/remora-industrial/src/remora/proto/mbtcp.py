# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``mbtcp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["MBTCP"]


class MBTCP(ProtocolBase):
    """Modbus/TCP (tshark layer ``mbtcp``)."""

    _proto_ = "mbtcp"
    _table_: ClassVar[FieldTable] = {
        "cannot_classify": ("mbtcp.cannot_classify", "FT_NONE", 0),
        "invalid_len": ("mbtcp.invalid_len", "FT_NONE", 0),
        "invalid_prot_id": ("mbtcp.invalid_prot_id", "FT_NONE", 0),
        "len": ("mbtcp.len", "FT_UINT16", 0),
        "prot_id": ("mbtcp.prot_id", "FT_UINT16", 0),
        "trans_id": ("mbtcp.trans_id", "FT_UINT16", 0),
        "unit_id": ("mbtcp.unit_id", "FT_UINT8", 0),
    }
