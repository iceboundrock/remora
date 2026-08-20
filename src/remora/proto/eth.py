# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``eth`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["ETH"]


class ETH(ProtocolBase):
    """Ethernet (tshark layer ``eth``)."""

    _proto_ = "eth"
    _table_: ClassVar[FieldTable] = {
        "addr": ("eth.addr", "FT_ETHER", 1),
        "addr_resolved": ("eth.addr_resolved", "FT_STRING", 0),
        "addr_oui": ("eth.addr.oui", "FT_UINT24", 0),
        "addr_oui_resolved": ("eth.addr.oui_resolved", "FT_STRING", 0),
        "fcs_bad": ("eth.fcs_bad", "FT_NONE", 0),
        "dst": ("eth.dst", "FT_ETHER", 0),
        "dst_resolved": ("eth.dst_resolved", "FT_STRING", 0),
        "dst_oui": ("eth.dst.oui", "FT_UINT24", 0),
        "dst_oui_resolved": ("eth.dst.oui_resolved", "FT_STRING", 0),
        "fcs_status": ("eth.fcs.status", "FT_UINT8", 0),
        "fcs": ("eth.fcs", "FT_UINT32", 0),
        "dst_ig": ("eth.dst.ig", "FT_BOOLEAN", 0),
        "ig": ("eth.ig", "FT_BOOLEAN", 1),
        "src_ig": ("eth.src.ig", "FT_BOOLEAN", 0),
        "invalid_lentype": ("eth.invalid_lentype", "FT_UINT16", 0),
        "invalid_lentype_expert": ("eth.invalid_lentype.expert", "FT_NONE", 0),
        "dst_lg": ("eth.dst.lg", "FT_BOOLEAN", 0),
        "lg": ("eth.lg", "FT_BOOLEAN", 1),
        "src_lg": ("eth.src.lg", "FT_BOOLEAN", 0),
        "len": ("eth.len", "FT_UINT16", 0),
        "len_past_end": ("eth.len.past_end", "FT_NONE", 0),
        "padding": ("eth.padding", "FT_BYTES", 0),
        "padding_bad": ("eth.padding_bad", "FT_NONE", 0),
        "src": ("eth.src", "FT_ETHER", 0),
        "src_resolved": ("eth.src_resolved", "FT_STRING", 0),
        "src_not_group": ("eth.src_not_group", "FT_NONE", 0),
        "src_oui": ("eth.src.oui", "FT_UINT24", 0),
        "src_oui_resolved": ("eth.src.oui_resolved", "FT_STRING", 0),
        "stream": ("eth.stream", "FT_UINT32", 0),
        "trailer": ("eth.trailer", "FT_BYTES", 0),
        "type": ("eth.type", "FT_UINT16", 0),
    }
