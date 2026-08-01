"""Ethernet seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["ETH"]


class ETH(ProtocolBase):
    """Ethernet II / 802.3 (tshark layer ``eth``)."""

    _proto_ = "eth"
    _table_: ClassVar[FieldTable] = {
        "dst": ("eth.dst", "FT_ETHER", 0),
        "src": ("eth.src", "FT_ETHER", 0),
        "addr": ("eth.addr", "FT_ETHER", 1),
        "ig": ("eth.ig", "FT_BOOLEAN", 1),
        "lg": ("eth.lg", "FT_BOOLEAN", 1),
        "type": ("eth.type", "FT_UINT16", 0),
        "len": ("eth.len", "FT_UINT16", 0),
        "padding": ("eth.padding", "FT_BYTES", 0),
        "trailer": ("eth.trailer", "FT_BYTES", 0),
        "fcs": ("eth.fcs", "FT_UINT32", 0),
        "fcs_status": ("eth.fcs.status", "FT_UINT8", 0),
    }
