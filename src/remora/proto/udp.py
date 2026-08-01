"""UDP seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["UDP"]


class UDP(ProtocolBase):
    """User Datagram Protocol (tshark layer ``udp``)."""

    _proto_ = "udp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("udp.srcport", "FT_UINT16", 0),
        "dstport": ("udp.dstport", "FT_UINT16", 0),
        "port": ("udp.port", "FT_UINT16", 1),
        "length": ("udp.length", "FT_UINT16", 0),
        "checksum": ("udp.checksum", "FT_UINT16", 0),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "stream": ("udp.stream", "FT_UINT32", 0),
        "payload": ("udp.payload", "FT_BYTES", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
        "time_relative": ("udp.time_relative", "FT_RELATIVE_TIME", 0),
    }
