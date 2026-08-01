"""TCP seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["TCP"]


class TCP(ProtocolBase):
    """Transmission Control Protocol (tshark layer ``tcp``)."""

    _proto_ = "tcp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("tcp.srcport", "FT_UINT16", 0),
        "dstport": ("tcp.dstport", "FT_UINT16", 0),
        "port": ("tcp.port", "FT_UINT16", 1),
        "stream": ("tcp.stream", "FT_UINT32", 0),
        "len": ("tcp.len", "FT_UINT32", 0),
        "seq": ("tcp.seq", "FT_UINT32", 0),
        "nxtseq": ("tcp.nxtseq", "FT_UINT32", 0),
        "ack": ("tcp.ack", "FT_UINT32", 0),
        "hdr_len": ("tcp.hdr_len", "FT_UINT8", 0),
        "flags": ("tcp.flags", "FT_UINT16", 0),
        "flags_fin": ("tcp.flags.fin", "FT_BOOLEAN", 0),
        "flags_syn": ("tcp.flags.syn", "FT_BOOLEAN", 0),
        "flags_reset": ("tcp.flags.reset", "FT_BOOLEAN", 0),
        "flags_push": ("tcp.flags.push", "FT_BOOLEAN", 0),
        "flags_ack": ("tcp.flags.ack", "FT_BOOLEAN", 0),
        "flags_urg": ("tcp.flags.urg", "FT_BOOLEAN", 0),
        "flags_ece": ("tcp.flags.ece", "FT_BOOLEAN", 0),
        "flags_cwr": ("tcp.flags.cwr", "FT_BOOLEAN", 0),
        "window_size": ("tcp.window_size", "FT_UINT32", 0),
        "window_size_value": ("tcp.window_size_value", "FT_UINT16", 0),
        "checksum": ("tcp.checksum", "FT_UINT16", 0),
        "checksum_status": ("tcp.checksum.status", "FT_UINT8", 0),
        "urgent_pointer": ("tcp.urgent_pointer", "FT_UINT16", 0),
        "options": ("tcp.options", "FT_BYTES", 0),
        "payload": ("tcp.payload", "FT_BYTES", 0),
        "time_delta": ("tcp.time_delta", "FT_RELATIVE_TIME", 0),
        "time_relative": ("tcp.time_relative", "FT_RELATIVE_TIME", 0),
    }
