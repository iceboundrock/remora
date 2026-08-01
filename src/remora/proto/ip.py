"""IPv4 seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["IP"]


class IP(ProtocolBase):
    """Internet Protocol version 4 (tshark layer ``ip``)."""

    _proto_ = "ip"
    _table_: ClassVar[FieldTable] = {
        "version": ("ip.version", "FT_UINT8", 0),
        "hdr_len": ("ip.hdr_len", "FT_UINT8", 0),
        "dsfield": ("ip.dsfield", "FT_UINT8", 0),
        "dsfield_dscp": ("ip.dsfield.dscp", "FT_UINT8", 0),
        "dsfield_ecn": ("ip.dsfield.ecn", "FT_UINT8", 0),
        "len": ("ip.len", "FT_UINT16", 0),
        "id": ("ip.id", "FT_UINT16", 0),
        "flags": ("ip.flags", "FT_UINT8", 0),
        "flags_rb": ("ip.flags.rb", "FT_BOOLEAN", 0),
        "flags_df": ("ip.flags.df", "FT_BOOLEAN", 0),
        "flags_mf": ("ip.flags.mf", "FT_BOOLEAN", 0),
        "frag_offset": ("ip.frag_offset", "FT_UINT16", 0),
        "ttl": ("ip.ttl", "FT_UINT8", 0),
        "proto": ("ip.proto", "FT_UINT8", 0),
        "checksum": ("ip.checksum", "FT_UINT16", 0),
        "checksum_status": ("ip.checksum.status", "FT_UINT8", 0),
        "src": ("ip.src", "FT_IPv4", 0),
        "dst": ("ip.dst", "FT_IPv4", 0),
        "addr": ("ip.addr", "FT_IPv4", 1),
    }
