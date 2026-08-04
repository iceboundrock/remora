# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``udp`` — do not edit."""

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
        "stream": ("udp.stream", "FT_UINT32", 0),
        "stream_pnum": ("udp.stream.pnum", "FT_UINT32", 0),
        "length": ("udp.length", "FT_UINT16", 0),
        "checksum": ("udp.checksum", "FT_UINT16", 0),
        "checksum_calculated": ("udp.checksum_calculated", "FT_UINT16", 0),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "proc_srcuid": ("udp.proc.srcuid", "FT_UINT32", 0),
        "proc_srcpid": ("udp.proc.srcpid", "FT_UINT32", 0),
        "proc_srcuname": ("udp.proc.srcuname", "FT_STRING", 0),
        "proc_srccmd": ("udp.proc.srccmd", "FT_STRING", 0),
        "proc_dstuid": ("udp.proc.dstuid", "FT_UINT32", 0),
        "proc_dstpid": ("udp.proc.dstpid", "FT_UINT32", 0),
        "proc_dstuname": ("udp.proc.dstuname", "FT_STRING", 0),
        "proc_dstcmd": ("udp.proc.dstcmd", "FT_STRING", 0),
        "pdu_size": ("udp.pdu.size", "FT_UINT32", 0),
        "time_relative": ("udp.time_relative", "FT_RELATIVE_TIME", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
        "payload": ("udp.payload", "FT_BYTES", 0),
        "possible_traceroute": ("udp.possible_traceroute", "FT_NONE", 0),
        "length_bad": ("udp.length.bad", "FT_NONE", 0),
        "udplite_checksum_coverage_bad": ("udplite.checksum_coverage.bad", "FT_NONE", 0),
        "checksum_zero": ("udp.checksum.zero", "FT_NONE", 0),
        "checksum_partial": ("udp.checksum.partial", "FT_NONE", 0),
        "checksum_bad": ("udp.checksum.bad", "FT_NONE", 0),
        "length_bad_zero": ("udp.length.bad_zero", "FT_NONE", 0),
    }
