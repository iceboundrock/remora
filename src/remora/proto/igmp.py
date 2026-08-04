# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``igmp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["IGMP"]


class IGMP(ProtocolBase):
    """Internet Group Management Protocol (tshark layer ``igmp``)."""

    _proto_ = "igmp"
    _table_: ClassVar[FieldTable] = {
        "type": ("igmp.type", "FT_UINT8", 0),
        "reserved": ("igmp.reserved", "FT_BYTES", 0),
        "version": ("igmp.version", "FT_UINT8", 0),
        "group_type": ("igmp.group_type", "FT_UINT8", 0),
        "reply": ("igmp.reply", "FT_UINT8", 0),
        "reply_pending": ("igmp.reply.pending", "FT_UINT8", 0),
        "checksum": ("igmp.checksum", "FT_UINT16", 0),
        "checksum_status": ("igmp.checksum.status", "FT_UINT8", 0),
        "identifier": ("igmp.identifier", "FT_UINT32", 0),
        "access_key": ("igmp.access_key", "FT_BYTES", 0),
        "max_resp": ("igmp.max_resp", "FT_UINT8", 0),
        "s": ("igmp.s", "FT_BOOLEAN", 0),
        "qrv": ("igmp.qrv", "FT_UINT8", 0),
        "qqic": ("igmp.qqic", "FT_UINT8", 0),
        "num_src": ("igmp.num_src", "FT_UINT16", 0),
        "saddr": ("igmp.saddr", "FT_IPv4", 0),
        "num_grp_recs": ("igmp.num_grp_recs", "FT_UINT16", 0),
        "record_type": ("igmp.record_type", "FT_UINT8", 0),
        "aux_data_len": ("igmp.aux_data_len", "FT_UINT8", 0),
        "maddr": ("igmp.maddr", "FT_IPv4", 0),
        "aux_data": ("igmp.aux_data", "FT_BYTES", 0),
        "data": ("igmp.data", "FT_BYTES", 0),
        "max_resp_exp": ("igmp.max_resp.exp", "FT_UINT8", 0),
        "max_resp_mant": ("igmp.max_resp.mant", "FT_UINT8", 0),
        "mtrace_max_hops": ("igmp.mtrace.max_hops", "FT_UINT8", 0),
        "mtrace_saddr": ("igmp.mtrace.saddr", "FT_IPv4", 0),
        "mtrace_raddr": ("igmp.mtrace.raddr", "FT_IPv4", 0),
        "mtrace_rspaddr": ("igmp.mtrace.rspaddr", "FT_IPv4", 0),
        "mtrace_resp_ttl": ("igmp.mtrace.resp_ttl", "FT_UINT8", 0),
        "mtrace_q_id": ("igmp.mtrace.q_id", "FT_UINT24", 0),
        "mtrace_q_arrival": ("igmp.mtrace.q_arrival", "FT_UINT32", 0),
        "mtrace_q_inaddr": ("igmp.mtrace.q_inaddr", "FT_IPv4", 0),
        "mtrace_q_outaddr": ("igmp.mtrace.q_outaddr", "FT_IPv4", 0),
        "mtrace_q_prevrtr": ("igmp.mtrace.q_prevrtr", "FT_IPv4", 0),
        "mtrace_q_inpkt": ("igmp.mtrace.q_inpkt", "FT_UINT32", 0),
        "mtrace_q_outpkt": ("igmp.mtrace.q_outpkt", "FT_UINT32", 0),
        "mtrace_q_total": ("igmp.mtrace.q_total", "FT_UINT32", 0),
        "mtrace_q_rtg_proto": ("igmp.mtrace.q_rtg_proto", "FT_UINT8", 0),
        "mtrace_q_fwd_ttl": ("igmp.mtrace.q_fwd_ttl", "FT_UINT8", 0),
        "mtrace_q_mbz": ("igmp.mtrace.q_mbz", "FT_UINT8", 0),
        "mtrace_q_s": ("igmp.mtrace.q_s", "FT_UINT8", 0),
        "mtrace_q_src_mask": ("igmp.mtrace.q_src_mask", "FT_UINT8", 0),
        "mtrace_q_fwd_code": ("igmp.mtrace.q_fwd_code", "FT_UINT8", 0),
        "bad_checksum": ("igmp.bad_checksum", "FT_NONE", 0),
    }
