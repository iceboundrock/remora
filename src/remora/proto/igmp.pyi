# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from ipaddress import IPv4Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class IGMP(ProtocolBase):
    type: Field[int]
    reserved: Field[bytes]
    version: Field[int]
    group_type: Field[int]
    reply: Field[int]
    reply_pending: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    identifier: Field[int]
    access_key: Field[bytes]
    max_resp: Field[int]
    s: Field[bool]
    qrv: Field[int]
    qqic: Field[int]
    num_src: Field[int]
    saddr: Field[IPv4Address]
    num_grp_recs: Field[int]
    record_type: Field[int]
    aux_data_len: Field[int]
    maddr: Field[IPv4Address]
    aux_data: Field[bytes]
    data: Field[bytes]
    max_resp_exp: Field[int]
    max_resp_mant: Field[int]
    mtrace_max_hops: Field[int]
    mtrace_saddr: Field[IPv4Address]
    mtrace_raddr: Field[IPv4Address]
    mtrace_rspaddr: Field[IPv4Address]
    mtrace_resp_ttl: Field[int]
    mtrace_q_id: Field[int]
    mtrace_q_arrival: Field[int]
    mtrace_q_inaddr: Field[IPv4Address]
    mtrace_q_outaddr: Field[IPv4Address]
    mtrace_q_prevrtr: Field[IPv4Address]
    mtrace_q_inpkt: Field[int]
    mtrace_q_outpkt: Field[int]
    mtrace_q_total: Field[int]
    mtrace_q_rtg_proto: Field[int]
    mtrace_q_fwd_ttl: Field[int]
    mtrace_q_mbz: Field[int]
    mtrace_q_s: Field[int]
    mtrace_q_src_mask: Field[int]
    mtrace_q_fwd_code: Field[int]
    bad_checksum: Field[str]
