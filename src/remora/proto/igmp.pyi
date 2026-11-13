# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from ipaddress import IPv4Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class IGMP(ProtocolBase):
    access_key: Field[bytes]
    aux_data: Field[bytes]
    aux_data_len: Field[int]
    bad_checksum: Field[str]
    checksum: Field[int]
    checksum_status: Field[int]
    data: Field[bytes]
    group_type: Field[int]
    identifier: Field[int]
    maddr: Field[IPv4Address]
    max_resp: Field[int]
    max_resp_exp: Field[int]
    max_resp_mant: Field[int]
    mtrace_max_hops: Field[int]
    mtrace_q_arrival: Field[int]
    mtrace_q_fwd_code: Field[int]
    mtrace_q_fwd_ttl: Field[int]
    mtrace_q_id: Field[int]
    mtrace_q_inaddr: Field[IPv4Address]
    mtrace_q_inpkt: Field[int]
    mtrace_q_mbz: Field[int]
    mtrace_q_outaddr: Field[IPv4Address]
    mtrace_q_outpkt: Field[int]
    mtrace_q_prevrtr: Field[IPv4Address]
    mtrace_q_rtg_proto: Field[int]
    mtrace_q_s: Field[int]
    mtrace_q_src_mask: Field[int]
    mtrace_q_total: Field[int]
    mtrace_raddr: Field[IPv4Address]
    mtrace_resp_ttl: Field[int]
    mtrace_rspaddr: Field[IPv4Address]
    mtrace_saddr: Field[IPv4Address]
    num_grp_recs: Field[int]
    num_src: Field[int]
    qqic: Field[int]
    qrv: Field[int]
    record_type: Field[int]
    reply: Field[int]
    reply_pending: Field[int]
    reserved: Field[bytes]
    s: Field[bool]
    saddr: Field[IPv4Address]
    type: Field[int]
    version: Field[int]
