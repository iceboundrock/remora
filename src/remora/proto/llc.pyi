# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class LLC(ProtocolBase):
    ssap_cr: Field[bool]
    control_u_modifier_cmd: Field[int]
    control: Field[int]
    dsap: Field[int]
    control_f: Field[bool]
    control_ftype: Field[int]
    dsap_ig: Field[bool]
    control_n_r: Field[int]
    control_n_s: Field[int]
    oui: Field[int]
    apple_atalk_pid: Field[int]
    apple_awdl_pid: Field[int]
    bluetooth_pid: Field[int]
    cimetrics_pid: Field[int]
    cisco_pid: Field[int]
    extreme_pid: Field[int]
    force10_pid: Field[int]
    foundry_pid: Field[int]
    hpteam_pid: Field[int]
    iana_pid: Field[int]
    nortel_pid: Field[int]
    wlccp_pid: Field[int]
    locamation_im_llc_pid: Field[int]
    mausb_pid: Field[int]
    control_p: Field[bool]
    pid: Field[int]
    control_u_modifier_resp: Field[int]
    dsap_sap: Field[int]
    ssap_sap: Field[int]
    ssap: Field[int]
    control_s_ftype: Field[int]
    type: Field[int]
