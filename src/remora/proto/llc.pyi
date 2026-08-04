# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class LLC(ProtocolBase):
    dsap: Field[int]
    dsap_sap: Field[int]
    dsap_ig: Field[bool]
    ssap: Field[int]
    ssap_sap: Field[int]
    ssap_cr: Field[bool]
    control: Field[int]
    control_n_r: Field[int]
    control_n_s: Field[int]
    control_p: Field[bool]
    control_f: Field[bool]
    control_s_ftype: Field[int]
    control_u_modifier_cmd: Field[int]
    control_u_modifier_resp: Field[int]
    control_ftype: Field[int]
    type: Field[int]
    oui: Field[int]
    pid: Field[int]
    extreme_pid: Field[int]
    cisco_pid: Field[int]
    force10_pid: Field[int]
    apple_awdl_pid: Field[int]
    iana_pid: Field[int]
    cimetrics_pid: Field[int]
    hpteam_pid: Field[int]
    bluetooth_pid: Field[int]
    foundry_pid: Field[int]
    locamation_im_llc_pid: Field[int]
    mausb_pid: Field[int]
    wlccp_pid: Field[int]
    nortel_pid: Field[int]
    apple_atalk_pid: Field[int]
