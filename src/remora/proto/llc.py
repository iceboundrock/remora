# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``llc`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["LLC"]


class LLC(ProtocolBase):
    """Logical-Link Control (tshark layer ``llc``)."""

    _proto_ = "llc"
    _table_: ClassVar[FieldTable] = {
        "dsap": ("llc.dsap", "FT_UINT8", 0),
        "dsap_sap": ("llc.dsap.sap", "FT_UINT8", 0),
        "dsap_ig": ("llc.dsap.ig", "FT_BOOLEAN", 0),
        "ssap": ("llc.ssap", "FT_UINT8", 0),
        "ssap_sap": ("llc.ssap.sap", "FT_UINT8", 0),
        "ssap_cr": ("llc.ssap.cr", "FT_BOOLEAN", 0),
        "control": ("llc.control", "FT_UINT16", 0),
        "control_n_r": ("llc.control.n_r", "FT_UINT16", 0),
        "control_n_s": ("llc.control.n_s", "FT_UINT16", 0),
        "control_p": ("llc.control.p", "FT_BOOLEAN", 0),
        "control_f": ("llc.control.f", "FT_BOOLEAN", 0),
        "control_s_ftype": ("llc.control.s_ftype", "FT_UINT16", 0),
        "control_u_modifier_cmd": ("llc.control.u_modifier_cmd", "FT_UINT8", 0),
        "control_u_modifier_resp": ("llc.control.u_modifier_resp", "FT_UINT8", 0),
        "control_ftype": ("llc.control.ftype", "FT_UINT16", 0),
        "type": ("llc.type", "FT_UINT16", 0),
        "oui": ("llc.oui", "FT_UINT24", 0),
        "pid": ("llc.pid", "FT_UINT16", 0),
        "extreme_pid": ("llc.extreme_pid", "FT_UINT16", 0),
        "cisco_pid": ("llc.cisco_pid", "FT_UINT16", 0),
        "force10_pid": ("llc.force10_pid", "FT_UINT16", 0),
        "apple_awdl_pid": ("llc.apple_awdl_pid", "FT_UINT16", 0),
        "iana_pid": ("llc.iana_pid", "FT_UINT16", 0),
        "cimetrics_pid": ("llc.cimetrics_pid", "FT_UINT16", 0),
        "hpteam_pid": ("llc.hpteam_pid", "FT_UINT16", 0),
        "bluetooth_pid": ("llc.bluetooth_pid", "FT_UINT16", 0),
        "foundry_pid": ("llc.foundry_pid", "FT_UINT16", 0),
        "locamation_im_llc_pid": ("locamation-im.llc.pid", "FT_UINT16", 0),
        "mausb_pid": ("mausb.pid", "FT_UINT16", 0),
        "wlccp_pid": ("llc.wlccp_pid", "FT_UINT16", 0),
        "nortel_pid": ("llc.nortel_pid", "FT_UINT16", 0),
        "apple_atalk_pid": ("llc.apple_atalk_pid", "FT_UINT16", 0),
    }
