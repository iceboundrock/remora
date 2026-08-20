# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``stp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["STP"]


class STP(ProtocolBase):
    """Spanning Tree Protocol (tshark layer ``stp``)."""

    _proto_ = "stp"
    _table_: ClassVar[FieldTable] = {
        "flags_agreement": ("stp.flags.agreement", "FT_BOOLEAN", 0),
        "mstp_agreement_digest": ("mstp.agreement_digest", "FT_BYTES", 0),
        "bpdu_agreement_digest_convention_capabilities": ("bpdu.agreement_digest_convention_capabilities", "FT_UINT8", 0),
        "bpdu_agreement_digest_convention_id": ("bpdu.agreement_digest_convention_id", "FT_UINT8", 0),
        "bpdu_agreement_digest_edge_count": ("bpdu.agreement_digest_edge_count", "FT_UINT16", 0),
        "bpdu_agreement_digest_format_capabilities": ("bpdu.agreement_digest_format_capabilities", "FT_UINT8", 0),
        "bpdu_agreement_digest_format_id": ("bpdu.agreement_digest_format_id", "FT_UINT8", 0),
        "mstp_agree_flags_agreement_num": ("mstp.agree_flags.agreement_num", "FT_UINT8", 0),
        "mstp_agree_flags_agreement_valid": ("mstp.agree_flags.agreement_valid", "FT_BOOLEAN", 0),
        "type": ("stp.type", "FT_UINT8", 0),
        "flags": ("stp.flags", "FT_UINT8", 0),
        "mstp_msti_bridge_priority": ("mstp.msti.bridge_priority", "FT_UINT8", 0),
        "bridge_prio": ("stp.bridge.prio", "FT_UINT16", 0),
        "bridge_hw": ("stp.bridge.hw", "FT_ETHER", 0),
        "bridge_ext": ("stp.bridge.ext", "FT_UINT16", 0),
        "mstp_cist_bridge_hw": ("mstp.cist_bridge.hw", "FT_ETHER", 0),
        "mstp_cist_bridge_ext": ("mstp.cist_bridge.ext", "FT_UINT16", 0),
        "mstp_cist_bridge_prio": ("mstp.cist_bridge.prio", "FT_UINT16", 0),
        "mstp_cist_internal_root_path_cost": ("mstp.cist_internal_root_path_cost", "FT_UINT32", 0),
        "mstp_cist_remaining_hops": ("mstp.cist_remaining_hops", "FT_UINT8", 0),
        "mstp_agree_flags_dagreement_num": ("mstp.agree_flags.dagreement_num", "FT_UINT8", 0),
        "forward": ("stp.forward", "FT_DOUBLE", 0),
        "flags_forwarding": ("stp.flags.forwarding", "FT_BOOLEAN", 0),
        "hello": ("stp.hello", "FT_DOUBLE", 0),
        "pvst_tlvlen_invalid": ("stp.pvst.tlvlen.invalid", "FT_NONE", 0),
        "mstp_msti_root_cost": ("mstp.msti.root_cost", "FT_UINT32", 0),
        "flags_learning": ("stp.flags.learning", "FT_BOOLEAN", 0),
        "pvst_tlvlen": ("stp.pvst.tlvlen", "FT_UINT16", 0),
        "mstp_config_format_selector": ("mstp.config_format_selector", "FT_UINT8", 0),
        "mstp_config_digest": ("mstp.config_digest", "FT_BYTES", 0),
        "mstp_config_name": ("mstp.config_name", "FT_STRINGZPAD", 0),
        "mstp_config_revision_level": ("mstp.config_revision_level", "FT_UINT16", 0),
        "mstp_msti_bridge_id": ("mstp.msti.bridge_id", "FT_UINT16", 0),
        "mstp_msti_bridge_id_mac": ("mstp.msti.bridge_id_mac", "FT_ETHER", 0),
        "mstp_msti_bridge_id_priority": ("mstp.msti.bridge_id_priority", "FT_UINT16", 0),
        "mstp_msti_regional_root_id": ("mstp.msti.regional_root_id", "FT_UINT16", 0),
        "mstp_msti_flags": ("mstp.msti.flags", "FT_UINT8", 0),
        "mstp_msti_msti_id": ("mstp.msti.msti_id", "FT_UINT16", 0),
        "max_age": ("stp.max_age", "FT_DOUBLE", 0),
        "msg_age": ("stp.msg_age", "FT_DOUBLE", 0),
        "pvst_origvlan_missing": ("stp.pvst.origvlan.missing", "FT_NONE", 0),
        "pvst_origvlan": ("stp.pvst.origvlan", "FT_UINT16", 0),
        "flags_port_role": ("stp.flags.port_role", "FT_UINT8", 0),
        "mstp_msti_port": ("mstp.msti.port", "FT_UINT16", 0),
        "port": ("stp.port", "FT_UINT16", 0),
        "mstp_msti_port_priority": ("mstp.msti.port_priority", "FT_UINT8", 0),
        "mstp_msti_priority": ("mstp.msti.priority", "FT_UINT8", 0),
        "flags_proposal": ("stp.flags.proposal", "FT_BOOLEAN", 0),
        "protocol": ("stp.protocol", "FT_UINT16", 0),
        "version": ("stp.version", "FT_UINT8", 0),
        "mstp_msti_root_hw": ("mstp.msti.root.hw", "FT_ETHER", 0),
        "mstp_msti_remaining_hops": ("mstp.msti.remaining_hops", "FT_UINT8", 0),
        "mstp_agree_flags_rest_role": ("mstp.agree_flags.rest_role", "FT_BOOLEAN", 0),
        "root_prio": ("stp.root.prio", "FT_UINT16", 0),
        "root_hw": ("stp.root.hw", "FT_ETHER", 0),
        "root_ext": ("stp.root.ext", "FT_UINT16", 0),
        "root_cost": ("stp.root.cost", "FT_UINT32", 0),
        "pvst_tlv_truncated": ("stp.pvst.tlv.truncated", "FT_NONE", 0),
        "pvst_tlv_unknown": ("stp.pvst.tlv.unknown", "FT_NONE", 0),
        "bpdu_version_support": ("bpdu.version_support", "FT_NONE", 0),
        "flags_tc": ("stp.flags.tc", "FT_BOOLEAN", 0),
        "flags_tcack": ("stp.flags.tcack", "FT_BOOLEAN", 0),
        "pvst_tlvtype": ("stp.pvst.tlvtype", "FT_UINT16", 0),
        "type_unknown": ("stp.type.unknown", "FT_NONE", 0),
        "pvst_tlvval": ("stp.pvst.tlvval", "FT_BYTES", 0),
        "version_1_length": ("stp.version_1_length", "FT_UINT8", 0),
        "mstp_version_3_length": ("mstp.version_3_length", "FT_UINT16", 0),
        "mstp_version_4_length": ("mstp.version_4_length", "FT_UINT16", 0),
    }
