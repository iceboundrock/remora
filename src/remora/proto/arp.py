# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``arp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["ARP"]


class ARP(ProtocolBase):
    """Address Resolution Protocol (tshark layer ``arp``)."""

    _proto_ = "arp"
    _table_: ClassVar[FieldTable] = {
        "src_atm_afi": ("arp.src.atm_afi", "FT_UINT8", 0),
        "packet_storm_detected": ("arp.packet-storm-detected", "FT_NONE", 0),
        "dst_drarp_error_status": ("arp.dst.drarp_error_status", "FT_UINT16", 0),
        "src_atm_data_country_code": ("arp.src.atm_data_country_code", "FT_UINT16", 0),
        "src_atm_data_country_code_group": ("arp.src.atm_data_country_code_group", "FT_UINT16", 0),
        "duplicate_address_detected": ("arp.duplicate-address-detected", "FT_NONE", 0),
        "src_atm_e_164_isdn": ("arp.src.atm_e.164_isdn", "FT_BYTES", 0),
        "src_atm_e_164_isdn_group": ("arp.src.atm_e.164_isdn_group", "FT_BYTES", 0),
        "src_atm_end_system_identifier": ("arp.src.atm_end_system_identifier", "FT_BYTES", 0),
        "duplicate_address_frame": ("arp.duplicate-address-frame", "FT_FRAMENUM", 0),
        "hw_size": ("arp.hw.size", "FT_UINT8", 0),
        "hw_type": ("arp.hw.type", "FT_UINT16", 0),
        "src_atm_high_order_dsp": ("arp.src.atm_high_order_dsp", "FT_BYTES", 0),
        "src_atm_international_code_designator": ("arp.src.atm_international_code_designator", "FT_UINT16", 0),
        "src_atm_international_code_designator_group": ("arp.src.atm_international_code_designator_group", "FT_UINT16", 0),
        "isannouncement": ("arp.isannouncement", "FT_BOOLEAN", 0),
        "isgratuitous": ("arp.isgratuitous", "FT_BOOLEAN", 0),
        "isprobe": ("arp.isprobe", "FT_BOOLEAN", 0),
        "opcode": ("arp.opcode", "FT_UINT16", 0),
        "proto_size": ("arp.proto.size", "FT_UINT8", 0),
        "proto_type": ("arp.proto.type", "FT_UINT16", 0),
        "src_atm_rest_of_address": ("arp.src.atm_rest_of_address", "FT_BYTES", 0),
        "seconds_since_duplicate_address_frame": ("arp.seconds-since-duplicate-address-frame", "FT_UINT32", 0),
        "src_atm_selector": ("arp.src.atm_selector", "FT_UINT8", 0),
        "src_atm_num_e164": ("arp.src.atm_num_e164", "FT_STRING", 0),
        "src_atm_num_nsap": ("arp.src.atm_num_nsap", "FT_BYTES", 0),
        "src_hlen": ("arp.src.hlen", "FT_UINT8", 0),
        "src_htype": ("arp.src.htype", "FT_BOOLEAN", 0),
        "src_atm_subaddr": ("arp.src.atm_subaddr", "FT_BYTES", 0),
        "src_slen": ("arp.src.slen", "FT_UINT8", 0),
        "src_stype": ("arp.src.stype", "FT_BOOLEAN", 0),
        "src_hw_ax25": ("arp.src.hw_ax25", "FT_AX25", 0),
        "src_proto_ipv4": ("arp.src.proto_ipv4", "FT_IPv4", 0),
        "src_hw_mac": ("arp.src.hw_mac", "FT_ETHER", 0),
        "src_hw": ("arp.src.hw", "FT_BYTES", 0),
        "src_proto": ("arp.src.proto", "FT_BYTES", 0),
        "src_pln": ("arp.src.pln", "FT_UINT8", 0),
        "dst_atm_num_e164": ("arp.dst.atm_num_e164", "FT_STRING", 0),
        "dst_atm_num_nsap": ("arp.dst.atm_num_nsap", "FT_BYTES", 0),
        "dst_hlen": ("arp.dst.hlen", "FT_UINT8", 0),
        "dst_htype": ("arp.dst.htype", "FT_BOOLEAN", 0),
        "dst_atm_subaddr": ("arp.dst.atm_subaddr", "FT_BYTES", 0),
        "dst_slen": ("arp.dst.slen", "FT_UINT8", 0),
        "dst_stype": ("arp.dst.stype", "FT_BOOLEAN", 0),
        "dst_hw_ax25": ("arp.dst.hw_ax25", "FT_AX25", 0),
        "dst_nonzero_probe": ("arp.dst.nonzero.probe", "FT_NONE", 0),
        "dst_proto_ipv4": ("arp.dst.proto_ipv4", "FT_IPv4", 0),
        "dst_hw_mac": ("arp.dst.hw_mac", "FT_ETHER", 0),
        "dst_hw": ("arp.dst.hw", "FT_BYTES", 0),
        "dst_proto": ("arp.dst.proto", "FT_BYTES", 0),
        "dst_pln": ("arp.dst.pln", "FT_UINT8", 0),
        "src_atm_afi_unknown": ("arp.src.atm_afi.unknown", "FT_NONE", 0),
    }
