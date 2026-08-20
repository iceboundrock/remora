# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``gre`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["GRE"]


class GRE(ProtocolBase):
    """Generic Routing Encapsulation (tshark layer ``gre``)."""

    _proto_ = "gre"
    _table_: ClassVar[FieldTable] = {
        "f_3gpp2_attrib": ("gre.3gpp2_attrib", "FT_NONE", 0),
        "flags_ack": ("gre.flags.ack", "FT_BOOLEAN", 0),
        "ack_number": ("gre.ack_number", "FT_UINT32", 0),
        "routing_address_family": ("gre.routing.address_family", "FT_UINT16", 0),
        "wccp_alternative_bucket": ("gre.wccp.alternative_bucket", "FT_UINT8", 0),
        "wccp_alternative_bucket_used": ("gre.wccp.alternative_bucket_used", "FT_BOOLEAN", 0),
        "key_call_id": ("gre.key.call_id", "FT_UINT16", 0),
        "checksum": ("gre.checksum", "FT_UINT16", 0),
        "flags_checksum": ("gre.flags.checksum", "FT_BOOLEAN", 0),
        "checksum_status": ("gre.checksum.status", "FT_UINT8", 0),
        "f_3gpp2_di": ("gre.3gpp2_di", "FT_BOOLEAN", 0),
        "wccp_dynamic_service": ("gre.wccp.dynamic_service", "FT_BOOLEAN", 0),
        "flags_reserved": ("gre.flags.reserved", "FT_UINT16", 0),
        "flags_and_version": ("gre.flags_and_version", "FT_UINT16", 0),
        "f_3gpp2_fci": ("gre.3gpp2_fci", "FT_BOOLEAN", 0),
        "ggp2_flow_disc": ("gre.ggp2_flow_disc", "FT_BYTES", 0),
        "checksum_incorrect": ("gre.checksum.incorrect", "FT_NONE", 0),
        "key": ("gre.key", "FT_UINT32", 0),
        "flags_key": ("gre.flags.key", "FT_BOOLEAN", 0),
        "f_3gpp2_attrib_length": ("gre.3gpp2_attrib_length", "FT_UINT8", 0),
        "offset": ("gre.offset", "FT_UINT16", 0),
        "key_payload_length": ("gre.key.payload_length", "FT_UINT16", 0),
        "wccp_primary_bucket": ("gre.wccp.primary_bucket", "FT_UINT8", 0),
        "proto": ("gre.proto", "FT_UINT16", 0),
        "flags_recursion_control": ("gre.flags.recursion_control", "FT_UINT16", 0),
        "wccp_redirect_header": ("gre.wccp.redirect_header", "FT_NONE", 0),
        "routing": ("gre.routing", "FT_NONE", 0),
        "flags_routing": ("gre.flags.routing", "FT_BOOLEAN", 0),
        "routing_information": ("gre.routing.information", "FT_BYTES", 0),
        "f_3gpp2_sdi": ("gre.3gpp2_sdi", "FT_BOOLEAN", 0),
        "routing_src_length": ("gre.routing.src_length", "FT_UINT8", 0),
        "routing_sre_offset": ("gre.routing.sre_offset", "FT_UINT8", 0),
        "sequence_number": ("gre.sequence_number", "FT_UINT32", 0),
        "flags_sequence_number": ("gre.flags.sequence_number", "FT_BOOLEAN", 0),
        "wccp_service_id": ("gre.wccp.service_id", "FT_UINT8", 0),
        "flags_strict_source_route": ("gre.flags.strict_source_route", "FT_BOOLEAN", 0),
        "f_3gpp2_attrib_id": ("gre.3gpp2_attrib_id", "FT_UINT8", 0),
        "ggp2_3gpp2_seg": ("gre.ggp2_3gpp2_seg", "FT_UINT16", 0),
        "flags_version": ("gre.flags.version", "FT_UINT16", 0),
        "wccp_redirect_header_valid": ("gre.wccp.redirect_header_valid", "FT_BOOLEAN", 0),
    }
