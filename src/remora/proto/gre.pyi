# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class GRE(ProtocolBase):
    f_3gpp2_attrib: Field[str]
    flags_ack: Field[bool]
    ack_number: Field[int]
    routing_address_family: Field[int]
    wccp_alternative_bucket: Field[int]
    wccp_alternative_bucket_used: Field[bool]
    key_call_id: Field[int]
    checksum: Field[int]
    flags_checksum: Field[bool]
    checksum_status: Field[int]
    f_3gpp2_di: Field[bool]
    wccp_dynamic_service: Field[bool]
    flags_reserved: Field[int]
    flags_and_version: Field[int]
    f_3gpp2_fci: Field[bool]
    ggp2_flow_disc: Field[bytes]
    checksum_incorrect: Field[str]
    key: Field[int]
    flags_key: Field[bool]
    f_3gpp2_attrib_length: Field[int]
    offset: Field[int]
    key_payload_length: Field[int]
    wccp_primary_bucket: Field[int]
    proto: Field[int]
    flags_recursion_control: Field[int]
    wccp_redirect_header: Field[str]
    routing: Field[str]
    flags_routing: Field[bool]
    routing_information: Field[bytes]
    f_3gpp2_sdi: Field[bool]
    routing_src_length: Field[int]
    routing_sre_offset: Field[int]
    sequence_number: Field[int]
    flags_sequence_number: Field[bool]
    wccp_service_id: Field[int]
    flags_strict_source_route: Field[bool]
    f_3gpp2_attrib_id: Field[int]
    ggp2_3gpp2_seg: Field[int]
    flags_version: Field[int]
    wccp_redirect_header_valid: Field[bool]
