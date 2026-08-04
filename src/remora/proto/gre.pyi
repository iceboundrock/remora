# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class GRE(ProtocolBase):
    proto: Field[int]
    flags_and_version: Field[int]
    flags_checksum: Field[bool]
    flags_routing: Field[bool]
    flags_key: Field[bool]
    flags_sequence_number: Field[bool]
    flags_strict_source_route: Field[bool]
    flags_recursion_control: Field[int]
    flags_ack: Field[bool]
    flags_reserved: Field[int]
    flags_version: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    offset: Field[int]
    key: Field[int]
    key_payload_length: Field[int]
    key_call_id: Field[int]
    sequence_number: Field[int]
    ack_number: Field[int]
    routing: Field[str]
    routing_address_family: Field[int]
    routing_sre_offset: Field[int]
    routing_src_length: Field[int]
    routing_information: Field[bytes]
    f_3gpp2_attrib: Field[str]
    f_3gpp2_attrib_id: Field[int]
    f_3gpp2_attrib_length: Field[int]
    f_3gpp2_sdi: Field[bool]
    f_3gpp2_fci: Field[bool]
    f_3gpp2_di: Field[bool]
    ggp2_flow_disc: Field[bytes]
    ggp2_3gpp2_seg: Field[int]
    wccp_redirect_header: Field[str]
    wccp_dynamic_service: Field[bool]
    wccp_alternative_bucket_used: Field[bool]
    wccp_redirect_header_valid: Field[bool]
    wccp_service_id: Field[int]
    wccp_alternative_bucket: Field[int]
    wccp_primary_bucket: Field[int]
    checksum_incorrect: Field[str]
