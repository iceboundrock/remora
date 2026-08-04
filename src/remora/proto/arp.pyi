# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from ipaddress import IPv4Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class ARP(ProtocolBase):
    hw_type: Field[int]
    proto_type: Field[int]
    hw_size: Field[int]
    src_htype: Field[bool]
    src_hlen: Field[int]
    src_stype: Field[bool]
    src_slen: Field[int]
    proto_size: Field[int]
    opcode: Field[int]
    isgratuitous: Field[bool]
    isprobe: Field[bool]
    isannouncement: Field[bool]
    src_pln: Field[int]
    dst_htype: Field[bool]
    dst_hlen: Field[int]
    dst_stype: Field[bool]
    dst_slen: Field[int]
    dst_pln: Field[int]
    src_hw: Field[bytes]
    src_hw_mac: Field[bytes]
    src_hw_ax25: Field[str]
    src_atm_num_e164: Field[str]
    src_atm_num_nsap: Field[bytes]
    src_atm_subaddr: Field[bytes]
    src_proto: Field[bytes]
    src_proto_ipv4: Field[IPv4Address]
    dst_hw: Field[bytes]
    dst_hw_mac: Field[bytes]
    dst_hw_ax25: Field[str]
    dst_atm_num_e164: Field[str]
    dst_atm_num_nsap: Field[bytes]
    dst_atm_subaddr: Field[bytes]
    dst_proto: Field[bytes]
    dst_proto_ipv4: Field[IPv4Address]
    dst_drarp_error_status: Field[int]
    duplicate_address_frame: Field[int]
    seconds_since_duplicate_address_frame: Field[int]
    src_atm_data_country_code: Field[int]
    src_atm_data_country_code_group: Field[int]
    src_atm_high_order_dsp: Field[bytes]
    src_atm_end_system_identifier: Field[bytes]
    src_atm_selector: Field[int]
    src_atm_international_code_designator: Field[int]
    src_atm_international_code_designator_group: Field[int]
    src_atm_e_164_isdn: Field[bytes]
    src_atm_e_164_isdn_group: Field[bytes]
    src_atm_rest_of_address: Field[bytes]
    src_atm_afi: Field[int]
    duplicate_address_detected: Field[str]
    packet_storm_detected: Field[str]
    dst_nonzero_probe: Field[str]
    src_atm_afi_unknown: Field[str]
