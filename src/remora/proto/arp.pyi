# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from ipaddress import IPv4Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class ARP(ProtocolBase):
    dst_atm_num_e164: Field[str]
    dst_atm_num_nsap: Field[bytes]
    dst_atm_subaddr: Field[bytes]
    dst_drarp_error_status: Field[int]
    dst_hlen: Field[int]
    dst_htype: Field[bool]
    dst_hw: Field[bytes]
    dst_hw_ax25: Field[str]
    dst_hw_mac: Field[bytes]
    dst_nonzero_probe: Field[str]
    dst_pln: Field[int]
    dst_proto: Field[bytes]
    dst_proto_ipv4: Field[IPv4Address]
    dst_slen: Field[int]
    dst_stype: Field[bool]
    duplicate_address_detected: Field[str]
    duplicate_address_frame: Field[int]
    hw_size: Field[int]
    hw_type: Field[int]
    isannouncement: Field[bool]
    isgratuitous: Field[bool]
    isprobe: Field[bool]
    opcode: Field[int]
    packet_storm_detected: Field[str]
    proto_size: Field[int]
    proto_type: Field[int]
    seconds_since_duplicate_address_frame: Field[int]
    src_atm_afi: Field[int]
    src_atm_afi_unknown: Field[str]
    src_atm_data_country_code: Field[int]
    src_atm_data_country_code_group: Field[int]
    src_atm_e_164_isdn: Field[bytes]
    src_atm_e_164_isdn_group: Field[bytes]
    src_atm_end_system_identifier: Field[bytes]
    src_atm_high_order_dsp: Field[bytes]
    src_atm_international_code_designator: Field[int]
    src_atm_international_code_designator_group: Field[int]
    src_atm_num_e164: Field[str]
    src_atm_num_nsap: Field[bytes]
    src_atm_rest_of_address: Field[bytes]
    src_atm_selector: Field[int]
    src_atm_subaddr: Field[bytes]
    src_hlen: Field[int]
    src_htype: Field[bool]
    src_hw: Field[bytes]
    src_hw_ax25: Field[str]
    src_hw_mac: Field[bytes]
    src_pln: Field[int]
    src_proto: Field[bytes]
    src_proto_ipv4: Field[IPv4Address]
    src_slen: Field[int]
    src_stype: Field[bool]
