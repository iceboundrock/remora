# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from ipaddress import IPv4Address, IPv6Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class FTP(ProtocolBase):
    ftp_data_command: Field[str]
    ftp_data_command_frame: Field[int]
    ftp_data_current_working_directory: Field[str]
    ftp_data_setup_frame: Field[int]
    ftp_data_setup_method: Field[str]
    active_cip: Field[IPv4Address]
    active_nat: Field[bool]
    active_port: Field[int]
    command: Field[str]
    command_frame: Field[int]
    command_response_bitrate: Field[int]
    command_response_bytes: Field[int]
    command_response_duration: Field[int]
    command_response_first_frame_num: Field[int]
    command_response_frames: Field[int]
    command_response_last_frame_num: Field[int]
    current_working_directory: Field[str]
    eprt_af: Field[int]
    eprt_args_invalid: Field[str]
    eprt_ip: Field[IPv4Address]
    eprt_ipv6: Field[IPv6Address]
    eprt_port: Field[int]
    epsv_args_invalid: Field[str]
    epsv_ip: Field[IPv4Address]
    epsv_ipv6: Field[IPv6Address]
    epsv_port: Field[int]
    passive_ip: Field[IPv4Address]
    passive_nat: Field[bool]
    passive_port: Field[int]
    request: Field[bool]
    request_arg: Field[str]
    request_command: Field[str]
    response: Field[bool]
    response_arg: Field[str]
    response_code: Field[int]
    response_code_invalid: Field[str]
    response_pwd_invalid: Field[str]
    setup_frame: Field[int]
