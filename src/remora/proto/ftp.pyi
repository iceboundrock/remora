# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from ipaddress import IPv4Address, IPv6Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class FTP(ProtocolBase):
    active_nat: Field[bool]
    active_cip: Field[IPv4Address]
    active_port: Field[int]
    ftp_data_command: Field[str]
    command: Field[str]
    ftp_data_command_frame: Field[int]
    command_frame: Field[int]
    command_response_bytes: Field[int]
    command_response_first_frame_num: Field[int]
    command_response_frames: Field[int]
    command_response_last_frame_num: Field[int]
    ftp_data_current_working_directory: Field[str]
    current_working_directory: Field[str]
    eprt_args_invalid: Field[str]
    epsv_args_invalid: Field[str]
    eprt_ip: Field[IPv4Address]
    eprt_ipv6: Field[IPv6Address]
    eprt_af: Field[int]
    eprt_port: Field[int]
    epsv_ip: Field[IPv4Address]
    epsv_ipv6: Field[IPv6Address]
    epsv_port: Field[int]
    response_pwd_invalid: Field[str]
    response_code_invalid: Field[str]
    passive_nat: Field[bool]
    passive_ip: Field[IPv4Address]
    passive_port: Field[int]
    request: Field[bool]
    request_arg: Field[str]
    request_command: Field[str]
    response: Field[bool]
    response_arg: Field[str]
    command_response_bitrate: Field[int]
    response_code: Field[int]
    command_response_duration: Field[int]
    ftp_data_setup_frame: Field[int]
    setup_frame: Field[int]
    ftp_data_setup_method: Field[str]
