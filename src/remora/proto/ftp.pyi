# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from ipaddress import IPv4Address, IPv6Address

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class FTP(ProtocolBase):
    current_working_directory: Field[str]
    response: Field[bool]
    request: Field[bool]
    request_command: Field[str]
    request_arg: Field[str]
    response_code: Field[int]
    response_arg: Field[str]
    passive_ip: Field[IPv4Address]
    passive_port: Field[int]
    passive_nat: Field[bool]
    active_cip: Field[IPv4Address]
    active_port: Field[int]
    active_nat: Field[bool]
    eprt_af: Field[int]
    eprt_ip: Field[IPv4Address]
    eprt_ipv6: Field[IPv6Address]
    eprt_port: Field[int]
    epsv_ip: Field[IPv4Address]
    epsv_ipv6: Field[IPv6Address]
    epsv_port: Field[int]
    command_response_first_frame_num: Field[int]
    command_response_last_frame_num: Field[int]
    command_response_duration: Field[int]
    command_response_bitrate: Field[int]
    command_response_frames: Field[int]
    command_response_bytes: Field[int]
    setup_frame: Field[int]
    command_frame: Field[int]
    command: Field[str]
    ftp_data_setup_frame: Field[int]
    ftp_data_setup_method: Field[str]
    ftp_data_command: Field[str]
    ftp_data_command_frame: Field[int]
    ftp_data_current_working_directory: Field[str]
    eprt_args_invalid: Field[str]
    epsv_args_invalid: Field[str]
    response_code_invalid: Field[str]
    response_pwd_invalid: Field[str]
