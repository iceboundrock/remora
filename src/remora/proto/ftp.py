# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``ftp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["FTP"]


class FTP(ProtocolBase):
    """File Transfer Protocol (FTP) (tshark layer ``ftp``)."""

    _proto_ = "ftp"
    _table_: ClassVar[FieldTable] = {
        "current_working_directory": ("ftp.current-working-directory", "FT_STRING", 0),
        "response": ("ftp.response", "FT_BOOLEAN", 0),
        "request": ("ftp.request", "FT_BOOLEAN", 0),
        "request_command": ("ftp.request.command", "FT_STRING", 0),
        "request_arg": ("ftp.request.arg", "FT_STRING", 0),
        "response_code": ("ftp.response.code", "FT_UINT32", 0),
        "response_arg": ("ftp.response.arg", "FT_STRING", 0),
        "passive_ip": ("ftp.passive.ip", "FT_IPv4", 0),
        "passive_port": ("ftp.passive.port", "FT_UINT16", 0),
        "passive_nat": ("ftp.passive.nat", "FT_BOOLEAN", 0),
        "active_cip": ("ftp.active.cip", "FT_IPv4", 0),
        "active_port": ("ftp.active.port", "FT_UINT16", 0),
        "active_nat": ("ftp.active.nat", "FT_BOOLEAN", 0),
        "eprt_af": ("ftp.eprt.af", "FT_UINT8", 0),
        "eprt_ip": ("ftp.eprt.ip", "FT_IPv4", 0),
        "eprt_ipv6": ("ftp.eprt.ipv6", "FT_IPv6", 0),
        "eprt_port": ("ftp.eprt.port", "FT_UINT16", 0),
        "epsv_ip": ("ftp.epsv.ip", "FT_IPv4", 0),
        "epsv_ipv6": ("ftp.epsv.ipv6", "FT_IPv6", 0),
        "epsv_port": ("ftp.epsv.port", "FT_UINT16", 0),
        "command_response_first_frame_num": ("ftp.command-response.first-frame-num", "FT_FRAMENUM", 0),
        "command_response_last_frame_num": ("ftp.command-response.last-frame-num", "FT_FRAMENUM", 0),
        "command_response_duration": ("ftp.command-response.duration", "FT_UINT32", 0),
        "command_response_bitrate": ("ftp.command-response.bitrate", "FT_UINT32", 0),
        "command_response_frames": ("ftp.command-response.frames", "FT_UINT32", 0),
        "command_response_bytes": ("ftp.command-response.bytes", "FT_UINT32", 0),
        "setup_frame": ("ftp.setup-frame", "FT_FRAMENUM", 0),
        "command_frame": ("ftp.command-frame", "FT_FRAMENUM", 0),
        "command": ("ftp.command", "FT_STRING", 0),
        "ftp_data_setup_frame": ("ftp-data.setup-frame", "FT_FRAMENUM", 0),
        "ftp_data_setup_method": ("ftp-data.setup-method", "FT_STRING", 0),
        "ftp_data_command": ("ftp-data.command", "FT_STRING", 0),
        "ftp_data_command_frame": ("ftp-data.command-frame", "FT_FRAMENUM", 0),
        "ftp_data_current_working_directory": ("ftp-data.current-working-directory", "FT_STRING", 0),
        "eprt_args_invalid": ("ftp.eprt.args_invalid", "FT_NONE", 0),
        "epsv_args_invalid": ("ftp.epsv.args_invalid", "FT_NONE", 0),
        "response_code_invalid": ("ftp.response.code.invalid", "FT_NONE", 0),
        "response_pwd_invalid": ("ftp.response.pwd.invalid", "FT_NONE", 0),
    }
