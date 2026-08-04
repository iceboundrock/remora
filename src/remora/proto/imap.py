# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``imap`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["IMAP"]


class IMAP(ProtocolBase):
    """Internet Message Access Protocol (tshark layer ``imap``)."""

    _proto_ = "imap"
    _table_: ClassVar[FieldTable] = {
        "isrequest": ("imap.isrequest", "FT_BOOLEAN", 0),
        "line": ("imap.line", "FT_STRINGZ", 0),
        "request": ("imap.request", "FT_STRINGZ", 0),
        "request_tag": ("imap.request_tag", "FT_STRINGZ", 0),
        "response": ("imap.response", "FT_STRINGZ", 0),
        "response_tag": ("imap.response_tag", "FT_STRINGZ", 0),
        "request_command": ("imap.request.command", "FT_STRINGZ", 0),
        "response_command": ("imap.response.command", "FT_STRINGZ", 0),
        "response_status": ("imap.response.status", "FT_STRINGZ", 0),
        "tag": ("imap.tag", "FT_STRINGZ", 0),
        "command": ("imap.command", "FT_STRINGZ", 0),
        "request_folder": ("imap.request.folder", "FT_STRINGZ", 0),
        "request_command_uid": ("imap.request.command.uid", "FT_BOOLEAN", 0),
        "request_username": ("imap.request.username", "FT_STRINGZ", 0),
        "request_password": ("imap.request.password", "FT_STRINGZ", 0),
        "response_in": ("imap.response_in", "FT_FRAMENUM", 0),
        "response_to": ("imap.response_to", "FT_FRAMENUM", 0),
        "time": ("imap.time", "FT_RELATIVE_TIME", 0),
    }
