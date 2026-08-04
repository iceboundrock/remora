# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class IMAP(ProtocolBase):
    command: Field[str]
    line: Field[str]
    isrequest: Field[bool]
    request: Field[str]
    request_command: Field[str]
    request_folder: Field[str]
    response_to: Field[int]
    request_password: Field[str]
    request_tag: Field[str]
    request_username: Field[str]
    request_command_uid: Field[bool]
    response: Field[str]
    response_command: Field[str]
    response_in: Field[int]
    response_status: Field[str]
    response_tag: Field[str]
    time: Field[timedelta]
    tag: Field[str]
