# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class IMAP(ProtocolBase):
    isrequest: Field[bool]
    line: Field[str]
    request: Field[str]
    request_tag: Field[str]
    response: Field[str]
    response_tag: Field[str]
    request_command: Field[str]
    response_command: Field[str]
    response_status: Field[str]
    tag: Field[str]
    command: Field[str]
    request_folder: Field[str]
    request_command_uid: Field[bool]
    request_username: Field[str]
    request_password: Field[str]
    response_in: Field[int]
    response_to: Field[int]
    time: Field[timedelta]
