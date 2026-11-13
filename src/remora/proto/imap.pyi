# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class IMAP(ProtocolBase):
    command: Field[str]
    isrequest: Field[bool]
    line: Field[str]
    request: Field[str]
    request_command: Field[str]
    request_command_uid: Field[bool]
    request_folder: Field[str]
    request_password: Field[str]
    request_username: Field[str]
    request_tag: Field[str]
    response: Field[str]
    response_command: Field[str]
    response_status: Field[str]
    response_in: Field[int]
    response_tag: Field[str]
    response_to: Field[int]
    tag: Field[str]
    time: Field[timedelta]
