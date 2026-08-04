# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class SMTP(ProtocolBase):
    req_command: Field[str]
    command_line: Field[str]
    data_fragment_error: Field[int]
    data_fragment: Field[int]
    data_fragment_count: Field[int]
    data_fragment_overlap: Field[bool]
    data_fragment_overlap_conflicts: Field[bool]
    data_fragment_too_long_fragment: Field[bool]
    data_fragments: Field[str]
    data_fragment_multiple_tails: Field[bool]
    eom: Field[str]
    message: Field[str]
    auth_password: Field[str]
    data_reassembled_in: Field[int]
    data_reassembled_length: Field[int]
    req: Field[bool]
    req_parameter: Field[str]
    response: Field[str]
    rsp: Field[bool]
    response_code: Field[int]
    rsp_parameter: Field[str]
    response_code_unexpected: Field[str]
    auth_username: Field[str]
    auth_username_password: Field[str]
    base64_decode: Field[str]
