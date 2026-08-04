# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class SMTP(ProtocolBase):
    req: Field[bool]
    rsp: Field[bool]
    message: Field[str]
    command_line: Field[str]
    req_command: Field[str]
    req_parameter: Field[str]
    response: Field[str]
    response_code: Field[int]
    rsp_parameter: Field[str]
    auth_username: Field[str]
    auth_password: Field[str]
    auth_username_password: Field[str]
    eom: Field[str]
    data_fragments: Field[str]
    data_fragment: Field[int]
    data_fragment_overlap: Field[bool]
    data_fragment_overlap_conflicts: Field[bool]
    data_fragment_multiple_tails: Field[bool]
    data_fragment_too_long_fragment: Field[bool]
    data_fragment_error: Field[int]
    data_fragment_count: Field[int]
    data_reassembled_in: Field[int]
    data_reassembled_length: Field[int]
    base64_decode: Field[str]
    response_code_unexpected: Field[str]
