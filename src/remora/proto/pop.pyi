# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class POP(ProtocolBase):
    data_fragment_error: Field[int]
    data_fragment: Field[int]
    data_fragment_count: Field[int]
    data_fragment_overlap: Field[bool]
    data_fragment_overlap_conflicts: Field[bool]
    data_fragment_too_long_fragment: Field[bool]
    data_fragments: Field[str]
    data_fragment_multiple_tails: Field[bool]
    request_data: Field[str]
    response_data: Field[str]
    response_tot_len_invalid: Field[str]
    data_reassembled_in: Field[int]
    data_reassembled_length: Field[int]
    request: Field[str]
    request_command: Field[str]
    request_parameter: Field[str]
    response: Field[str]
    response_description: Field[str]
    response_indicator: Field[str]
