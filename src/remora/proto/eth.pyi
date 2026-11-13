# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class ETH(ProtocolBase):
    addr: MultiField[bytes]
    addr_oui: Field[int]
    addr_oui_resolved: Field[str]
    addr_resolved: Field[str]
    dst: Field[bytes]
    dst_ig: Field[bool]
    dst_lg: Field[bool]
    dst_oui: Field[int]
    dst_oui_resolved: Field[str]
    dst_resolved: Field[str]
    fcs: Field[int]
    fcs_status: Field[int]
    fcs_bad: Field[str]
    ig: MultiField[bool]
    invalid_lentype: Field[int]
    invalid_lentype_expert: Field[str]
    len: Field[int]
    len_past_end: Field[str]
    lg: MultiField[bool]
    padding: Field[bytes]
    padding_bad: Field[str]
    src: Field[bytes]
    src_ig: Field[bool]
    src_lg: Field[bool]
    src_oui: Field[int]
    src_oui_resolved: Field[str]
    src_not_group: Field[str]
    src_resolved: Field[str]
    stream: Field[int]
    trailer: Field[bytes]
    type: Field[int]
