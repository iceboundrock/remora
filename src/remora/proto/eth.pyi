# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class ETH(ProtocolBase):
    addr: MultiField[bytes]
    addr_resolved: Field[str]
    addr_oui: Field[int]
    addr_oui_resolved: Field[str]
    fcs_bad: Field[str]
    dst: Field[bytes]
    dst_resolved: Field[str]
    dst_oui: Field[int]
    dst_oui_resolved: Field[str]
    fcs_status: Field[int]
    fcs: Field[int]
    dst_ig: Field[bool]
    ig: MultiField[bool]
    src_ig: Field[bool]
    invalid_lentype: Field[int]
    invalid_lentype_expert: Field[str]
    dst_lg: Field[bool]
    lg: MultiField[bool]
    src_lg: Field[bool]
    len: Field[int]
    len_past_end: Field[str]
    padding: Field[bytes]
    padding_bad: Field[str]
    src: Field[bytes]
    src_resolved: Field[str]
    src_not_group: Field[str]
    src_oui: Field[int]
    src_oui_resolved: Field[str]
    stream: Field[int]
    trailer: Field[bytes]
    type: Field[int]
