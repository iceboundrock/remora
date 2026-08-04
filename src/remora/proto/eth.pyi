# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class ETH(ProtocolBase):
    dst: Field[bytes]
    dst_resolved: Field[str]
    dst_oui: Field[int]
    dst_oui_resolved: Field[str]
    src: Field[bytes]
    src_resolved: Field[str]
    src_oui: Field[int]
    src_oui_resolved: Field[str]
    len: Field[int]
    type: Field[int]
    invalid_lentype: Field[int]
    addr: MultiField[bytes]
    addr_resolved: Field[str]
    addr_oui: Field[int]
    addr_oui_resolved: Field[str]
    padding: Field[bytes]
    trailer: Field[bytes]
    fcs: Field[int]
    fcs_status: Field[int]
    dst_lg: Field[bool]
    dst_ig: Field[bool]
    src_lg: Field[bool]
    src_ig: Field[bool]
    lg: MultiField[bool]
    ig: MultiField[bool]
    stream: Field[int]
    invalid_lentype_expert: Field[str]
    src_not_group: Field[str]
    fcs_bad: Field[str]
    len_past_end: Field[str]
    padding_bad: Field[str]
