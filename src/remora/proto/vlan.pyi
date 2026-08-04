# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class VLAN(ProtocolBase):
    priority: Field[int]
    cfi: Field[bool]
    dei: Field[bool]
    id: Field[int]
    id_name: Field[str]
    etype: Field[int]
    len: Field[int]
    trailer: Field[bytes]
    len_past_end: Field[str]
    too_many_tags: Field[str]
