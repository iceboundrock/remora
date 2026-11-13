# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class VLAN(ProtocolBase):
    cfi: Field[bool]
    dei: Field[bool]
    etype: Field[int]
    id: Field[int]
    id_name: Field[str]
    len: Field[int]
    len_past_end: Field[str]
    priority: Field[int]
    too_many_tags: Field[str]
    trailer: Field[bytes]
