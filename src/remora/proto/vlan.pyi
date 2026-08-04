# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class VLAN(ProtocolBase):
    cfi: Field[bool]
    dei: Field[bool]
    id: Field[int]
    len: Field[int]
    len_past_end: Field[str]
    id_name: Field[str]
    priority: Field[int]
    too_many_tags: Field[str]
    trailer: Field[bytes]
    etype: Field[int]
