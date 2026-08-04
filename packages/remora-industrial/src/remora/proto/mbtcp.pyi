# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from remora.fields import Field
from remora.proto._meta import ProtocolBase

class MBTCP(ProtocolBase):
    cannot_classify: Field[str]
    invalid_len: Field[str]
    invalid_prot_id: Field[str]
    len: Field[int]
    prot_id: Field[int]
    trans_id: Field[int]
    unit_id: Field[int]
