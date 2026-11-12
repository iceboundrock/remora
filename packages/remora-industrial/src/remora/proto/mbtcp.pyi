# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
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
