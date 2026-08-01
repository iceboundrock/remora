from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class ETH(ProtocolBase):
    dst: Field[bytes]
    src: Field[bytes]
    addr: MultiField[bytes]
    ig: MultiField[bool]
    lg: MultiField[bool]
    type: Field[int]
    len: Field[int]
    padding: Field[bytes]
    trailer: Field[bytes]
    fcs: Field[int]
    fcs_status: Field[int]
