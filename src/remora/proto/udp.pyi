from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    srcport: Field[int]
    dstport: Field[int]
    port: MultiField[int]
    length: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    stream: Field[int]
    payload: Field[bytes]
    time_delta: Field[timedelta]
    time_relative: Field[timedelta]
