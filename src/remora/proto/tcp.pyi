from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class TCP(ProtocolBase):
    srcport: Field[int]
    dstport: Field[int]
    port: MultiField[int]
    stream: Field[int]
    len: Field[int]
    seq: Field[int]
    nxtseq: Field[int]
    ack: Field[int]
    hdr_len: Field[int]
    flags: Field[int]
    flags_fin: Field[bool]
    flags_syn: Field[bool]
    flags_reset: Field[bool]
    flags_push: Field[bool]
    flags_ack: Field[bool]
    flags_urg: Field[bool]
    flags_ece: Field[bool]
    flags_cwr: Field[bool]
    window_size: Field[int]
    window_size_value: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    urgent_pointer: Field[int]
    options: Field[bytes]
    payload: Field[bytes]
    time_delta: Field[timedelta]
    time_relative: Field[timedelta]
