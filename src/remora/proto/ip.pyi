from ipaddress import IPv4Address

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class IP(ProtocolBase):
    version: Field[int]
    hdr_len: Field[int]
    dsfield: Field[int]
    dsfield_dscp: Field[int]
    dsfield_ecn: Field[int]
    len: Field[int]
    id: Field[int]
    flags: Field[int]
    flags_rb: Field[bool]
    flags_df: Field[bool]
    flags_mf: Field[bool]
    frag_offset: Field[int]
    ttl: Field[int]
    proto: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    src: Field[IPv4Address]
    dst: Field[IPv4Address]
    addr: MultiField[IPv4Address]
