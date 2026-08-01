from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class DNS(ProtocolBase):
    id: Field[int]
    flags: Field[int]
    flags_response: Field[bool]
    flags_opcode: Field[int]
    flags_authoritative: Field[bool]
    flags_recdesired: Field[bool]
    flags_recavail: Field[bool]
    flags_rcode: Field[int]
    count_queries: Field[int]
    count_answers: Field[int]
    count_auth_rr: Field[int]
    count_add_rr: Field[int]
    qry_name: MultiField[str]
    qry_type: MultiField[int]
    qry_class: MultiField[int]
    resp_name: MultiField[str]
    resp_type: MultiField[int]
    resp_class: MultiField[int]
    resp_ttl: MultiField[int]
    a: MultiField[IPv4Address]
    aaaa: MultiField[IPv6Address]
    cname: MultiField[str]
    ns: MultiField[str]
    ptr_domain_name: MultiField[str]
    mx_mail_exchange: MultiField[str]
    txt: MultiField[str]
    response_in: Field[int]
    response_to: Field[int]
    time: Field[timedelta]
