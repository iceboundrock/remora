"""DNS seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["DNS"]


class DNS(ProtocolBase):
    """Domain Name System (tshark layer ``dns``).

    Query and resource-record fields are multi-valued: a DNS message carries
    any number of queries/records, and tshark emits one occurrence per record.
    """

    _proto_ = "dns"
    _table_: ClassVar[FieldTable] = {
        "id": ("dns.id", "FT_UINT16", 0),
        "flags": ("dns.flags", "FT_UINT16", 0),
        "flags_response": ("dns.flags.response", "FT_BOOLEAN", 0),
        "flags_opcode": ("dns.flags.opcode", "FT_UINT16", 0),
        "flags_authoritative": ("dns.flags.authoritative", "FT_BOOLEAN", 0),
        "flags_recdesired": ("dns.flags.recdesired", "FT_BOOLEAN", 0),
        "flags_recavail": ("dns.flags.recavail", "FT_BOOLEAN", 0),
        "flags_rcode": ("dns.flags.rcode", "FT_UINT16", 0),
        "count_queries": ("dns.count.queries", "FT_UINT16", 0),
        "count_answers": ("dns.count.answers", "FT_UINT16", 0),
        "count_auth_rr": ("dns.count.auth_rr", "FT_UINT16", 0),
        "count_add_rr": ("dns.count.add_rr", "FT_UINT16", 0),
        "qry_name": ("dns.qry.name", "FT_STRING", 1),
        "qry_type": ("dns.qry.type", "FT_UINT16", 1),
        "qry_class": ("dns.qry.class", "FT_UINT16", 1),
        "resp_name": ("dns.resp.name", "FT_STRING", 1),
        "resp_type": ("dns.resp.type", "FT_UINT16", 1),
        "resp_class": ("dns.resp.class", "FT_UINT16", 1),
        "resp_ttl": ("dns.resp.ttl", "FT_UINT32", 1),
        "a": ("dns.a", "FT_IPv4", 1),
        "aaaa": ("dns.aaaa", "FT_IPv6", 1),
        "cname": ("dns.cname", "FT_STRING", 1),
        "ns": ("dns.ns", "FT_STRING", 1),
        "ptr_domain_name": ("dns.ptr.domain_name", "FT_STRING", 1),
        "mx_mail_exchange": ("dns.mx.mail_exchange", "FT_STRING", 1),
        "txt": ("dns.txt", "FT_STRING", 1),
        "response_in": ("dns.response_in", "FT_FRAMENUM", 0),
        "response_to": ("dns.response_to", "FT_FRAMENUM", 0),
        "time": ("dns.time", "FT_RELATIVE_TIME", 0),
    }
