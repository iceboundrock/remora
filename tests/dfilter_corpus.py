"""Shared display-filter golden corpus (issue #18).

Single source of truth for (Expr, expected display-filter string) pairs,
consumed by:

- tests/test_dfilter.py — golden-string equality against compile_dfilter
- tests/test_dfilter_validation.py — every golden string is syntax-validated
  by a real tshark

Every StubField here uses a REAL tshark field name with its real ftype, so
each golden string is valid input for tshark's display-filter parser. Cases
whose strings cannot validate (the deliberately fake ``x.custom`` field) live
inline in test_dfilter.py instead, excluded from this corpus.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import NamedTuple

from remora.expr import Expr, FieldExprOps


class StubField(FieldExprOps):
    """Minimal FieldLike for tests; mirrors remora.fields.FieldRef."""

    __slots__ = ("_ftype", "_multi", "_name")

    def __init__(self, name: str, ftype: str = "FT_STRING", multi: bool = False) -> None:
        self._name = name
        self._ftype = ftype
        self._multi = multi

    @property
    def name(self) -> str:
        return self._name

    @property
    def ftype(self) -> str:
        return self._ftype

    @property
    def multi(self) -> bool:
        return self._multi

    def __repr__(self) -> str:
        return f"StubField({self._name!r}, {self._ftype!r})"


# All real tshark fields (verified against `tshark -G fields`, Wireshark 4.6).
SRC = StubField("ip.src", "FT_IPv4")
DST = StubField("ip.dst", "FT_IPv4")
SRC6 = StubField("ipv6.src", "FT_IPv6")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)
HOST = StubField("http.host", "FT_STRING")
PAYLOAD = StubField("tcp.payload", "FT_BYTES")
TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")
DELTA = StubField("frame.time_delta", "FT_RELATIVE_TIME")
SYN = StubField("tcp.flags.syn", "FT_BOOLEAN")
RESPTIME = StubField("icmp.resptime", "FT_DOUBLE")


class GoldenCase(NamedTuple):
    """One golden pair: compile_dfilter(expr) must equal expected, and
    expected must be accepted by a real tshark."""

    id: str
    expr: Expr
    expected: str


GOLDEN: tuple[GoldenCase, ...] = (
    # comparison operators
    GoldenCase("eq", PORT == 443, "tcp.port == 443"),
    GoldenCase("lt", PORT < 1024, "tcp.port < 1024"),
    GoldenCase("le", PORT <= 1024, "tcp.port <= 1024"),
    GoldenCase("gt", PORT > 1024, "tcp.port > 1024"),
    GoldenCase("ge", PORT >= 1024, "tcp.port >= 1024"),
    # != arrives as Not(Comparison(EQ)) and renders !(field == value) — never
    # Wireshark's multi-value `!=` pitfall.
    GoldenCase("ne-negated-eq", PORT != 443, "!(tcp.port == 443)"),
    # floats
    GoldenCase("float-gt", RESPTIME > 0.25, "icmp.resptime > 0.25"),
    GoldenCase("float-int-widened", RESPTIME > 1, "icmp.resptime > 1.0"),
    GoldenCase("float-sci-small", RESPTIME > 1e-05, "icmp.resptime > 1e-05"),
    GoldenCase("float-sci-large", RESPTIME < 1e21, "icmp.resptime < 1e+21"),
    # presence
    GoldenCase("presence", SRC.present(), "ip.src"),
    # boolean structure
    GoldenCase(
        "and",
        (SRC == "10.0.0.1") & (PORT == 443),
        "(ip.src == 10.0.0.1) && (tcp.port == 443)",
    ),
    GoldenCase(
        "or",
        (SRC == "10.0.0.1") | (DST == "10.0.0.2"),
        "(ip.src == 10.0.0.1) || (ip.dst == 10.0.0.2)",
    ),
    GoldenCase("not-presence", ~SRC.present(), "!(ip.src)"),
    GoldenCase(
        "not-over-or-conjoined",
        ~((SRC == "10.0.0.1") | (PORT == 443)) & (DST == "10.0.0.2"),
        "(!((ip.src == 10.0.0.1) || (tcp.port == 443))) && (ip.dst == 10.0.0.2)",
    ),
    GoldenCase(
        "and-left-leaning",
        ((SRC == "10.0.0.1") & (PORT == 443)) & (DST == "10.0.0.2"),
        "((ip.src == 10.0.0.1) && (tcp.port == 443)) && (ip.dst == 10.0.0.2)",
    ),
    GoldenCase(
        "and-right-leaning",
        (SRC == "10.0.0.1") & ((PORT == 443) & (DST == "10.0.0.2")),
        "(ip.src == 10.0.0.1) && ((tcp.port == 443) && (ip.dst == 10.0.0.2))",
    ),
    GoldenCase(
        "or-inside-and-inside-not",
        ~((SRC.present() & (PORT >= 1024)) | (SYN == True)),  # noqa: E712
        "!(((ip.src) && (tcp.port >= 1024)) || (tcp.flags.syn == 1))",
    ),
    GoldenCase("double-negation", ~~(PORT == 443), "!(!(tcp.port == 443))"),
    # string literals
    GoldenCase("str-plain", HOST == "example.com", 'http.host == "example.com"'),
    GoldenCase("str-embedded-quote", HOST == 'say "hi"', 'http.host == "say \\"hi\\""'),
    GoldenCase("str-backslash", HOST == "a\\b", 'http.host == "a\\\\b"'),
    GoldenCase("str-backslash-quote", HOST == '\\"', 'http.host == "\\\\\\""'),
    GoldenCase("str-non-ascii", HOST == "café.example", 'http.host == "café.example"'),
    GoldenCase("str-named-controls", HOST == "a\nb\tc\rd", 'http.host == "a\\nb\\tc\\rd"'),
    GoldenCase("str-named-controls-2", HOST == "\a\b\f\v", 'http.host == "\\a\\b\\f\\v"'),
    GoldenCase("str-hex-controls", HOST == "\x00\x1b\x7f", 'http.host == "\\x00\\x1b\\x7f"'),
    # address literals
    GoldenCase("ipv4-from-str", SRC == "10.0.0.1", "ip.src == 10.0.0.1"),
    # SIM300 ("Yoda condition") is suppressed here: swapping the operands would
    # dispatch to the literal's own operator, not the field's.
    GoldenCase("ipv4-object", SRC == IPv4Address("10.0.0.1"), "ip.src == 10.0.0.1"),  # noqa: SIM300
    GoldenCase("ipv6-compressed", SRC6 == "2001:0db8:0::1", "ipv6.src == 2001:db8::1"),
    # bytes literals
    GoldenCase("bytes-colon-hex", PAYLOAD == b"\xaa\xbb\xcc", "tcp.payload == aa:bb:cc"),
    GoldenCase("bytes-from-str", PAYLOAD == "aabbcc", "tcp.payload == aa:bb:cc"),
    # bool literals
    GoldenCase("bool-true", SYN == True, "tcp.flags.syn == 1"),  # noqa: E712
    GoldenCase("bool-false", SYN == False, "tcp.flags.syn == 0"),  # noqa: E712
)
