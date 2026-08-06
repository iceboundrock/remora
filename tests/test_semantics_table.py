"""Table-driven semantics suite run through BOTH compile backends.

ONE table of cases, each executed against the display-filter backend (golden
string, or an expected :class:`UnsupportedExprError` when the expression is
not pushdown-able) AND against the Python predicate backend (packet rows with
expected boolean results). Because both parametrized tests consume the same
``Case`` objects, the two backends cannot drift apart silently.

This file also hosts the cross-module drift guard promised in the PR #46
review: every ``py_type`` in ``remora.values.FTYPE_TABLE`` must be accepted as
an ``Expr`` comparison literal.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from conftest import FakePacket
from remora import values
from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import CompareOp, Comparison, Expr, LiteralValue
from remora.fields import FieldRef

SRC = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
DST = FieldRef[IPv4Address]("ip.dst", "FT_IPv4", False)
PORT = FieldRef[int]("tcp.port", "FT_UINT16", True)
TTL = FieldRef[int]("ip.ttl", "FT_UINT8", False)
HOST = FieldRef[str]("http.host", "FT_STRING", False)
TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
QNAME = FieldRef[str]("dns.qry.name", "FT_STRING", True)
PAYLOAD = FieldRef[bytes]("tcp.payload", "FT_BYTES", False)

EMPTY = FakePacket({})


@dataclass(frozen=True)
class Case:
    """One semantics scenario, shared verbatim by both backend tests."""

    id: str
    expr: Expr
    dfilter: str | None
    """Expected golden dfilter string; None = UnsupportedExprError expected."""
    rows: tuple[tuple[FakePacket, bool], ...]
    """(packet, expected predicate result) pairs."""


_MOMENT = datetime(2021, 7, 1, tzinfo=timezone.utc)  # epoch 1625097600

CASES: tuple[Case, ...] = (
    Case(
        id="eq-scalar",
        expr=SRC == "10.0.0.1",
        dfilter="ip.src == 10.0.0.1",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.1",)}), True),
            (FakePacket({"ip.src": ("10.0.0.2",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="lt",
        expr=TTL < 64,
        dfilter="ip.ttl < 64",
        rows=(
            (FakePacket({"ip.ttl": ("63",)}), True),
            (FakePacket({"ip.ttl": ("64",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="le",
        expr=TTL <= 64,
        dfilter="ip.ttl <= 64",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("65",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="gt",
        expr=TTL > 64,
        dfilter="ip.ttl > 64",
        rows=(
            (FakePacket({"ip.ttl": ("65",)}), True),
            (FakePacket({"ip.ttl": ("64",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="ge",
        expr=TTL >= 64,
        dfilter="ip.ttl >= 64",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("63",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="presence",
        expr=SRC.present(),
        dfilter="ip.src",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.1",)}), True),
            (EMPTY, False),
        ),
    ),
    Case(
        id="not-presence",
        expr=~SRC.present(),
        dfilter="!(ip.src)",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.1",)}), False),
            (EMPTY, True),
        ),
    ),
    Case(
        id="and",
        expr=(SRC == "10.0.0.1") & (PORT == 443),
        dfilter="(ip.src == 10.0.0.1) && (tcp.port == 443)",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.1",), "tcp.port": ("443",)}), True),
            (FakePacket({"ip.src": ("10.0.0.1",), "tcp.port": ("80",)}), False),
            (FakePacket({"tcp.port": ("443",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="or",
        expr=(SRC == "10.0.0.1") | (DST == "10.0.0.2"),
        dfilter="(ip.src == 10.0.0.1) || (ip.dst == 10.0.0.2)",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.1",)}), True),
            (FakePacket({"ip.dst": ("10.0.0.2",)}), True),
            (FakePacket({"ip.src": ("10.0.0.9",), "ip.dst": ("10.0.0.9",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="nested-not-over-or-conjoined",
        expr=~((SRC == "10.0.0.1") | (PORT == 443)) & (DST == "10.0.0.2"),
        dfilter="(!((ip.src == 10.0.0.1) || (tcp.port == 443))) && (ip.dst == 10.0.0.2)",
        rows=(
            (
                FakePacket({"ip.src": ("10.0.0.9",), "tcp.port": ("80",), "ip.dst": ("10.0.0.2",)}),
                True,
            ),
            (FakePacket({"ip.src": ("10.0.0.1",), "ip.dst": ("10.0.0.2",)}), False),
            (FakePacket({"ip.dst": ("10.0.0.2",)}), True),
            (EMPTY, False),
        ),
    ),
    Case(
        # Wireshark multi-value ==: true if ANY occurrence matches.
        id="multi-value-eq-any-occurrence",
        expr=PORT == 443,
        dfilter="tcp.port == 443",
        rows=(
            (FakePacket({"tcp.port": ("52034", "8080")}), False),
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (EMPTY, False),
        ),
    ),
    Case(
        # The != contract: Not(Eq), rendered !(f == v), true iff NO occurrence
        # equals — including the absent-field row (Eq is False there, so Not
        # is True), exactly Wireshark's row set for !(tcp.port == 443).
        id="ne-is-not-eq",
        expr=PORT != 443,
        dfilter="!(tcp.port == 443)",
        rows=(
            (FakePacket({"tcp.port": ("443", "52034")}), False),
            (FakePacket({"tcp.port": ("80", "8080")}), True),
            (EMPTY, True),
        ),
    ),
    Case(
        # Time comparisons are not pushed down in M1: dfilter refuses
        # (UnsupportedExprError) while the predicate backend evaluates them
        # against epoch-seconds raws.
        id="time-literal-residual",
        expr=TIME >= _MOMENT,
        dfilter=None,
        rows=(
            (FakePacket({"frame.time": ("1625097600.123456",)}), True),
            (FakePacket({"frame.time": ("1625097599.999999",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="string-escaping",
        expr=HOST == 'say "hi"',
        dfilter='http.host == "say \\"hi\\""',
        rows=(
            (FakePacket({"http.host": ('say "hi"',)}), True),
            (FakePacket({"http.host": ("say hi",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="in-scalar-set",
        expr=PORT.in_([80, 443]),
        dfilter="tcp.port in {80, 443}",
        rows=(
            (FakePacket({"tcp.port": ("443",)}), True),
            (FakePacket({"tcp.port": ("8080",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # Any-occurrence semantics under membership, like every operator.
        id="in-multi-value-any-occurrence",
        expr=PORT.in_([443]),
        dfilter="tcp.port in {443}",
        rows=(
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (FakePacket({"tcp.port": ("52034", "8080")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # Python range(8000, 8081) is half-open; the set element is the
        # inclusive 8000 .. 8080, matching Wireshark's `..` semantics.
        id="in-range-inclusive",
        expr=PORT.in_([443, range(8000, 8081)]),
        dfilter="tcp.port in {443, 8000 .. 8080}",
        rows=(
            (FakePacket({"tcp.port": ("8000",)}), True),
            (FakePacket({"tcp.port": ("8080",)}), True),
            (FakePacket({"tcp.port": ("8081",)}), False),
            (FakePacket({"tcp.port": ("443",)}), True),
            (EMPTY, False),
        ),
    ),
    Case(
        id="in-ipv4-range",
        expr=SRC.in_([("10.0.0.5", "10.0.0.9"), "10.0.0.1"]),
        dfilter="ip.src in {10.0.0.5 .. 10.0.0.9, 10.0.0.1}",
        rows=(
            (FakePacket({"ip.src": ("10.0.0.7",)}), True),
            (FakePacket({"ip.src": ("10.0.0.1",)}), True),
            (FakePacket({"ip.src": ("10.0.0.10",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # ~in_ mirrors the != contract: true iff NO occurrence is in the set,
        # including the absent-field row.
        id="not-in",
        expr=~PORT.in_([80, 443]),
        dfilter="!(tcp.port in {80, 443})",
        rows=(
            (FakePacket({"tcp.port": ("443", "52034")}), False),
            (FakePacket({"tcp.port": ("8080",)}), True),
            (EMPTY, True),
        ),
    ),
    Case(
        # Time literals stay residual under membership too (M1 policy).
        id="in-time-residual",
        expr=TIME.in_([_MOMENT]),
        dfilter=None,
        rows=(
            (FakePacket({"frame.time": ("1625097600",)}), True),
            (FakePacket({"frame.time": ("1625097601",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="contains-str",
        expr=HOST.contains("ample"),
        dfilter='http.host contains "ample"',
        rows=(
            (FakePacket({"http.host": ("example.com",)}), True),
            (FakePacket({"http.host": ("other.org",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="contains-multi-value-any-occurrence",
        expr=QNAME.contains("example"),
        dfilter='dns.qry.name contains "example"',
        rows=(
            (FakePacket({"dns.qry.name": ("alpha.example", "beta.io")}), True),
            (FakePacket({"dns.qry.name": ("beta.io", "gamma.net")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="contains-bytes",
        expr=PAYLOAD.contains(b"\xbb\xcc"),
        dfilter="tcp.payload contains bb:cc",
        rows=(
            (FakePacket({"tcp.payload": ("aa:bb:cc:dd",)}), True),
            (FakePacket({"tcp.payload": ("aa:bb",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # Wireshark's `matches` is case-insensitive by default — pinned here
        # via the EXAMPLE.COM row on both backends.
        id="matches-case-insensitive",
        expr=HOST.matches("^ex.*com$"),
        dfilter='http.host matches "^ex.*com$"',
        rows=(
            (FakePacket({"http.host": ("example.com",)}), True),
            (FakePacket({"http.host": ("EXAMPLE.COM",)}), True),
            (FakePacket({"http.host": ("other.org",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # PCRE2 without UTF mode counts bytes, not characters; the predicate
        # backend mirrors that ("café" is 5 UTF-8 bytes).
        id="matches-byte-oriented",
        expr=HOST.matches("^.{5}$"),
        dfilter='http.host matches "^.{5}$"',
        rows=(
            (FakePacket({"http.host": ("café",)}), True),
            (FakePacket({"http.host": ("abcde",)}), True),
            (FakePacket({"http.host": ("abcd",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # Any-occurrence under matches, like every operator (PR #73 review).
        id="matches-multi-value-any-occurrence",
        expr=QNAME.matches("^alpha"),
        dfilter='dns.qry.name matches "^alpha"',
        rows=(
            (FakePacket({"dns.qry.name": ("beta.io", "alpha.example")}), True),
            (FakePacket({"dns.qry.name": ("beta.io", "gamma.net")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="not-matches-absent-is-true",
        expr=~HOST.matches("com"),
        dfilter='!(http.host matches "com")',
        rows=(
            (FakePacket({"http.host": ("example.com",)}), False),
            (EMPTY, True),
        ),
    ),
)


def _case_id(case: Case) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_dfilter_backend(case: Case) -> None:
    """Every case compiles to its golden dfilter string (or refuses loudly)."""
    if case.dfilter is None:
        with pytest.raises(UnsupportedExprError):
            compile_dfilter(case.expr)
    else:
        assert compile_dfilter(case.expr) == case.dfilter


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_predicate_backend(case: Case) -> None:
    """Every case's predicate selects exactly the expected rows."""
    pred = compile_predicate(case.expr)
    for index, (packet, expected) in enumerate(case.rows):
        assert pred(packet) is expected, f"row {index} of case {case.id!r}"


_SAMPLE_LITERALS: dict[type, LiteralValue] = {
    int: 1,
    bool: True,
    float: 1.0,
    str: "x",
    bytes: b"\x01",
    IPv4Address: IPv4Address("10.0.0.1"),
    IPv6Address: IPv6Address("2001:db8::1"),
    datetime: datetime(2026, 1, 1, tzinfo=timezone.utc),
    timedelta: timedelta(seconds=1),
}


@pytest.mark.parametrize("ftype", sorted(values.FTYPE_TABLE))
def test_every_ftype_py_type_is_a_valid_comparison_literal(ftype: str) -> None:
    """Cross-module drift guard (PR #46 review).

    ``values.FTYPE_TABLE`` and ``expr``'s literal union must stay in sync: if
    values grows an ftype whose ``py_type`` Expr rejects as a literal, the
    ``Comparison`` constructor raises TypeError here; if ``coerce_literal``
    stops accepting an ftype's own ``py_type``, ``compile_predicate`` raises.
    """
    info = values.FTYPE_TABLE[ftype]
    assert info.py_type in _SAMPLE_LITERALS, (
        f"no sample literal for py_type {info.py_type.__name__}; "
        "add it to _SAMPLE_LITERALS (and to expr.LiteralValue if needed)"
    )
    sample = _SAMPLE_LITERALS[info.py_type]
    expr = Comparison(CompareOp.EQ, FieldRef[object]("x.sample", ftype, False), sample)
    compile_predicate(expr)  # coerce_literal must accept the ftype's own py_type
