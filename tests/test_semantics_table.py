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

from remora import values
from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import CompareOp, Comparison, Expr, FieldExprOps, LiteralValue


class StubField(FieldExprOps):
    """Minimal FieldLike for tests; FieldRef (issue #8) looks like this."""

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


class FakePacket:
    """Minimal RawPacket: absent fields are ()."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())


SRC = StubField("ip.src", "FT_IPv4")
DST = StubField("ip.dst", "FT_IPv4")
PORT = StubField("tcp.port", "FT_UINT16", multi=True)
TTL = StubField("ip.ttl", "FT_UINT8")
HOST = StubField("http.host", "FT_STRING")
TIME = StubField("frame.time", "FT_ABSOLUTE_TIME")

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
    expr = Comparison(CompareOp.EQ, StubField("x.sample", ftype), sample)
    compile_predicate(expr)  # coerce_literal must accept the ftype's own py_type
