"""Table-driven semantics suite run through THREE compile backends.

ONE table of cases, each executed against the display-filter backend (golden
string, or an expected :class:`UnsupportedExprError` when the expression is
not pushdown-able), the Python predicate backend (packet rows with expected
boolean results), and the SQL backend run through DuckDB
(``tests/test_sql_duckdb.py``, gated on duckdb). Because all three parametrized
tests consume the same ``Case`` objects, the three backends cannot drift apart
silently.

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
RESP = FieldRef[float]("icmp.resptime", "FT_DOUBLE", False)

EMPTY = FakePacket({})

NAN = float("nan")
INF = float("inf")


@dataclass(frozen=True)
class Case:
    """One semantics scenario, shared verbatim by all three backend tests.

    ``rows`` is the single expected row set: the display-filter, Python
    predicate and DuckDB SQL backends must all select exactly the packets
    flagged True. The two escape hatches below are the only ways a backend is
    allowed to differ, and each one is a *loud* difference (a refusal or an
    error), never a quiet row-set fork.
    """

    id: str
    expr: Expr
    dfilter: str | None
    """Expected golden dfilter string; None = UnsupportedExprError expected."""
    rows: tuple[tuple[FakePacket, bool], ...]
    """(packet, expected result) pairs — the same answer on all three backends."""
    sql_refusal: str | None = None
    """Regex fragment the SQL backend's UnsupportedSqlExprError must match;
    None means compile_sql must succeed."""
    sql_guard_rows: frozenset[int] = frozenset()
    """Row indices whose stored text trips the SQL backend's portable-text
    guard, so the DuckDB run raises instead of returning rows."""


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
        # IEEE-754 NaN (issue #90). Same row set on all three backends, reached
        # three different ways: the dfilter backend REFUSES (Wireshark does not
        # give NaN Python's semantics, so the planner falls back to the Python
        # predicate, which does), the SQL backend compiles the constant FALSE
        # (issue #88), and the predicate backend just evaluates Python.
        id="nan-literal-gt",
        expr=RESP > NAN,
        dfilter=None,
        rows=(
            (FakePacket({"icmp.resptime": ("0.25",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # The negated twin: `!=` is Not(Comparison(EQ, ...)), so `not False` is
        # True for every packet, the absent one included.
        id="nan-literal-ne",
        expr=RESP != NAN,
        dfilter=None,
        rows=(
            (FakePacket({"icmp.resptime": ("0.25",)}), True),
            (EMPTY, True),
        ),
    ),
    Case(
        id="nan-literal-membership",
        expr=RESP.in_([NAN]),
        dfilter=None,
        rows=(
            (FakePacket({"icmp.resptime": ("0.25",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        # inf is NOT refused anywhere: all three engines order it identically,
        # so it stays a pushdown. Here so the NaN rows above cannot be widened
        # to cover it without this row failing.
        id="inf-literal-lt",
        expr=RESP < INF,
        dfilter="icmp.resptime < inf",
        rows=(
            (FakePacket({"icmp.resptime": ("0.25",)}), True),
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
        sql_refusal="BLOB",
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
        # backend mirrors that ("café" is 5 UTF-8 bytes). DuckDB's RE2 counts
        # runes, so the portable-text guard refuses row 0 outright rather than
        # silently answering differently (issue #36).
        id="matches-byte-oriented",
        expr=HOST.matches("^.{5}$"),
        dfilter='http.host matches "^.{5}$"',
        rows=(
            (FakePacket({"http.host": ("café",)}), True),
            (FakePacket({"http.host": ("abcde",)}), True),
            (FakePacket({"http.host": ("abcd",)}), False),
            (EMPTY, False),
        ),
        sql_guard_rows=frozenset({0}),
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
    Case(
        # Double negation is the ONE shape where the SQL backend's leaf-level
        # coalesce and a subtree-level one part company on row sets rather than
        # only on emitted text: over an absent (NULL) scalar, coalescing at each
        # Not gives NOT(coalesce(NOT(NULL), FALSE)) = TRUE, where Python's
        # `not not False` — and Wireshark's `!(!(...))` — is False. Without this
        # case that claim rested entirely on tests/test_sql.py's golden strings.
        id="not-not-eq-scalar",
        expr=~~(TTL == 64),
        dfilter="!(!(ip.ttl == 64))",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("65",)}), False),
            (EMPTY, False),
        ),
    ),
)


#: The operators the absent-field truth table covers. `!=` is not listed
#: separately: the DSL has no Ne node, so `f != v` IS `~(f == v)` and appears as
#: the negated twin of the `==` row.
TRUTH_OPERATORS: tuple[str, ...] = (
    "==",
    "<",
    "<=",
    ">",
    ">=",
    "in",
    "contains",
    "matches",
    "present",
)

#: Operator label -> the id suffix used by NULL_TRUTH_POSITIVE.
_OP_SLUG: dict[str, str] = {
    "==": "eq",
    "<": "lt",
    "<=": "le",
    ">": "gt",
    ">=": "ge",
    "in": "in",
    "contains": "contains",
    "matches": "matches",
    "present": "present",
}

#: One packet that satisfies each positive test, one that does not, and EMPTY.
#: EMPTY is the whole point: every positive operator is False on an absent
#: field, on every backend, whether the column stores NULL (scalar) or []
#: (multi) — and every negated one is therefore True. Where these restate a case
#: the base table above already covers (the four `null-*-scalar` ordering cases
#: and `null-in-multi`) the overlap is intentional: the point is a complete grid
#: over operator, multiplicity and polarity, not duplication to clean up.
NULL_TRUTH_POSITIVE: tuple[Case, ...] = (
    Case(
        id="null-eq-scalar",
        expr=TTL == 64,
        dfilter="ip.ttl == 64",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("63",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-eq-multi",
        expr=PORT == 443,
        dfilter="tcp.port == 443",
        rows=(
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (FakePacket({"tcp.port": ("52034", "80")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-lt-scalar",
        expr=TTL < 64,
        dfilter="ip.ttl < 64",
        rows=(
            (FakePacket({"ip.ttl": ("63",)}), True),
            (FakePacket({"ip.ttl": ("64",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-lt-multi",
        expr=PORT < 1024,
        dfilter="tcp.port < 1024",
        rows=(
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (FakePacket({"tcp.port": ("52034", "8080")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-le-scalar",
        expr=TTL <= 64,
        dfilter="ip.ttl <= 64",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("65",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-le-multi",
        expr=PORT <= 443,
        dfilter="tcp.port <= 443",
        rows=(
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (FakePacket({"tcp.port": ("52034", "8080")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-gt-scalar",
        expr=TTL > 64,
        dfilter="ip.ttl > 64",
        rows=(
            (FakePacket({"ip.ttl": ("65",)}), True),
            (FakePacket({"ip.ttl": ("64",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-gt-multi",
        expr=PORT > 1024,
        dfilter="tcp.port > 1024",
        rows=(
            (FakePacket({"tcp.port": ("443", "52034")}), True),
            (FakePacket({"tcp.port": ("80", "443")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-ge-scalar",
        expr=TTL >= 64,
        dfilter="ip.ttl >= 64",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (FakePacket({"ip.ttl": ("63",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-ge-multi",
        expr=PORT >= 1024,
        dfilter="tcp.port >= 1024",
        rows=(
            (FakePacket({"tcp.port": ("443", "52034")}), True),
            (FakePacket({"tcp.port": ("80", "443")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-in-scalar",
        expr=TTL.in_([64, 128]),
        dfilter="ip.ttl in {64, 128}",
        rows=(
            (FakePacket({"ip.ttl": ("128",)}), True),
            (FakePacket({"ip.ttl": ("63",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-in-multi",
        expr=PORT.in_([80, 443]),
        dfilter="tcp.port in {80, 443}",
        rows=(
            (FakePacket({"tcp.port": ("52034", "443")}), True),
            (FakePacket({"tcp.port": ("52034", "8080")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-contains-scalar",
        expr=HOST.contains("ample"),
        dfilter='http.host contains "ample"',
        rows=(
            (FakePacket({"http.host": ("example.com",)}), True),
            (FakePacket({"http.host": ("other.org",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-contains-multi",
        expr=QNAME.contains("ample"),
        dfilter='dns.qry.name contains "ample"',
        rows=(
            (FakePacket({"dns.qry.name": ("beta.io", "alpha.example")}), True),
            (FakePacket({"dns.qry.name": ("beta.io", "gamma.net")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-matches-scalar",
        expr=HOST.matches("^ex"),
        dfilter='http.host matches "^ex"',
        rows=(
            (FakePacket({"http.host": ("example.com",)}), True),
            (FakePacket({"http.host": ("other.org",)}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-matches-multi",
        expr=QNAME.matches("^alpha"),
        dfilter='dns.qry.name matches "^alpha"',
        rows=(
            (FakePacket({"dns.qry.name": ("beta.io", "alpha.example")}), True),
            (FakePacket({"dns.qry.name": ("beta.io", "gamma.net")}), False),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-present-scalar",
        expr=TTL.present(),
        dfilter="ip.ttl",
        rows=(
            (FakePacket({"ip.ttl": ("64",)}), True),
            (EMPTY, False),
        ),
    ),
    Case(
        id="null-present-multi",
        expr=PORT.present(),
        dfilter="tcp.port",
        rows=(
            (FakePacket({"tcp.port": ("443",)}), True),
            (EMPTY, False),
        ),
    ),
)


def _negated(case: Case) -> Case:
    """The ``~case.expr`` twin: same packets, inverted expectations.

    Every backend must invert together — that is the whole claim. The dfilter
    golden is the ``!(...)`` wrapper compile_dfilter renders for any Not, and a
    case the dfilter backend refuses stays refused under negation.
    """
    return Case(
        id=f"not-{case.id}",
        expr=~case.expr,
        dfilter=None if case.dfilter is None else f"!({case.dfilter})",
        rows=tuple((packet, not hit) for packet, hit in case.rows),
        sql_refusal=case.sql_refusal,
        sql_guard_rows=case.sql_guard_rows,
    )


NULL_TRUTH_CASES: tuple[Case, ...] = NULL_TRUTH_POSITIVE + tuple(
    _negated(case) for case in NULL_TRUTH_POSITIVE
)

CASES = CASES + NULL_TRUTH_CASES


class TestTruthTableCompleteness:
    """The absent-field truth table is complete and matches its own claim."""

    def test_every_operator_multiplicity_polarity_triple_is_covered(self) -> None:
        expected = {
            f"{prefix}null-{_OP_SLUG[op]}-{multi}"
            for op in TRUTH_OPERATORS
            for multi in ("scalar", "multi")
            for prefix in ("", "not-")
        }
        assert {case.id for case in NULL_TRUTH_CASES} == expected
        assert len(expected) == len(TRUTH_OPERATORS) * 2 * 2

    def test_every_positive_case_is_false_on_the_absent_packet(self) -> None:
        for case in NULL_TRUTH_POSITIVE:
            packet, hit = case.rows[-1]
            assert packet is EMPTY, case.id
            assert hit is False, case.id

    def test_every_negated_case_is_true_on_the_absent_packet(self) -> None:
        for case in NULL_TRUTH_CASES:
            if not case.id.startswith("not-"):
                continue
            packet, hit = case.rows[-1]
            assert packet is EMPTY, case.id
            assert hit is True, case.id

    def test_the_truth_cases_are_in_the_shared_table(self) -> None:
        ids = {case.id for case in CASES}
        assert {case.id for case in NULL_TRUTH_CASES} <= ids

    def test_case_ids_are_unique(self) -> None:
        ids = [case.id for case in CASES]
        assert len(ids) == len(set(ids))


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
