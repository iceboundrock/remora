"""The exhaustive Capture / Query parity matrix (issue #38).

The two-class design — :class:`remora.Capture` over a tshark subprocess and
:class:`remora.workspace.Query` over DuckDB — is only safe if both surfaces
answer the same question for the same ``Expr``. ``test_query_parity.py`` next
door spot-checks that; this module is the operator-by-operator table, run
end to end over the committed fixture pcaps with a real tshark and a real
workspace. Every row carries the **same** ``Expr`` down both paths and compares
the selected frame numbers.

Two empty sets compare equal, so a matrix that quietly stopped matching anything
would pass in silence. Three things stop that:

* every row declares its own ``expected`` frame numbers, and **both** paths are
  asserted against that declaration rather than only against each other;
* ``test_the_matrix_covers_every_frame`` asserts the union of all rows covers
  every frame of the fixture, so a fixture change that guts the matrix fails;
* ``test_only_the_declared_rows_are_empty`` pins the handful of rows that are
  deliberately empty by name, so no other row can decay into one.

Divergences are reported, never papered over: a row that genuinely disagreed
would be marked ``xfail(strict=True)`` with the backend bug it belongs to. As
of #38 there are none: all 49 rows (33 on ``tcp_mixed.pcap``, 16 on
``dns_multi.pcap``) agree under tshark 4.6.8 and duckdb 1.5.5.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

import pytest

# duckdb ships as the optional remora[workspace] extra, so a checkout without
# it skips cleanly, naming the install. In CI the skip is not allowed: the
# REMORA_REQUIRE_DUCKDB guard in tests/conftest.py stops the run outright, the
# mirror of the REMORA_REQUIRE_TSHARK escape hatch below.
pytest.importorskip("duckdb", reason="duckdb not installed; pip install 'remora[workspace]'")

from remora import DNS, IP, TCP, UDP, Capture
from remora.expr import Expr
from remora.workspace import Query, Workspace

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

# Every frame each fixture holds — the coverage test's target.
TCP_MIXED_FRAMES = frozenset({1, 2, 3, 4, 5})
DNS_MULTI_FRAMES = frozenset({1, 2, 3})

# REMORA_REQUIRE_TSHARK (set in CI) turns "tshark missing" from a skip into a
# hard failure, so a broken CI install can never silently skip the suite.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


@dataclass(frozen=True)
class Case:
    """One matrix row: an expression and the frame numbers it must select.

    ``expected`` is what makes the row non-vacuous. Both paths are compared
    against it, so a row cannot pass by matching nothing on both sides.
    """

    label: str
    expr: Expr
    expected: frozenset[int]


def case(label: str, expr: Expr, expected: set[int]) -> Case:
    return Case(label, expr, frozenset(expected))


def capture_frames(pcap: Path, expr: Expr) -> set[int]:
    """Frame numbers the pcap path selects — tshark dissecting the capture."""
    return {int(pkt.get_raw("frame.number")[0]) for pkt in Capture(pcap).filter(expr)}


def query_frames(query: Query) -> set[int]:
    """Frame numbers the cache path selects — DuckDB scanning the workspace."""
    numbers: set[int] = set()
    for row in query:
        assert row.frame_number is not None
        numbers.add(row.frame_number)
    return numbers


# --------------------------------------------------------------------------
# tcp_mixed.pcap — 1,2 TCP:443  3 TCP:8080  4 UDP/DNS  5 ARP (no ip.*, no tcp.*)
# --------------------------------------------------------------------------
TCP_MIXED_MATRIX: list[Case] = [
    # -- equality and the DSL's !=, on a scalar and on a multi-value column ---
    case("scalar ==", IP.src == "10.0.0.1", {1, 4}),
    # Frame 5 is ARP and carries no ip.src at all: Wireshark evaluates the
    # comparison false and negates it to true, and #36's coalesce-under-Not
    # makes DuckDB's three-valued NULL agree.
    case("scalar != (absent field included)", ~(IP.src == "10.0.0.1"), {2, 3, 5}),
    case("multi ==", TCP.port == 443, {1, 2}),
    # Frames 4 (UDP) and 5 (ARP) have no tcp.port; an absent multi column is
    # stored as [] rather than NULL, so any-occurrence equality is false and
    # the negation is true — same answer, a different mechanism.
    case("multi != (absent field included)", ~(TCP.port == 443), {3, 4, 5}),
    case("second multi-value field ==", UDP.port == 53, {4}),
    case("second multi-value field !=", ~(UDP.port == 53), {1, 2, 3, 5}),
    # -- ordering comparisons, scalar --------------------------------------
    case("scalar <", TCP.srcport < 1024, {2}),
    case("scalar <=", TCP.srcport <= 443, {2}),
    case("scalar >", TCP.srcport > 51234, {3}),
    case("scalar >=", TCP.srcport >= 51234, {1, 3}),
    # -- ordering comparisons, multi (any occurrence matches) --------------
    case("multi <", TCP.port < 1024, {1, 2}),
    case("multi <=", TCP.port <= 443, {1, 2}),
    case("multi >", TCP.port > 8080, {1, 2, 3}),
    case("multi >=", TCP.port >= 8080, {1, 2, 3}),
    # Addresses are stored as integers (#26), so ordering an FT_IPv4 column is
    # an integer comparison on both paths rather than text.
    case("address <", IP.src < "10.0.0.2", {1, 4}),
    case("address >=", IP.src >= "10.0.0.2", {2, 3}),
    # -- membership and the subnet range -----------------------------------
    case("membership, scalar", IP.src.in_(["10.0.0.1", "10.0.0.3"]), {1, 3, 4}),
    case("membership, multi", TCP.port.in_([443, 8080]), {1, 2, 3}),
    case(
        "subnet range",
        IP.src.in_([(IPv4Address("10.0.0.1"), IPv4Address("10.0.0.2"))]),
        {1, 2, 4},
    ),
    case("range, multi", TCP.port.in_([(1024, 60000)]), {1, 2, 3}),
    # -- presence -----------------------------------------------------------
    case("presence, scalar", IP.src.present(), {1, 2, 3, 4}),
    case("presence, multi", TCP.port.present(), {1, 2, 3}),
    case("negated presence, scalar", ~IP.src.present(), {5}),
    case("negated presence, multi", ~TCP.port.present(), {4, 5}),
    # -- boolean structure --------------------------------------------------
    case("conjunction", (IP.src == "10.0.0.1") & (TCP.port == 443), {1}),
    case("disjunction", (TCP.port == 8080) | (IP.src == "10.0.0.1"), {1, 3, 4}),
    case("negated conjunction", ~((IP.src == "10.0.0.1") & (TCP.port == 443)), {2, 3, 4, 5}),
    case("negated disjunction", ~((TCP.port == 8080) | (IP.src == "10.0.0.1")), {2, 5}),
    # Double negation is where a whole-subtree coalesce would go wrong
    # (NOT (NOT NULL) is NULL, but Python's `not not False` is False); #36
    # coalesces at the leaf precisely so this row holds.
    case("nested negation", ~(~(IP.src == "10.0.0.1")), {1, 4}),
    case("negation inside a conjunction", ~(TCP.port == 443) & IP.src.present(), {3, 4}),
    case(
        "negation inside a disjunction", ~(IP.src == "10.0.0.1") | (TCP.port == 443), {1, 2, 3, 5}
    ),
    # -- deliberately empty (pinned by test_only_the_declared_rows_are_empty) -
    case("scalar == a value no frame carries", IP.src == "192.168.99.99", set()),
    case("multi == a value no frame carries", TCP.port == 12345, set()),
]

# --------------------------------------------------------------------------
# dns_multi.pcap — 1 two questions (alpha.example, beta.example)
#                  2 one question (gamma.example)   3 TCP, no dns.*
# dns.qry.name is the multi-occurrence *text* column, so it is also where
# `matches` lives: the SQL backend's portable-text guard refuses non-ASCII,
# newline- or VT-bearing values, and these hostnames are plain ASCII.
# --------------------------------------------------------------------------
DNS_MULTI_MATRIX: list[Case] = [
    case("multi text ==", DNS.qry_name == "beta.example", {1}),
    case("multi text != (absent field included)", ~(DNS.qry_name == "beta.example"), {2, 3}),
    case("multi text <", DNS.qry_name < "beta.example", {1}),
    case("multi text >=", DNS.qry_name >= "beta.example", {1, 2}),
    case("multi text membership", DNS.qry_name.in_(["gamma.example", "zzz.example"]), {2}),
    case("multi text presence", DNS.qry_name.present(), {1, 2}),
    case("multi text negated presence", ~DNS.qry_name.present(), {3}),
    case("contains", DNS.qry_name.contains("alpha"), {1}),
    # matches: only the constructs all three engines (PCRE2, Python re, RE2)
    # run identically — ASCII, no lookarounds, repeats far below RE2's 1000.
    case("matches, anchored both ends", DNS.qry_name.matches(r"^alpha\.example$"), {1}),
    case("matches, anchored at the end", DNS.qry_name.matches(r"a\.example$"), {1, 2}),
    case("matches, character class", DNS.qry_name.matches(r"^[ab][a-z]+\.example$"), {1}),
    case(
        "matches, alternation in a non-capturing group", DNS.qry_name.matches(r"^(?:be|ga)"), {1, 2}
    ),
    case("matches, bounded repeat", DNS.qry_name.matches(r"^[a-z]{5}\.example$"), {1, 2}),
    # Wireshark's `matches` is case-insensitive, and so is the compiled
    # regexp_matches(..., 'i').
    case("matches, case-insensitive", DNS.qry_name.matches(r"^ALPHA\."), {1}),
    case("negated matches (absent field included)", ~DNS.qry_name.matches(r"^alpha\."), {2, 3}),
    case("matches nothing", DNS.qry_name.matches(r"^nope\."), set()),
]


@pytest.fixture(scope="module")
def tcp_mixed_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """tcp_mixed.pcap materialized whole, under every field the matrix names."""
    path = tmp_path_factory.mktemp("matrix") / "tcp_mixed.duckdb"
    with Workspace(path, mode="rw") as ws:
        result = ws.materialize(TCP_MIXED, [IP.src, TCP.port, TCP.srcport, UDP.port])
        assert result.row_count == len(TCP_MIXED_FRAMES)
    return path


@pytest.fixture(scope="module")
def dns_multi_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """dns_multi.pcap materialized whole, under dns.qry.name."""
    path = tmp_path_factory.mktemp("matrix") / "dns_multi.duckdb"
    with Workspace(path, mode="rw") as ws:
        result = ws.materialize(DNS_MULTI, [DNS.qry_name])
        assert result.row_count == len(DNS_MULTI_FRAMES)
    return path


def assert_row_parity(pcap: Path, workspace: Path, item: Case) -> None:
    """Both surfaces must select exactly ``item.expected`` for ``item.expr``."""
    from_pcap = capture_frames(pcap, item.expr)
    with Workspace(workspace) as ws:
        assert ws.mode == "ro"
        from_cache = query_frames(ws.query().filter(item.expr))
    assert from_cache == from_pcap, (
        f"Capture / Query divergence for {item.label!r} ({item.expr!r}): "
        f"pcap selected {sorted(from_pcap)}, cache selected {sorted(from_cache)}"
    )
    assert from_pcap == set(item.expected), (
        f"the pcap path no longer matches the declared expectation for {item.label!r}"
    )


@pytest.mark.parametrize("item", TCP_MIXED_MATRIX, ids=[c.label for c in TCP_MIXED_MATRIX])
def test_tcp_mixed_row_parity(tcp_mixed_workspace: Path, item: Case) -> None:
    assert_row_parity(TCP_MIXED, tcp_mixed_workspace, item)


@pytest.mark.parametrize("item", DNS_MULTI_MATRIX, ids=[c.label for c in DNS_MULTI_MATRIX])
def test_dns_multi_row_parity(dns_multi_workspace: Path, item: Case) -> None:
    assert_row_parity(DNS_MULTI, dns_multi_workspace, item)


def test_the_matrix_covers_every_frame() -> None:
    # A fixture change that gutted the matrix would leave rows matching nothing
    # and every row-parity assertion still passing (two empty sets are equal).
    tcp_covered = frozenset[int]().union(*(c.expected for c in TCP_MIXED_MATRIX))
    dns_covered = frozenset[int]().union(*(c.expected for c in DNS_MULTI_MATRIX))
    assert tcp_covered == TCP_MIXED_FRAMES
    assert dns_covered == DNS_MULTI_FRAMES


def test_only_the_declared_rows_are_empty() -> None:
    # Emptiness is a deliberate property of exactly three rows; naming them
    # keeps any other row from decaying into a vacuous pass.
    empty = {c.label for c in TCP_MIXED_MATRIX + DNS_MULTI_MATRIX if not c.expected}
    assert empty == {
        "scalar == a value no frame carries",
        "multi == a value no frame carries",
        "matches nothing",
    }


def test_the_matrix_labels_are_unique() -> None:
    labels = [c.label for c in TCP_MIXED_MATRIX + DNS_MULTI_MATRIX]
    assert len(labels) == len(set(labels))


def test_scalar_and_multi_values_match_the_pcap_path(tcp_mixed_workspace: Path) -> None:
    # Row parity is not value parity: a cache row could be selected correctly
    # and still decode to the wrong value. ip.src is the scalar codec
    # (FT_IPv4 -> UINTEGER -> IPv4Address), tcp.port the multi one.
    expr = IP.src.present()
    from_pcap = {
        int(pkt.get_raw("frame.number")[0]): (pkt[IP].src, pkt[TCP].port)
        for pkt in Capture(TCP_MIXED).filter(expr)
    }
    with Workspace(tcp_mixed_workspace) as ws:
        from_cache = {
            row.frame_number: (row.get(IP.src), row.get_all(TCP.port))
            for row in ws.query().filter(expr)
        }
    assert from_cache == from_pcap
    # Anti-vacuity: the comparison above must have had a multi-value field with
    # two occurrences and an absent one in it.
    assert from_pcap[1][1] == (51234, 443)
    assert from_pcap[4][1] == ()


def test_multi_occurrence_text_values_match_the_pcap_path(dns_multi_workspace: Path) -> None:
    expr = DNS.qry_name.present()
    from_pcap = {
        int(pkt.get_raw("frame.number")[0]): pkt[DNS].qry_name
        for pkt in Capture(DNS_MULTI).filter(expr)
    }
    with Workspace(dns_multi_workspace) as ws:
        from_cache = {
            row.frame_number: row.get_all(DNS.qry_name) for row in ws.query().filter(expr)
        }
    assert from_cache == from_pcap
    assert from_pcap[1] == ("alpha.example", "beta.example")


def test_the_absent_field_frame_is_covered_by_both_polarities(tcp_mixed_workspace: Path) -> None:
    # Frame 5 (ARP) is the #36 NULL-harmonization case, and the issue names it:
    # it must be *out* of every positive comparison and *in* every negated one,
    # for a scalar column (NULL) and a multi column ([]) alike.
    positive = [IP.src == "10.0.0.1", TCP.port == 443]
    with Workspace(tcp_mixed_workspace) as ws:
        for expr in positive:
            assert 5 not in capture_frames(TCP_MIXED, expr)
            assert 5 not in query_frames(ws.query().filter(expr))
            negated = ~expr
            assert 5 in capture_frames(TCP_MIXED, negated)
            assert 5 in query_frames(ws.query().filter(negated))
