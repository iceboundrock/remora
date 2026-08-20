"""Capture / Query parity over the fixture pcaps (issue #35).

The point of the cache path is that it answers the same question the pcap path
answers. This suite materializes a capture into a workspace and then runs the
*same* ``Expr`` through both surfaces — :class:`remora.Capture` over tshark and
:class:`remora.workspace.Query` over DuckDB — comparing the selected frame
numbers. It is a spot check by design: the exhaustive operator matrix is the M4
integration-test issue's job, and the operator-level semantics are already
pinned backend-to-backend in ``tests/test_sql_duckdb.py``.

One divergence used to be asserted rather than papered over: SQL is three-valued,
so a negated comparison on a scalar column excluded rows where the field is
absent, which Wireshark and the Python predicate backend include. Issue #29
stated that and explicitly did not harmonize it; issue #36 removed it by making
every NULL-able leaf beneath a ``Not`` two-valued with ``coalesce(..., FALSE)``,
so this suite now asserts equality there too.
"""

from __future__ import annotations

import os
import shutil
from ipaddress import IPv4Address
from pathlib import Path

import pytest

pytest.importorskip("duckdb")

from remora import DNS, IP, TCP, Capture
from remora.expr import Expr
from remora.fields import FieldRef
from remora.workspace import Query, Workspace

# No generated FRAME protocol class exists (frame is not in codegen.toml's
# [generate].protocols), so the row key is referenced the way a user would have
# to: a hand-built ref carrying tshark's own -G fields declaration.
FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

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


def capture_frames(pcap: Path, expr: Expr) -> set[int]:
    """Frame numbers the pcap path selects — tshark dissecting the capture."""
    return {int(pkt.get_raw("frame.number")[0]) for pkt in Capture(pcap).filter(expr)}


def query_frames(query: Query) -> set[int]:
    """Frame numbers the cache path selects — DuckDB scanning the workspace."""
    numbers = set()
    for row in query:
        assert row.frame_number is not None
        numbers.add(row.frame_number)
    return numbers


TCP_MIXED_CASES: list[tuple[str, Expr]] = [
    ("multi-value equality", TCP.port == 443),
    ("scalar equality", IP.src == "10.0.0.1"),
    ("conjunction", (IP.src == "10.0.0.1") & (TCP.port == 443)),
    ("disjunction", (TCP.port == 8080) | (IP.src == "10.0.0.1")),
    ("presence", IP.src.present()),
    ("subnet range", IP.src.in_([(IPv4Address("10.0.0.1"), IPv4Address("10.0.0.2"))])),
    ("membership", TCP.port.in_([443, 8080])),
    ("ordered comparison", TCP.port < 1024),
    ("no match", IP.src == "192.168.99.99"),
    ("negated scalar equality", ~(IP.src == "10.0.0.1")),
]


@pytest.fixture(scope="module")
def tcp_mixed_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """tcp_mixed.pcap materialized whole (no filter) under ip.src / tcp.port."""
    path = tmp_path_factory.mktemp("parity") / "tcp_mixed.duckdb"
    with Workspace(path, mode="rw") as ws:
        result = ws.materialize(TCP_MIXED, [IP.src, TCP.port])
        assert result.row_count == 5
    return path


@pytest.mark.parametrize(
    "expr", [case for _label, case in TCP_MIXED_CASES], ids=[label for label, _ in TCP_MIXED_CASES]
)
def test_same_filter_selects_the_same_frames(tcp_mixed_workspace: Path, expr: Expr) -> None:
    expected = capture_frames(TCP_MIXED, expr)
    with Workspace(tcp_mixed_workspace) as ws:
        assert ws.mode == "ro"
        assert query_frames(ws.query().filter(expr)) == expected


def test_the_parity_cases_are_not_all_vacuous(tcp_mixed_workspace: Path) -> None:
    # Two empty sets compare equal, so at least prove the fixture selects rows.
    with Workspace(tcp_mixed_workspace) as ws:
        assert query_frames(ws.query().filter(TCP.port == 443)) == {1, 2}
        assert query_frames(ws.query()) == {1, 2, 3, 4, 5}


def test_row_key_is_reachable_by_reference_after_a_real_materialize(
    tcp_mixed_workspace: Path,
) -> None:
    # The declarations here are the real ones: proto refs from codegen for the
    # field columns, tshark's -G fields ftype for the row key.
    with Workspace(tcp_mixed_workspace) as ws:
        rows = list(ws.query().select(IP.src))
    assert [row.get(FRAME_NUMBER) for row in rows] == [1, 2, 3, 4, 5]
    assert all(row.get(FRAME_NUMBER) == row.frame_number for row in rows)


def test_row_values_match_the_pcap_path(tcp_mixed_workspace: Path) -> None:
    expr = TCP.port == 443
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


def test_multi_occurrence_field_parity(tmp_path: Path) -> None:
    path = tmp_path / "dns.duckdb"
    with Workspace(path, mode="rw") as ws:
        ws.materialize(DNS_MULTI, [DNS.qry_name])
    expr = DNS.qry_name == "beta.example"
    with Workspace(path) as ws:
        assert query_frames(ws.query().filter(expr)) == capture_frames(DNS_MULTI, expr)
        row = next(iter(ws.query().filter(DNS.qry_name.present())))
        assert row.get_all(DNS.qry_name) == ("alpha.example", "beta.example")


def test_negation_over_an_absent_scalar_matches_the_pcap_path(
    tcp_mixed_workspace: Path,
) -> None:
    # Frame 5 is ARP: no ip.src at all. Wireshark evaluates `ip.src == x` as
    # false and negates it to true. SQL used to evaluate `"ip_src" = ?` as NULL
    # and drop the row (#29 stated that); #36 harmonizes it with a coalesce on
    # leaves beneath a Not, so the two paths now agree. This is the issue's
    # named regression test.
    expr = ~(IP.src == "10.0.0.1")
    from_pcap = capture_frames(TCP_MIXED, expr)
    with Workspace(tcp_mixed_workspace) as ws:
        from_cache = query_frames(ws.query().filter(expr))
    assert 5 in from_pcap
    assert from_cache == from_pcap
