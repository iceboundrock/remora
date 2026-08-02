"""Validate compiled display filters against a real tshark (issue #18).

Two halves:

1. Syntax: every golden string in dfilter_corpus.GOLDEN and every filter
   compiled from exprgen's 200-tree seeded corpus must be accepted by
   ``tshark -r <fixture> -Y <filter>``. Filters are batch-validated in
   OR-joined chunks (one tshark spawn per ~32 filters); a failing chunk is
   bisected filter-by-filter so the report names each offending tree and
   filter string.

2. Semantics: the row set tshark returns for ``!(x == v)`` must match the
   predicate backend's row set for the DSL's ``!=`` on the fixture pcaps —
   including the multi-value (tcp.port) and absent-field (ARP frame) cases.

Runs whenever tshark is installed; in CI, REMORA_REQUIRE_TSHARK=1 turns the
"tshark missing" skip into a hard failure so the suite can never silently
vanish.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dfilter_corpus import GOLDEN
from exprgen import gen_corpus
from remora import DNS, IP, TCP, UDP, Capture
from remora.compile.dfilter import compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

# Same skip contract as tests/integration/: skipped with a clear message when
# tshark is absent locally; REMORA_REQUIRE_TSHARK (set in CI) turns a missing
# tshark into a hard failure instead of a silent skip.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping dfilter validation tests",
    ),
]

_TSHARK = os.environ.get("TSHARK") or "tshark"
_CHUNK_SIZE = 32


def _run_tshark(dfilter: str) -> subprocess.CompletedProcess[str]:
    """Run tshark over the tcp_mixed fixture with *dfilter* as ``-Y``.

    ``-n`` disables name resolution: no DNS lookups, so validation is
    hermetic and fast. argv list, never ``shell=True``.
    """
    argv = [_TSHARK, "-n", "-r", str(TCP_MIXED), "-Y", dfilter]
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _assert_all_valid(cases: list[tuple[str, str]]) -> None:
    """``cases`` is (description, filter). Chunk-validate via OR-join; on a
    failing chunk, re-check each filter individually to attribute blame."""
    failures: list[str] = []
    for start in range(0, len(cases), _CHUNK_SIZE):
        chunk = cases[start : start + _CHUNK_SIZE]
        joined = " || ".join(f"({dfilter})" for _, dfilter in chunk)
        if _run_tshark(joined).returncode == 0:
            continue
        for description, dfilter in chunk:
            result = _run_tshark(dfilter)
            if result.returncode != 0:
                failures.append(
                    f"{description}\n  filter: {dfilter}\n  tshark: {result.stderr.strip()}"
                )
    if failures:
        pytest.fail(
            "tshark rejected compiled display filters:\n" + "\n".join(failures), pytrace=False
        )


class TestGoldenCorpusValidates:
    def test_every_golden_string_is_accepted_by_tshark(self) -> None:
        _assert_all_valid([(f"golden[{case.id}]", case.expected) for case in GOLDEN])


class TestGeneratedCorpusValidates:
    def test_all_generated_filters_are_accepted_by_tshark(self) -> None:
        trees = gen_corpus()
        assert len(trees) >= 200
        _assert_all_valid(
            [(f"tree[{i}]: {tree!r}", compile_dfilter(tree)) for i, tree in enumerate(trees)]
        )


def _tshark_matching_frames(pcap: Path, dfilter: str) -> set[int]:
    argv = [
        _TSHARK,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        dfilter,
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"tshark rejected {dfilter!r}: {result.stderr.strip()}"
    return {int(line) for line in result.stdout.split() if line}


def _predicate_matching_frames(pcap: Path, expr: Expr) -> set[int]:
    predicate = compile_predicate(expr)
    packets = list(Capture(pcap))  # no filter: every frame, in file order
    return {number for number, packet in enumerate(packets, start=1) if predicate(packet)}


class TestNeSemanticsParity:
    """The DSL's ``!=`` compiles to ``!(x == v)``; tshark's row set for that
    filter must equal the predicate backend's row set for the same Expr —
    multi-value fields match on ANY occurrence, and frames lacking the field
    entirely (the ARP frame) satisfy the negation on both sides."""

    @pytest.mark.parametrize(
        ("pcap", "expr"),
        [
            pytest.param(TCP_MIXED, TCP.port != 443, id="multi-value-tcp-port"),
            pytest.param(TCP_MIXED, IP.src != "10.0.0.1", id="scalar-ip-src"),
            pytest.param(TCP_MIXED, UDP.dstport != 53, id="mostly-absent-udp-dstport"),
            pytest.param(DNS_MULTI, DNS.qry_name != "alpha.example", id="multi-occurrence-dns"),
        ],
    )
    def test_ne_row_set_matches_predicate_backend(self, pcap: Path, expr: Expr) -> None:
        dfilter = compile_dfilter(expr)
        assert dfilter.startswith("!(")  # sanity: != really is negated ==
        assert _tshark_matching_frames(pcap, dfilter) == _predicate_matching_frames(pcap, expr)
