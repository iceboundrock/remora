"""The workspace break-even benchmark (issue #38).

M4 exists on one claim: dissecting a capture once into DuckDB makes the
*second* question cheaper than asking tshark again. This module measures that
claim end to end on a ~20k-packet synthetic capture — the same expression run
through :class:`remora.Capture` (a fresh tshark subprocess dissecting every
packet) and through :class:`remora.workspace.Query` (a DuckDB scan over columns
dissected once).

Methodology, chosen to be flake-resistant rather than flattering:

* one discarded warm-up per side, so page cache and interpreter warm-up are not
  charged to the first timed run;
* ``TIMED_RUNS`` (5) timed runs per side, interleaved so a burst of system noise
  lands on both sides, and the **median** is compared — a single stalled run
  cannot move it;
* both sides count their rows, and the counts are asserted equal and non-zero,
  so the benchmark can never time a query that quietly returns nothing.

Measured on an Apple M-series laptop (tshark 4.6.8, duckdb 1.5.5, 20 000
packets, the filter selecting 1 000 of them), across three runs:

* materialize: 13.0-18.7 s (one-time)
* pcap re-parse, median of 5: 0.52-1.13 s
* cached query, median of 5: 0.0041-0.0066 s
* speedup: 121-172x, so materialization pays for itself after 17-33 repeat
  queries

The spread across those runs is the point of the median: an unloaded laptop
gave 0.52 s per re-parse and a busy one 1.13 s, and the ratio still never came
within an order of magnitude of the floor.

``MIN_SPEEDUP`` is asserted at 10x — an order of magnitude below what was
measured, because CI runners are shared, slower and noisy, and this test is a
regression net for "the cache stopped being worth it", not a performance
dashboard. The absolute numbers above are machine-specific and will differ on
any other host; the ratio is the durable claim.

Marked ``slow``: deselect with ``-m "not slow"``.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

# duckdb ships as the optional remora[workspace] extra, so a checkout without
# it skips cleanly, naming the install. In CI the skip is not allowed: the
# REMORA_REQUIRE_DUCKDB guard in tests/conftest.py stops the run outright, the
# mirror of the REMORA_REQUIRE_TSHARK escape hatch below.
pytest.importorskip("duckdb", reason="duckdb not installed; pip install 'remora[workspace]'")

from remora import IP, TCP, Capture
from remora.expr import Expr
from remora.workspace import Workspace

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"

#: Packets in the synthetic capture. Big enough that tshark's dissection, not
#: its startup, dominates the pcap side; small enough that materializing it
#: stays a handful of seconds.
PACKET_COUNT = 20_000

#: Timed runs per side, after one discarded warm-up. Median of 5.
TIMED_RUNS = 5

#: The asserted floor, an order of magnitude below the measured 121-172x.
MIN_SPEEDUP = 10.0

#: The question both paths answer. build_bulk_tcp cycles ten source hosts and
#: four destination ports, so this conjunction selects exactly a twentieth of
#: the capture — 1 000 rows at 20 000 packets.
BENCHMARK_EXPR: Expr = (TCP.port == 443) & (IP.src == "10.0.0.1")
EXPECTED_ROWS = PACKET_COUNT // 20

# REMORA_REQUIRE_TSHARK (set in CI) turns "tshark missing" from a skip into a
# hard failure, so a broken CI install can never silently skip the suite.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


def load_fixture_generator() -> ModuleType:
    """Load tests/fixtures/make_fixtures.py by path (tests/ is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "make_fixtures", FIXTURES_DIR / "make_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Bench:
    """The benchmark's subject: a bulk capture and a workspace built from it."""

    pcap: Path
    workspace: Path
    materialize_seconds: float
    row_count: int


@pytest.fixture(scope="module")
def bench(tmp_path_factory: pytest.TempPathFactory) -> Bench:
    """Build the bulk capture in tmp_path and materialize it once.

    The capture is deliberately not a committed fixture — 20 000 packets have
    no business in the repository — so it is generated here from
    ``make_fixtures.build_bulk_tcp`` and dies with the temp directory.
    """
    directory = tmp_path_factory.mktemp("benchmark")
    pcap = directory / "bulk.pcap"
    pcap.write_bytes(load_fixture_generator().build_bulk_tcp(PACKET_COUNT))

    workspace = directory / "bulk.duckdb"
    started = time.perf_counter()
    with Workspace(workspace, mode="rw") as ws:
        result = ws.materialize(pcap, [IP.src, TCP.port])
    elapsed = time.perf_counter() - started
    assert result.row_count == PACKET_COUNT
    return Bench(pcap, workspace, elapsed, result.row_count)


def test_the_cached_query_beats_re_parsing_the_pcap(bench: Bench) -> None:
    def from_pcap() -> int:
        return sum(1 for _ in Capture(bench.pcap).filter(BENCHMARK_EXPR))

    with Workspace(bench.workspace) as ws:
        assert ws.mode == "ro"

        def from_cache() -> int:
            return sum(1 for _ in ws.query().filter(BENCHMARK_EXPR))

        # Interleaved: alternating the sides spreads any burst of system noise
        # across both medians instead of loading it onto whichever ran first.
        pcap_timings: list[float] = []
        cache_timings: list[float] = []
        pcap_rows = from_pcap()  # warm-up, discarded
        cache_rows = from_cache()  # warm-up, discarded
        for _ in range(TIMED_RUNS):
            started = time.perf_counter()
            assert from_pcap() == pcap_rows
            pcap_timings.append(time.perf_counter() - started)
            started = time.perf_counter()
            assert from_cache() == cache_rows
            cache_timings.append(time.perf_counter() - started)

    pcap_median = statistics.median(pcap_timings)
    cache_median = statistics.median(cache_timings)
    speedup = pcap_median / cache_median
    queries_to_break_even = bench.materialize_seconds / (pcap_median - cache_median)

    print(
        f"\nbreak-even benchmark ({PACKET_COUNT} packets, {pcap_rows} selected)\n"
        f"  materialize (one-time): {bench.materialize_seconds:.3f}s\n"
        f"  pcap re-parse, median of {TIMED_RUNS}: {pcap_median:.4f}s {pcap_timings}\n"
        f"  cached query, median of {TIMED_RUNS}: {cache_median:.4f}s {cache_timings}\n"
        f"  speedup: {speedup:.1f}x (floor asserted: {MIN_SPEEDUP}x)\n"
        f"  materialization pays for itself after {queries_to_break_even:.1f} repeat queries"
    )

    # Anti-vacuity: a benchmark over an empty result set proves nothing, and
    # two sides counting differently are not running the same query.
    assert pcap_rows == EXPECTED_ROWS
    assert cache_rows == pcap_rows
    assert speedup >= MIN_SPEEDUP, (
        f"cached query is only {speedup:.1f}x faster than re-parsing the pcap "
        f"(pcap median {pcap_median:.4f}s, cache median {cache_median:.4f}s); "
        f"the workspace's whole reason to exist is that this stays well above "
        f"{MIN_SPEEDUP}x"
    )


def test_the_one_time_materialization_cost_is_reported(bench: Bench) -> None:
    # The materialization is the price the break-even is measured against; it
    # is reported rather than bounded, because it is dominated by tshark's
    # dissection of the whole capture and so tracks the runner, not remora.
    print(
        f"\nmaterialized {bench.row_count} packets in {bench.materialize_seconds:.3f}s "
        f"({bench.workspace.stat().st_size} bytes on disk)"
    )
    assert bench.materialize_seconds > 0.0
    assert bench.row_count == PACKET_COUNT


def test_the_two_paths_select_the_same_frames_at_scale(bench: Bench) -> None:
    # Parity at 5 packets (test_parity_matrix.py) does not imply parity at
    # 20 000: batched appends, the -Y pushdown and DuckDB's row groups all
    # only start behaving like themselves at size.
    from_pcap = {
        int(pkt.get_raw("frame.number")[0]) for pkt in Capture(bench.pcap).filter(BENCHMARK_EXPR)
    }
    with Workspace(bench.workspace) as ws:
        from_cache = {row.frame_number for row in ws.query().filter(BENCHMARK_EXPR)}
    assert len(from_pcap) == EXPECTED_ROWS
    assert from_cache == from_pcap
