"""The workspace break-even benchmark (issue #38).

M4 exists on one claim: dissecting a capture once into DuckDB makes the
*second* question cheaper than asking tshark again. This module measures that
claim end to end on a ~20k-packet synthetic capture — the same expression run
through :class:`remora.Capture` (a fresh tshark subprocess dissecting every
packet) and through :class:`remora.workspace.Query` (a DuckDB scan over columns
dissected once).

Which pcap baseline (issue #105)
--------------------------------
The asserted ratio is measured against the **projected** pcap path —
``Capture(pcap).select(IP.src, TCP.port).filter(...)``, which plans to
``-T fields`` — and not against a bare ``Capture``, which falls back to the
``-T ek`` whole-packet NDJSON. Two reasons, and only the second is about
honesty:

* ``select()`` did not exist when this benchmark was written, so ``-T ek`` was
  the only pcap path the public surface could reach. #105 made fields mode
  reachable, and a benchmark should measure what the planner is capable of
  rather than what it used to be limited to.
* the projection names *exactly* the field set the workspace was materialized
  with, so both sides produce the same columns and the ratio isolates one
  effect: dissect the capture again versus scan columns dissected once. The ek
  baseline bundled a second, unrelated effect into that number — tshark
  rendering every field of every packet as JSON that remora then parses and
  throws away — which is worth 2.1-2.5x here on its own, and inflated the old
  headline 121-172x by roughly that factor.

The ek side is still measured and still printed, precisely so that component
stays visible rather than being absorbed into a smaller headline number. It is
reported, never asserted: it is a property of the fallback mode, not of the
claim M4 rests on.

Methodology, chosen to be flake-resistant rather than flattering:

* one discarded warm-up per side, so page cache and interpreter warm-up are not
  charged to the first timed run;
* ``TIMED_RUNS`` (5) timed runs per side, the three sides interleaved so a burst
  of system noise lands on all of them, and the **medians** are compared — a
  single stalled run cannot move one;
* all three sides count their rows, and the counts are asserted equal and
  non-zero, so the benchmark can never time a query that quietly returns
  nothing.

Measured on an Apple M-series laptop (tshark 4.6.8, duckdb 1.5.5, 20 000
packets, the filter selecting 1 000 of them), across four runs:

* materialize: 16.6-18.8 s (one-time)
* pcap re-parse ``-T ek``, median of 5: 0.557-0.590 s
* pcap re-parse ``-T fields``, median of 5: 0.221-0.278 s
* cached query, median of 5: 0.0047-0.0051 s
* ek / fields: 2.1-2.5x — the component #105 identified, reported only
* speedup over the projected baseline: 47-54x, so materialization pays for
  itself after 61-83 repeat queries

The spread across those runs is the point of the median: one run's ek side
stalled at 0.92 s on a single iteration and the median moved by nothing.

``MIN_SPEEDUP`` is asserted at 5x — an order of magnitude below what was
measured, because CI runners are shared, slower and noisy, and this test is a
regression net for "the cache stopped being worth it", not a performance
dashboard. It was 10x against the ek baseline's 121-172x, which was that same
order-of-magnitude margin; keeping 10x against a 47-54x measurement would have
quietly halved the headroom to 4.7x, and the projected baseline needs the
margin *more*, not less — it cut the numerator by 2.4x while leaving the
denominator a ~5 ms query, where a shared runner's scheduling stall costs
proportionally far more than it does on a quarter-second subprocess. The
absolute numbers above are machine-specific and will differ on any other host;
the ratio is the durable claim.

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

#: The asserted floor, an order of magnitude below the measured 47-54x — the
#: same margin the old 10.0 kept below the ek baseline's 121-172x, restored
#: rather than shrunk when #105 moved the assertion onto the faster projected
#: baseline. Asserted against the *projected* pcap median; the ek median is
#: reported only.
MIN_SPEEDUP = 5.0

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
    # The measured baseline. `.select(IP.src, TCP.port)` names exactly the
    # field set the workspace was materialized with, which is what makes the
    # comparison honest: both sides then produce the same columns, so the ratio
    # is purely "dissect again" versus "scan columns dissected once". The
    # filter is fully pushable, so this plans to -T fields with no residual.
    def from_projected_pcap() -> int:
        return sum(1 for _ in Capture(bench.pcap).select(IP.src, TCP.port).filter(BENCHMARK_EXPR))

    # Kept, and reported rather than asserted: this is the *old* baseline, and
    # the gap between the two is the ek-versus-fields component #105 found
    # bundled into the headline ratio. Measuring it here is what keeps that
    # component visible instead of quietly absorbed.
    def from_ek_pcap() -> int:
        return sum(1 for _ in Capture(bench.pcap).filter(BENCHMARK_EXPR))

    with Workspace(bench.workspace) as ws:
        assert ws.mode == "ro"

        def from_cache() -> int:
            return sum(1 for _ in ws.query().filter(BENCHMARK_EXPR))

        # Interleaved: rotating the three sides spreads any burst of system
        # noise across all three medians instead of loading it onto whichever
        # ran first.
        ek_timings: list[float] = []
        fields_timings: list[float] = []
        cache_timings: list[float] = []
        ek_rows = from_ek_pcap()  # warm-up, discarded
        fields_rows = from_projected_pcap()  # warm-up, discarded
        cache_rows = from_cache()  # warm-up, discarded
        for _ in range(TIMED_RUNS):
            started = time.perf_counter()
            assert from_ek_pcap() == ek_rows
            ek_timings.append(time.perf_counter() - started)
            started = time.perf_counter()
            assert from_projected_pcap() == fields_rows
            fields_timings.append(time.perf_counter() - started)
            started = time.perf_counter()
            assert from_cache() == cache_rows
            cache_timings.append(time.perf_counter() - started)

    ek_median = statistics.median(ek_timings)
    fields_median = statistics.median(fields_timings)
    cache_median = statistics.median(cache_timings)
    speedup = fields_median / cache_median
    ek_over_fields = ek_median / fields_median

    print(
        f"\nbreak-even benchmark ({PACKET_COUNT} packets, {fields_rows} selected)\n"
        f"  materialize (one-time): {bench.materialize_seconds:.3f}s\n"
        f"  pcap re-parse -T ek, median of {TIMED_RUNS}: {ek_median:.4f}s {ek_timings}\n"
        f"  pcap re-parse -T fields, median of {TIMED_RUNS}: "
        f"{fields_median:.4f}s {fields_timings}\n"
        f"  cached query, median of {TIMED_RUNS}: {cache_median:.4f}s {cache_timings}\n"
        f"  ek / fields: {ek_over_fields:.1f}x (reported, not asserted — #105's component)\n"
        f"  speedup vs the projected baseline: {speedup:.1f}x (floor asserted: {MIN_SPEEDUP}x)"
    )

    # Anti-vacuity: a benchmark over an empty result set proves nothing, and
    # sides counting differently are not running the same query. All three are
    # checked, so the ek reading stays a comparable measurement rather than a
    # number nobody validated.
    assert fields_rows == EXPECTED_ROWS
    assert ek_rows == fields_rows
    assert cache_rows == fields_rows
    assert speedup >= MIN_SPEEDUP, (
        f"cached query is only {speedup:.1f}x faster than re-parsing the pcap "
        f"through the projected path (pcap median {fields_median:.4f}s, "
        f"cache median {cache_median:.4f}s); the workspace's whole reason to "
        f"exist is that this stays well above {MIN_SPEEDUP}x"
    )

    # Derived only once the floor holds, and off the projected side for the
    # same reason the floor is: it is the cost a caller who knows their field
    # set actually pays. The divisor is the *difference* of the medians, so on
    # a failing run it is zero or negative — a ZeroDivisionError or a "pays for
    # itself after -3.0 queries" line would replace the message above that says
    # what actually went wrong.
    queries_to_break_even = bench.materialize_seconds / (fields_median - cache_median)
    print(f"  materialization pays for itself after {queries_to_break_even:.1f} repeat queries")


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
    #
    # Deliberately left on the ek path while the benchmark above moved to the
    # projected one (#105). This is the suite's only at-scale exercise of the
    # whole-packet fallback — the mode an opaque callable term forces and a
    # caller who names no projection gets — and every other integration test
    # here runs a handful of packets. Converting it would need frame.number in
    # the projection (get_raw would otherwise raise FieldNotProjectedError) and
    # would buy nothing the benchmark's own row-count assertions do not already
    # cover, at the cost of leaving ek untested at size.
    from_pcap = {
        int(pkt.get_raw("frame.number")[0]) for pkt in Capture(bench.pcap).filter(BENCHMARK_EXPR)
    }
    with Workspace(bench.workspace) as ws:
        from_cache = {row.frame_number for row in ws.query().filter(BENCHMARK_EXPR)}
    assert len(from_pcap) == EXPECTED_ROWS
    assert from_cache == from_pcap
