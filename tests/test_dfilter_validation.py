"""Validate compiled display filters against a real tshark (issue #18).

Three parts:

1. Syntax: every golden dfilter string the test suite asserts anywhere —
   dfilter_corpus.GOLDEN, the semantics table's per-case goldens, and the
   planner/capture composed plan strings (also in dfilter_corpus) — plus every filter
   compiled from exprgen's 200-tree seeded corpus must be accepted by
   ``tshark -r <fixture> -Y <filter>``. Filters are batch-validated in
   OR-joined chunks (one tshark spawn per ~32 filters); a failing chunk is
   bisected filter-by-filter so the report names each offending tree and
   filter string.

2. Semantics: the row set tshark returns for ``!(x == v)`` must match the
   predicate backend's row set for the DSL's ``!=`` on the fixture pcaps —
   including the multi-value (tcp.port) and absent-field (ARP frame) cases.

3. Evidence: the measurements of tshark that a *policy* rests on, pinned so a
   Wireshark that changes them is caught here rather than silently invalidating
   the reasoning in the compiler's docstring. Today that is issue #90's
   IEEE-754 finding — ``nan`` is lexed as a real float literal (so rendering it
   is not self-protecting), yet is never a comparison worth pushing down, while
   ``inf``/``-inf`` are accepted and pushed down unchanged.

   These assertions are deliberately written to hold on **every** tshark the
   project is tested against, not just the newest. CI's ``checks`` job installs
   Ubuntu's stock build (4.2.2), which differs from a current release (4.6.8)
   on exactly this subject: 4.6.8 rejects an ordered NaN comparison outright
   while 4.2.2 accepts it, and 4.6.8 accepts ``nan``/``inf`` on a *time* field
   where 4.2.2 rejects them as "not a valid time". Anything measured on one
   build alone belongs in a comment, not an assertion.

Runs whenever tshark is installed; in CI, REMORA_REQUIRE_TSHARK=1 turns the
"tshark missing" skip into a hard failure so the suite can never silently
vanish.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dfilter_corpus import CAPTURE_DFILTER_GOLDENS, GOLDEN, PLANNER_DFILTER_GOLDENS, RESPTIME
from exprgen import gen_corpus
from remora import DNS, IP, TCP, UDP, values
from remora.compile.dfilter import UnsupportedExprError, compile_dfilter
from remora.compile.predicate import compile_predicate
from remora.expr import Expr
from remora.proto.http import HTTP
from remora.reader.ek_reader import EkReader
from test_semantics_table import CASES

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TCP_MIXED = FIXTURES_DIR / "tcp_mixed.pcap"
DNS_MULTI = FIXTURES_DIR / "dns_multi.pcap"

NAN = float("nan")

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
# Every tshark spawn here is bounded so a wedged binary cannot hang CI; on
# expiry subprocess.TimeoutExpired carries the full argv (filter included).
_TSHARK_TIMEOUT = 60


@functools.lru_cache(maxsize=1)
def _tshark_version() -> str:
    """First line of ``tshark -v``, captured once per session.

    The validating tshark differs between a developer's box and CI's apt
    build; a rejection caused by version drift must be identifiable from the
    failure report alone rather than misread as a compiler bug.
    """
    result = subprocess.run(
        [_TSHARK, "-v"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TSHARK_TIMEOUT,
    )
    lines = result.stdout.strip().splitlines()
    return lines[0].strip() if lines else "unknown tshark version"


def _run_tshark(dfilter: str) -> subprocess.CompletedProcess[str]:
    """Run tshark over the tcp_mixed fixture with *dfilter* as ``-Y``.

    ``-n`` disables name resolution: no DNS lookups, so validation is
    hermetic and fast. argv list, never ``shell=True``.
    """
    argv = [_TSHARK, "-n", "-r", str(TCP_MIXED), "-Y", dfilter]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TSHARK_TIMEOUT,
    )


def _assert_all_valid(cases: list[tuple[str, str]]) -> None:
    """``cases`` is (description, filter). Chunk-validate via OR-join; on a
    failing chunk, re-check each filter individually to attribute blame.

    Bisection must never fail open: if the joined form is rejected but every
    filter in the chunk passes alone (dfilter depth/complexity limits, argv
    length, resource errors), the chunk itself is reported — otherwise the
    suite would go green on the only form it actually ran.
    """
    failures: list[str] = []
    for start in range(0, len(cases), _CHUNK_SIZE):
        chunk = cases[start : start + _CHUNK_SIZE]
        joined = " || ".join(f"({dfilter})" for _, dfilter in chunk)
        joined_result = _run_tshark(joined)
        if joined_result.returncode == 0:
            continue
        before = len(failures)
        for description, dfilter in chunk:
            result = _run_tshark(dfilter)
            if result.returncode != 0:
                failures.append(
                    f"{description}\n  filter: {dfilter}\n  tshark: {result.stderr.strip()}"
                )
        if len(failures) == before:
            failures.append(
                f"chunk[{start}:{start + len(chunk)}] failed OR-joined but every filter "
                f"passed individually\n  joined: {joined}\n"
                f"  tshark: {joined_result.stderr.strip()}"
            )
    if failures:
        pytest.fail(
            f"tshark rejected compiled display filters [{_tshark_version()}]:\n"
            + "\n".join(failures),
            pytrace=False,
        )


class TestGoldenCorpusValidates:
    def test_every_golden_string_is_accepted_by_tshark(self) -> None:
        # Size guard, exact so silent shrinkage is impossible: dropping a
        # golden case must fail here rather than quietly validate less.
        # Update deliberately when cases are added.
        assert len(GOLDEN) == 47
        cases: list[tuple[str, str]] = []
        for case in GOLDEN:
            # Validate what the compiler emits, not just the literal golden
            # string, so this file is self-contained proof about the compiler.
            assert compile_dfilter(case.expr) == case.expected
            cases.append((f"golden[{case.id}]: {case.expr!r}", case.expected))
        _assert_all_valid(cases)


class TestSemanticsTableGoldensValidate:
    """The dual-backend semantics table (tests/test_semantics_table.py) carries
    its own golden dfilter strings; they must be real tshark syntax too."""

    def test_every_semantics_golden_is_accepted_by_tshark(self) -> None:
        dfilters = [case.dfilter for case in CASES if case.dfilter is not None]
        # Exact count: a case losing its golden string must fail loudly here.
        # Update deliberately when the table grows. 27 base cases plus the 36
        # absent-field truth-table cases (nine operators x scalar/multi x
        # positive/negated), every one of which carries a golden.
        assert len(dfilters) == 63
        _assert_all_valid(
            [
                (f"semantics[{case.id}]: {case.expr!r}", case.dfilter)
                for case in CASES
                if case.dfilter is not None
            ]
        )


class TestPlannerAndCaptureGoldensValidate:
    """Plans and argv assembled by the planner/capture unit tests are asserted
    against the shared DF_* golden strings there (no tshark runs in those
    files); a real tshark must accept every one of those composed filters."""

    def test_planner_and_capture_goldens_are_accepted_by_tshark(self) -> None:
        # Exact counts, so a golden dropped from either tuple fails here rather
        # than quietly validating less. Update deliberately when they grow.
        assert len(PLANNER_DFILTER_GOLDENS) == 6
        assert len(CAPTURE_DFILTER_GOLDENS) == 3
        cases: list[tuple[str, str]] = [
            (f"planner[{i}]", dfilter) for i, dfilter in enumerate(PLANNER_DFILTER_GOLDENS)
        ] + [(f"capture[{i}]", dfilter) for i, dfilter in enumerate(CAPTURE_DFILTER_GOLDENS)]
        # Dedup by filter string (capture repeats two planner strings), first
        # description wins, insertion order preserved.
        deduped: dict[str, str] = {}
        for description, dfilter in cases:
            deduped.setdefault(dfilter, description)
        # Exact count after dedup (capture repeats two planner strings).
        # Update deliberately when a distinct composed string is added.
        assert len(deduped) == 7
        _assert_all_valid([(description, dfilter) for dfilter, description in deduped.items()])


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
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TSHARK_TIMEOUT,
    )
    assert result.returncode == 0, f"tshark rejected {dfilter!r}: {result.stderr.strip()}"
    return {int(line) for line in result.stdout.split() if line}


def _predicate_matching_frames(pcap: Path, expr: Expr) -> set[int]:
    """Row set the predicate backend matches over *pcap*, by frame number.

    tshark is spawned here directly rather than through ``Capture`` so this
    path stays bounded by ``_TSHARK_TIMEOUT`` too — ``TsharkProcess`` waits on
    natural EOF without a timeout, and a wedged binary would hang CI. ``-T ek``
    with no ``-Y`` gives every frame in file order, so the 1-based enumeration
    index is the frame number; ``EkReader`` accepts any iterable of decoded
    lines and yields packets satisfying the RawPacket protocol.
    """
    argv = [_TSHARK, "-n", "-r", str(pcap), "-T", "ek"]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TSHARK_TIMEOUT,
    )
    assert result.returncode == 0, f"tshark -T ek failed: {result.stderr.strip()}"
    predicate = compile_predicate(expr)
    packets = list(EkReader(result.stdout.splitlines()))
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


class TestMatchesSemanticsParity:
    """The row set tshark selects for ``field matches "p"`` must equal the
    predicate backend's row set for the same Expr — pinning case-insensitive
    matching, per-occurrence anchoring on multi-value fields, and the
    absent-field negation contract against a real PCRE2, not just our reading
    of it (PR #73 review: the common-subset guarantee needs parity evidence)."""

    @pytest.mark.parametrize(
        ("pcap", "expr"),
        [
            pytest.param(DNS_MULTI, DNS.qry_name.matches("^alpha"), id="anchored-multi-occurrence"),
            pytest.param(DNS_MULTI, DNS.qry_name.matches("ALPHA"), id="case-insensitive"),
            pytest.param(DNS_MULTI, DNS.qry_name.matches("example$"), id="dollar-anchor"),
            pytest.param(
                DNS_MULTI, DNS.qry_name.matches("a{2,}|beta"), id="quantifier-alternation"
            ),
            pytest.param(DNS_MULTI, DNS.qry_name.matches(r"\bexample\b"), id="word-boundary"),
            pytest.param(TCP_MIXED, ~DNS.qry_name.matches("alpha"), id="negation-absent-field"),
            # The scalar half of the same cell: DNS.qry_name is multi, so
            # without this the negated-absent-SCALAR matches cell rested on
            # predicate.py's reading of Wireshark rather than on Wireshark.
            # http.host occurs in no fixture frame, so both sides must select
            # every frame — the absent-field negation contract exactly.
            pytest.param(TCP_MIXED, ~HTTP.host.matches("com"), id="negation-absent-scalar"),
        ],
    )
    def test_matches_row_set_matches_predicate_backend(self, pcap: Path, expr: Expr) -> None:
        dfilter = compile_dfilter(expr)
        assert " matches " in dfilter
        assert _tshark_matching_frames(pcap, dfilter) == _predicate_matching_frames(pcap, expr)


def _tshark_accepts(pcap: Path, dfilter: str) -> bool:
    """Does tshark's display-filter parser accept *dfilter* at all?

    Acceptance, not the row set: used below to separate "tshark lexed this as a
    literal" from "tshark rejected the text outright".
    """
    argv = [_TSHARK, "-n", "-r", str(pcap), "-Y", dfilter]
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_TSHARK_TIMEOUT,
    )
    return result.returncode == 0


class TestNaNIsARecognizedDfilterLiteral:
    """Why the dfilter backend refuses NaN literals (issue #90).

    These tests measure tshark rather than remora: they are the evidence behind
    the policy in ``dfilter.py``'s IEEE-754 section, pinned so a future
    Wireshark that changes how it lexes or orders ``nan`` is caught here and the
    policy gets revisited, instead of the reasoning quietly going stale.

    Everything asserted below is measured on **both** tshark versions this
    project is tested against — CI's apt build (4.2.2) and a current release
    (4.6.8) — and only on a **float** ftype, which is the only kind of field a
    float literal can reach (``test_float_literals_only_reach_float_ftypes``).

    Two observations are deliberately recorded here rather than asserted,
    because they are version-specific trivia and not a remora contract:

    * The treatment of an *ordered* NaN comparison flips between the two
      builds. 4.6.8 rejects it outright (``NaN cannot be used in ordered
      comparisons``); 4.2.2 accepts it. So there is no stable pushdown
      behaviour to rely on even if the semantics happened to line up — which
      is precisely why a "dfilter-native never-matches rendering" was rejected
      as version-fragile.
    * On a *time* ftype 4.6.8 does answer wrongly rather than loudly:
      ``frame.time_delta > nan`` selects every frame carrying the field where
      Python selects none. That is unreachable through the DSL — a float
      literal cannot be coerced for ``FT_RELATIVE_TIME`` — and 4.2.2 rejects
      the same filter as ``"nan" is not a valid time``. It motivated the
      investigation; it is not something the suite should enforce.
    """

    def test_float_literals_only_reach_float_ftypes(self) -> None:
        # Pure Python, no tshark. This is what makes the float-ftype scoping of
        # every tshark assertion below the right scoping: a NaN literal can
        # never be aimed at a time field through the DSL in the first place.
        assert values.coerce_literal("FT_DOUBLE", NAN) != values.coerce_literal("FT_DOUBLE", NAN)
        for time_ftype in ("FT_RELATIVE_TIME", "FT_ABSOLUTE_TIME"):
            with pytest.raises(TypeError):
                values.coerce_literal(time_ftype, NAN)

    def test_nan_is_lexed_as_a_literal_while_near_misses_are_rejected(self) -> None:
        # The load-bearing fact: rendering `nan` is NOT self-protecting. If
        # tshark rejected it the way it rejects `nam`, a repr-rendered NaN would
        # be a loud failure and there would be nothing to fix.
        for spelling in ("nan", "NaN"):
            assert _tshark_accepts(DNS_MULTI, f"{RESPTIME.name} == {spelling}"), spelling
        for near_miss in ("nam", "nan5", "zzz"):
            assert not _tshark_accepts(DNS_MULTI, f"{RESPTIME.name} == {near_miss}"), near_miss

    def test_ordered_nan_comparisons_are_never_a_filter_worth_pushing(self) -> None:
        # Python compares false against NaN for every operator, so the
        # predicate backend selects NOTHING. tshark gives us one of two
        # unusable answers, and which one depends on the build:
        #
        #   rejected      -> emitting the filter aborts the whole tshark run
        #   accepted      -> selects nothing, but only incidentally; the
        #                    ordering it implements is not specified and
        #                    flipped between 4.2.2 and 4.6.8
        #
        # Either way the conjunct belongs on the predicate backend. The
        # assertion has teeth against the one outcome that would be a silent
        # wrong answer: accepted AND matching rows.
        #
        # Caveat, stated rather than dressed up: no checked-in fixture carries
        # a populated FT_DOUBLE field, so on a build that ACCEPTS these filters
        # the row-set branch is witnessed vacuously. It still fails loudly if a
        # future tshark starts returning rows here, which is the regression
        # this test exists to catch.
        for op in (">", ">=", "<", "<="):
            dfilter = f"{RESPTIME.name} {op} nan"
            if _tshark_accepts(DNS_MULTI, dfilter):
                assert _tshark_matching_frames(DNS_MULTI, dfilter) == set(), dfilter

    def test_the_compiler_never_emits_any_of_those_filters(self) -> None:
        # The refusal is what keeps the divergence above off the pushdown path.
        # A float literal only reaches the renderer on a float ftype, so this is
        # the same policy the measurements above are the motive for.
        for expr in (RESPTIME > NAN, RESPTIME >= NAN, RESPTIME != NAN, RESPTIME.in_([NAN])):
            with pytest.raises(UnsupportedExprError, match="NaN"):
                compile_dfilter(expr)


class TestInfinityIsPushedDownUnchanged:
    """``inf``/``-inf`` are pushed down unchanged. Pinned beside the NaN
    evidence so nobody "completes" the NaN rule by refusing them too (#90).

    Acceptance is the claim worth pinning here, and it holds on both 4.2.2 and
    4.6.8: an infinite bound reaches tshark as a real float literal and does
    not abort the run, which is exactly what NaN fails to do. The *row sets*
    are covered where they can be witnessed non-vacuously — the corpus goldens
    in :data:`dfilter_corpus.GOLDEN` go through
    :class:`TestGoldenCorpusValidates`, and the semantics table exercises the
    predicate backend on the same expressions.
    """

    def test_infinite_literals_are_accepted_by_tshark(self) -> None:
        for dfilter in (
            f"{RESPTIME.name} < inf",
            f"{RESPTIME.name} > inf",
            f"{RESPTIME.name} == inf",
            f"{RESPTIME.name} > -inf",
            f"{RESPTIME.name} < -inf",
            f"{RESPTIME.name} in {{-inf .. inf}}",
        ):
            assert _tshark_accepts(DNS_MULTI, dfilter), dfilter
