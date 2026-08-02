# End-to-End Capture Query API Implementation Plan (issue #15)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire planner, readers, and protocol classes into one public query surface: `for pkt in Capture("x.pcap").filter(expr_or_lambda):` runs a typed end-to-end query against a pcap.

**Architecture:** `Capture` is an immutable query builder: `.filter()` returns a new `Capture` with the term appended; iteration calls `make_plan(terms, select=None)`, builds a tshark argv (`-r` + optional `-Y` + `-T fields`/`-T ek` per `plan.mode`), spawns a `TsharkProcess`, wraps it in `FieldsReader`/`EkReader`, and yields packets that pass the residual predicate. A `try/finally` around the yield loop guarantees the subprocess is closed on early break. In M1 `select` is always `None`, so live plans are always ek-mode; the fields-mode execution branch is still implemented (it is what the planner emits once a projection API lands) and covered by unit tests that inject a fields-mode plan.

**Tech Stack:** Python ≥3.10, uv, pytest, mypy --strict, ruff. No new dependencies.

## Global Constraints

- CI gate before any commit: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest` (all four must pass).
- Integration tests are marked `@pytest.mark.integration` + `@pytest.mark.skipif(shutil.which("tshark") is None, ...)`; `uv run pytest -m "not integration"` must pass without tshark installed.
- `assert_type` comes from `typing_extensions` (Python floor is 3.10; `typing.assert_type` is 3.11+). Place `assert_type` BEFORE runtime asserts — a preceding `assert x == value` narrows the type and breaks `assert_type`.
- Absence contract: `()` from `get_raw`, `None` from scalar instance access, `()` from multi instance access.
- `tests/test_proto_seed.py` pairing tests must keep passing unmodified.
- Branch: `feat/issue-15-capture-api`. PR body includes `Closes #15`.
- Work happens on the branch in the main checkout (no worktree — session config).

## File Structure

- Create `src/remora/capture.py` — the only new runtime module: `Capture`, argv assembly, tshark binary resolution.
- Modify `src/remora/__init__.py` — public exports (`Capture` + seed protocols).
- Create `tests/test_capture.py` — unit tests, no tshark spawned (fake `TsharkProcess`).
- Create `tests/test_capture_integration.py` — integration tests against `tests/data/sample.pcap` with real tshark; doubles as the mypy-checked quickstart snippet.
- Modify `tests/test_package.py` — exercise the public exports.

## Fixture facts (tests/data/sample.pcap, 3 packets)

1. TCP SYN `10.0.0.1 -> 10.0.0.2`, srcport 51234, dstport 443 (`tcp.port` dissects twice: 51234, 443).
2. ARP request — no IP/TCP/UDP/DNS layers at all.
3. DNS query over UDP `10.0.0.3 -> 10.0.0.53`, sport 40000, dport 53, qname `foo,bar.example`.

## Interface facts (already merged, do not re-derive)

- `make_plan(terms: Sequence[Expr | Callable[[RawPacket], bool]], *, select=None) -> Plan`; `Plan` has `.dfilter: str | None`, `.mode: Literal["fields","ek"]`, `.projection: tuple[FieldRef[Any], ...] | None`, `.residual: Callable[[RawPacket], bool] | None`. `select=None` or any opaque callable forces `mode="ek"`.
- `TsharkProcess(argv)` — context manager; iterating yields newline-stripped stdout lines; `close()` terminates/kills/reaps (idempotent); `.returncode` is `None` while running, the exit code after reaping.
- `fields_argv(projection) -> list[str]` (the `-T fields -E ...` fragment + `-e` per field); `FieldsReader(lines, projection)` yields `FieldsRow`.
- `ek_argv() -> ["-T", "ek"]`; `EkReader(lines)` yields `EkPacket`.
- Both `FieldsRow` and `EkPacket` implement `get_raw` and `__getitem__(proto)` — they satisfy `remora.fields.Packet` structurally.
- Seed protocols: `from remora.proto import DNS, ETH, IP, TCP, UDP`. Attrs used in tests: `IP.src` (`FT_IPv4` → `IPv4Address`), `TCP.port` (multi, `int`), `TCP.dstport`, `UDP.dstport`, `DNS.qry_name` (multi, `str`).
- Planner guarantee used for typing: opaque lambdas force ek mode, so a residual lambda is only ever invoked on an `EkPacket` (full `Packet`); residual `Expr` predicates consume bare `RawPacket` and run in either mode (their fields are always added to a fields-mode projection).

---

### Task 1: `capture.py` — Capture core + unit tests

**Files:**
- Create: `src/remora/capture.py`
- Test: `tests/test_capture.py`

**Interfaces:**
- Consumes: everything under "Interface facts" above.
- Produces: `Capture(path: str | os.PathLike[str], *, tshark: str | None = None)`; `.filter(*terms: Expr | Callable[[Packet], bool]) -> Capture` (new instance); `.plan() -> Plan`; `__iter__() -> Iterator[Packet]`. Module-private `_build_argv(tshark: str, path: Path, plan: Plan) -> list[str]` and `_resolve_tshark(explicit: str | None) -> str`.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/test_capture.py`:

```python
"""Unit tests for remora.capture — no tshark is spawned; TsharkProcess is faked."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

import remora.capture as capture_module
from remora.capture import Capture, _build_argv, _resolve_tshark
from remora.fields import FieldRef, RawPacket
from remora.planner import make_plan
from remora.proto import IP, TCP


def ek_line(layers: dict[str, Any]) -> str:
    return json.dumps({"layers": layers})


#: Two data packets (each preceded by an ek index line, as real tshark emits).
EK_LINES = [
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.1"}, "tcp": {"tcp_tcp_port": ["51234", "443"]}}),
    json.dumps({"index": {"_index": "packets-test"}}),
    ek_line({"ip": {"ip_ip_src": "10.0.0.3"}, "udp": {"udp_udp_dstport": "53"}}),
]


class FakeProcess:
    """Stands in for TsharkProcess: canned stdout lines plus close bookkeeping."""

    def __init__(self, argv: Sequence[str], lines: Sequence[str]) -> None:
        self.argv = list(argv)
        self.lines = list(lines)
        self.closed = False

    def __iter__(self) -> Any:
        yield from self.lines

    def close(self) -> None:
        self.closed = True


class FakeTshark:
    """Factory installed in place of capture_module.TsharkProcess."""

    def __init__(self) -> None:
        self.lines: list[str] = list(EK_LINES)
        self.created: list[FakeProcess] = []

    def __call__(self, argv: Sequence[str]) -> FakeProcess:
        proc = FakeProcess(argv, self.lines)
        self.created.append(proc)
        return proc


@pytest.fixture
def fake_tshark(monkeypatch: pytest.MonkeyPatch) -> FakeTshark:
    factory = FakeTshark()
    monkeypatch.setattr(capture_module, "TsharkProcess", factory)
    return factory


class TestFilterBuilder:
    def test_filter_returns_new_capture(self) -> None:
        cap = Capture("x.pcap")
        filtered = cap.filter(IP.src == "10.0.0.1")
        assert filtered is not cap
        assert cap.plan().dfilter is None
        assert filtered.plan().dfilter == "(ip.src == 10.0.0.1)"

    def test_filters_accumulate_across_calls(self) -> None:
        cap = Capture("x.pcap").filter(IP.src == "10.0.0.1").filter(TCP.port == 443)
        assert cap.plan().dfilter == "(ip.src == 10.0.0.1) && (tcp.port == 443)"

    def test_m1_plans_are_ek_mode(self) -> None:
        # No projection API in M1: select is always None, so mode is always ek.
        assert Capture("x.pcap").filter(IP.src == "10.0.0.1").plan().mode == "ek"


class TestArgvAssembly:
    def test_ek_argv_with_dfilter(self) -> None:
        plan = make_plan([IP.src == "10.0.0.1"])
        argv = _build_argv("tshark", capture_module.Path("x.pcap"), plan)
        assert argv[:3] == ["tshark", "-r", "x.pcap"]
        assert argv[3:5] == ["-Y", "(ip.src == 10.0.0.1)"]
        assert argv[5:] == ["-T", "ek"]

    def test_ek_argv_without_dfilter(self) -> None:
        plan = make_plan([])
        argv = _build_argv("tshark", capture_module.Path("x.pcap"), plan)
        assert argv == ["tshark", "-r", "x.pcap", "-T", "ek"]

    def test_fields_argv_projects_selected_fields(self) -> None:
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        plan = make_plan([TCP.port == 443], select=select)
        argv = _build_argv("tshark", capture_module.Path("x.pcap"), plan)
        assert argv[3:5] == ["-Y", "(tcp.port == 443)"]
        assert argv[5:7] == ["-T", "fields"]
        assert argv[-2:] == ["-e", "ip.src"]

    def test_resolve_tshark_explicit_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TSHARK", "/env/tshark")
        assert _resolve_tshark("/explicit/tshark") == "/explicit/tshark"

    def test_resolve_tshark_env_then_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TSHARK", "/env/tshark")
        assert _resolve_tshark(None) == "/env/tshark"
        monkeypatch.delenv("TSHARK")
        assert _resolve_tshark(None) == "tshark"


class TestIteration:
    def test_unfiltered_yields_every_packet(self, fake_tshark: FakeTshark) -> None:
        packets = list(Capture("x.pcap"))
        assert len(packets) == 2
        assert packets[0].get_raw("ip.src") == ("10.0.0.1",)
        assert packets[1].get_raw("ip.src") == ("10.0.0.3",)

    def test_residual_lambda_filters_in_python(self, fake_tshark: FakeTshark) -> None:
        cap = Capture("x.pcap").filter(lambda pkt: pkt.get_raw("udp.dstport") == ("53",))
        packets = list(cap)
        assert len(packets) == 1
        assert packets[0].get_raw("ip.src") == ("10.0.0.3",)
        # The opaque lambda cannot be pushed down: no -Y in argv.
        assert "-Y" not in fake_tshark.created[0].argv

    def test_pushed_expr_lands_in_argv(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap").filter(IP.src == "10.0.0.1"))
        argv = fake_tshark.created[0].argv
        assert argv[argv.index("-Y") + 1] == "(ip.src == 10.0.0.1)"

    def test_typed_access_on_yielded_packet(self, fake_tshark: FakeTshark) -> None:
        first = next(iter(Capture("x.pcap")))
        assert first[TCP].port == (51234, 443)

    def test_early_break_closes_process(self, fake_tshark: FakeTshark) -> None:
        for _pkt in Capture("x.pcap"):
            break
        assert fake_tshark.created[0].closed

    def test_exhaustion_closes_process(self, fake_tshark: FakeTshark) -> None:
        list(Capture("x.pcap"))
        assert fake_tshark.created[0].closed

    def test_consumer_exception_closes_process(self, fake_tshark: FakeTshark) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            for _pkt in Capture("x.pcap"):
                raise RuntimeError("boom")
        assert fake_tshark.created[0].closed

    def test_fields_mode_plan_uses_fields_reader(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # M1's public surface never produces a fields-mode plan (select is
        # always None), so inject one to prove the execution branch works.
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        plan = make_plan([], select=select)
        monkeypatch.setattr(Capture, "plan", lambda self: plan)
        fake_tshark.lines = ["10.0.0.1", "10.0.0.3"]
        packets = list(Capture("x.pcap"))
        assert [pkt.get_raw("ip.src") for pkt in packets] == [("10.0.0.1",), ("10.0.0.3",)]
        assert fake_tshark.created[0].argv[3:5] == ["-T", "fields"]

    def test_residual_expr_applies_in_fields_mode(
        self, fake_tshark: FakeTshark, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A residual Expr's field is auto-added to the projection by the
        # planner, so the compiled predicate can read it from a FieldsRow.
        select: list[FieldRef[Any]] = [FieldRef("ip.src", "FT_IPv4", False)]
        residual = ~(IP.src == "10.0.0.1") | (IP.src == "10.0.0.1")
        plan = make_plan([residual], select=select)
        assert plan.mode == "fields"
        if plan.dfilter is None:  # only meaningful if it was NOT pushed down
            monkeypatch.setattr(Capture, "plan", lambda self: plan)
            fake_tshark.lines = ["10.0.0.1", "10.0.0.3"]
            assert len(list(Capture("x.pcap"))) == 2
```

Note on the last test: `~a | a` is a tautology; if the dfilter backend can push it, the test degenerates (guarded by the `if`) — its real purpose is exercising `residual is not None` in fields mode. If `compile_dfilter` pushes `Or`/`Not` fine, simplify the test to use an opaque-free residual that is genuinely unsupported (check `tests/test_planner.py` for an expression that lands in the residual, e.g. one that raises `UnsupportedExprError`), or drop the test if no Expr is unpushable — do NOT contort the implementation for it.

- [ ] **Step 2: Run the tests to verify they fail on import**

Run: `uv run pytest tests/test_capture.py -x -q`
Expected: FAIL/ERROR with `ModuleNotFoundError: No module named 'remora.capture'`

- [ ] **Step 3: Implement `src/remora/capture.py`**

```python
"""The public Capture query surface: the M1 end-to-end tracer bullet.

``Capture`` wires the pieces together: ``.filter()`` accumulates query terms
into an immutable builder; iteration plans the query
(:func:`remora.planner.make_plan`), assembles a tshark argv, spawns a
:class:`~remora.reader.process.TsharkProcess`, wraps its stdout in the
mode-appropriate reader, and yields packets that pass the residual predicate.

M1 has no projection API, so ``plan()`` is always called with ``select=None``
and live plans are always ek-mode; the fields-mode execution branch below is
what the planner emits once a select/projection API exists, and is covered by
unit tests injecting a fields-mode plan.

Lifecycle: the ``try/finally`` in ``__iter__`` guarantees ``close()`` on the
subprocess however iteration ends — exhaustion, early ``break``, a consumer
exception, or the generator being GC'd — so no tshark orphans outlive a query.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeAlias, cast

from remora.expr import Expr
from remora.fields import Packet
from remora.planner import Plan, QueryTerm, make_plan
from remora.reader.ek_reader import EkReader, ek_argv
from remora.reader.fields_reader import FieldsReader, fields_argv
from remora.reader.process import TsharkProcess

__all__ = ["Capture", "CaptureFilter"]

#: A query term: an ``Expr`` built from field comparisons, or an opaque
#: predicate over the full packet. Opaque callables receive ``Packet`` (not
#: bare ``RawPacket``): they only ever run in ek mode, whose packets support
#: ``pkt[Proto]`` views.
CaptureFilter: TypeAlias = Expr | Callable[[Packet], bool]


def _resolve_tshark(explicit: str | None) -> str:
    """Resolve the tshark binary: explicit arg, then $TSHARK, then PATH."""
    if explicit is not None:
        return explicit
    return os.environ.get("TSHARK") or "tshark"


def _build_argv(tshark: str, path: Path, plan: Plan) -> list[str]:
    """Assemble the full tshark argv for *plan* over the pcap at *path*."""
    argv = [tshark, "-r", str(path)]
    if plan.dfilter is not None:
        argv += ["-Y", plan.dfilter]
    if plan.mode == "fields":
        assert plan.projection is not None  # Plan invariant: fields => projection
        argv += fields_argv(plan.projection)
    else:
        argv += ek_argv()
    return argv


class Capture:
    """A lazily-executed, immutable query over one pcap file.

    ``filter()`` returns a NEW ``Capture`` with the terms appended (the
    original is unchanged), so partial queries can be shared and extended.
    Iteration executes the query: each ``for`` loop spawns a fresh tshark
    subprocess and yields packets supporting ``pkt[IP].src`` typed access.
    """

    __slots__ = ("_path", "_terms", "_tshark")

    def __init__(self, path: str | os.PathLike[str], *, tshark: str | None = None) -> None:
        self._path = Path(path)
        self._tshark = _resolve_tshark(tshark)
        self._terms: tuple[CaptureFilter, ...] = ()

    def filter(self, *terms: CaptureFilter) -> Capture:
        """A new ``Capture`` with *terms* AND-ed onto the existing ones."""
        clone = Capture(self._path, tshark=self._tshark)
        clone._terms = self._terms + terms
        return clone

    def plan(self) -> Plan:
        """The query plan iteration would execute (inspectable, side-effect free)."""
        # A residual lambda only ever runs in ek mode (opaque terms force it),
        # where every packet satisfies the full Packet protocol — so widening
        # the callable's parameter from Packet to RawPacket here is sound.
        return make_plan(cast("tuple[QueryTerm, ...]", self._terms), select=None)

    def __iter__(self) -> Iterator[Packet]:
        plan = self.plan()
        process = TsharkProcess(_build_argv(self._tshark, self._path, plan))
        try:
            reader: Iterator[Packet]
            if plan.mode == "fields":
                assert plan.projection is not None  # Plan invariant
                reader = iter(FieldsReader(process, plan.projection))
            else:
                reader = iter(EkReader(process))
            residual = plan.residual
            for packet in reader:
                if residual is None or residual(packet):
                    yield packet
        finally:
            process.close()

    def __repr__(self) -> str:
        return f"<Capture {str(self._path)!r} terms={len(self._terms)}>"
```

- [ ] **Step 4: Run the unit tests**

Run: `uv run pytest tests/test_capture.py -q`
Expected: all PASS. If `test_residual_expr_applies_in_fields_mode` proves vacuous (dfilter pushed the tautology), follow the note in Step 1.

- [ ] **Step 5: Run the full local gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -m "not integration" -q`
Expected: all four green. (Iterator/reader typing: `FieldsRow` and `EkPacket` satisfy `Packet` structurally; if mypy disagrees about `Iterator[Packet]`, annotate as shown — do not add casts beyond the one in `plan()` without understanding why.)

- [ ] **Step 6: Commit**

```bash
git add src/remora/capture.py tests/test_capture.py
git commit -m "core: add Capture end-to-end query surface"
```

---

### Task 2: Public exports

**Files:**
- Modify: `src/remora/__init__.py`
- Modify: `tests/test_package.py`

**Interfaces:**
- Consumes: `remora.capture.Capture`, `remora.proto.{DNS, ETH, IP, TCP, UDP}`.
- Produces: `from remora import Capture, DNS, ETH, IP, TCP, UDP` for all downstream code (Task 3 uses these imports).

- [ ] **Step 1: Extend `tests/test_package.py` with a failing test**

Replace the file content with:

```python
import remora


def test_package_importable() -> None:
    assert isinstance(remora.__version__, str)


def test_public_exports() -> None:
    # The M1 public surface: Capture plus the seed protocols.
    from remora import DNS, ETH, IP, TCP, UDP, Capture

    assert Capture is remora.capture.Capture
    for proto in (DNS, ETH, IP, TCP, UDP):
        assert proto._proto_  # a real protocol class, not a stray import

    assert sorted(remora.__all__) == ["DNS", "ETH", "IP", "TCP", "UDP", "Capture", "__version__"]
```

Wait — `sorted()` puts `Capture` before `DNS` (uppercase C < D) and `__version__` last is wrong (`_` > letters). Use a set comparison instead; write exactly:

```python
    assert set(remora.__all__) == {"Capture", "DNS", "ETH", "IP", "TCP", "UDP", "__version__"}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_package.py -q`
Expected: FAIL (`ImportError`/`AttributeError`: no `Capture` in `remora`)

- [ ] **Step 3: Implement the exports in `src/remora/__init__.py`**

```python
"""Remora: a type-safe, IDE-friendly Python DSL for Wireshark/tshark capture analysis."""

from remora.capture import Capture
from remora.proto import DNS, ETH, IP, TCP, UDP

__version__ = "0.1.0"

__all__ = ["DNS", "ETH", "IP", "TCP", "UDP", "Capture", "__version__"]
```

(Ruff sorts `__all__`; accept whatever order `ruff format`/RUF022 wants.)

- [ ] **Step 4: Run the test and the gate**

Run: `uv run pytest tests/test_package.py -q && uv run ruff check . && uv run mypy --strict src tests`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/remora/__init__.py tests/test_package.py
git commit -m "core: export Capture and seed protocols from package root"
```

---

### Task 3: Integration tests — the acceptance criteria

**Files:**
- Create: `tests/test_capture_integration.py`

**Interfaces:**
- Consumes: `from remora import Capture, DNS, IP, TCP, UDP`; `tests/data/sample.pcap` (fixture facts above); `remora.capture` module internals only for the process spy (`capture_module.TsharkProcess`).
- Produces: nothing downstream; this file IS the acceptance test + quickstart snippet.

- [ ] **Step 1: Write the integration tests**

Create `tests/test_capture_integration.py`:

```python
"""End-to-end acceptance tests for issue #15: Capture over sample.pcap with real tshark.

This file is also the M1 quickstart snippet: it is type-checked by
``mypy --strict`` (the CI gate covers tests/), and the ``assert_type`` calls
pin the static type flow from ``FieldRef`` declarations to packet values.
``assert_type`` lines come BEFORE runtime asserts — an equality assert first
would narrow the type and break them.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from typing_extensions import assert_type

import remora.capture as capture_module
from remora import DNS, IP, TCP, UDP, Capture
from remora.fields import Packet
from remora.reader.process import TsharkProcess

DATA_DIR = Path(__file__).resolve().parent / "data"
PCAP = DATA_DIR / "sample.pcap"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed"),
]


class TestQuickstart:
    def test_pure_expr_query_returns_exactly_matching_packets(self) -> None:
        cap = Capture(PCAP).filter((IP.src == "10.0.0.1") & (TCP.port == 443))
        matched = list(cap)
        assert len(matched) == 1
        pkt = matched[0]
        src = pkt[IP].src
        ports = pkt[TCP].port
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src == IPv4Address("10.0.0.1")
        assert ports == (51234, 443)
        assert pkt[TCP].dstport == 443

    def test_no_match_is_empty(self) -> None:
        assert list(Capture(PCAP).filter(IP.src == "192.168.99.99")) == []

    def test_unfiltered_capture_yields_every_packet(self) -> None:
        assert len(list(Capture(PCAP))) == 3


class TestEkFallback:
    def test_expr_plus_lambda_takes_ek_path_end_to_end(self) -> None:
        cap = Capture(PCAP).filter(IP.src.present()).filter(lambda pkt: pkt[UDP].dstport == 53)
        assert cap.plan().mode == "ek"
        assert cap.plan().dfilter == "(ip.src)"
        matched = list(cap)
        assert len(matched) == 1
        names = matched[0][DNS].qry_name
        assert_type(names, tuple[str, ...])
        assert names == ("foo,bar.example",)


class TestProcessLifecycle:
    def test_early_break_terminates_tshark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        created: list[TsharkProcess] = []
        real = TsharkProcess

        def spy(argv: Sequence[str]) -> TsharkProcess:
            proc = real(argv)
            created.append(proc)
            return proc

        monkeypatch.setattr(capture_module, "TsharkProcess", spy)
        pkt: Packet
        for pkt in Capture(PCAP):
            break
        assert len(created) == 1
        # close() ran and reaped the child: a live or zombie process would
        # still poll() as None.
        assert created[0].returncode is not None
```

Note: `assert cap.plan().dfilter == "(ip.src)"` presumes `compile_dfilter` renders `Presence` as the bare field name — verify against `tests/test_dfilter.py` and use the actual rendering; if `Presence` is not pushable at all, drop the dfilter assert (the mode/results asserts are the acceptance criteria, not the exact dfilter string).

- [ ] **Step 2: Run the integration tests**

Run: `uv run pytest tests/test_capture_integration.py -q`
Expected: all PASS against the local tshark. If tshark is not installed locally, they must SKIP (and the earlier unit tests still cover the logic) — but on this machine tshark exists (`/opt/homebrew/bin/tshark`), so expect real runs.

- [ ] **Step 3: Verify the quickstart snippet types**

Run: `uv run mypy --strict src tests`
Expected: clean — this is acceptance criterion #4.

- [ ] **Step 4: Commit**

```bash
git add tests/test_capture_integration.py
git commit -m "tests: end-to-end Capture acceptance tests over sample.pcap"
```

---

### Task 4: Full gate + PR

**Files:** none new.

- [ ] **Step 1: Run the complete CI gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest -q`
Expected: all four green, including integration tests.

- [ ] **Step 2: Also verify the no-tshark path**

Run: `uv run pytest -m "not integration" -q`
Expected: green (integration tests deselected).

- [ ] **Step 3: Push branch and open the PR**

```bash
git push -u origin feat/issue-15-capture-api
gh pr create --title "core: wire end-to-end Capture query API" --body "$(cat <<'EOF'
## Summary
- add `Capture(path).filter(expr_or_lambda)` — immutable query builder; iteration plans the query, spawns tshark, and yields typed packets
- execution branches on `plan.mode` (fields projection vs ek fallback); residual predicates run in Python
- subprocess lifecycle: early break / consumer exception / exhaustion all close and reap tshark (no zombies)
- export `Capture` + seed protocols from the package root
- integration tests double as the mypy-strict-checked quickstart snippet

Closes #15

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Self-Review Notes

- Acceptance criterion 1 → Task 3 `test_pure_expr_query_returns_exactly_matching_packets`.
- Acceptance criterion 2 (mixed Expr + lambda, ek path, correct results) → Task 3 `TestEkFallback`.
- Acceptance criterion 3 (early break, no zombie) → Task 1 `test_early_break_closes_process` (unit) + Task 3 `TestProcessLifecycle` (real process, `returncode is not None` after break).
- Acceptance criterion 4 (quickstart passes mypy --strict) → Task 3 Step 3; `assert_type` before runtime asserts throughout.
- Issue scope "chooses fields-mode or ek-mode per the plan" → `_build_argv` + `__iter__` branch; fields branch unit-tested via injected plan (M1 public surface is always ek because `select=None` — documented in module docstring and planner docstring).
