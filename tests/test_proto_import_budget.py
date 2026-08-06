"""Benchmark guard: importing generated protocol modules must stay cheap (#23).

Lazy field materialization (``remora.proto._meta``) promises that importing a
generated protocol module does no per-field descriptor work: import executes
only the compact ``_table_`` dict literal, and each ``Field``/``MultiField``
descriptor is built on first attribute access. These tests pin that promise so
a future refactor cannot silently regress it.

Methodology (flake resistance):

- Each sample re-executes the module in-process (pop from ``sys.modules``,
  re-import). Dependencies (``remora.fields``, ``_meta``) stay warm, so the
  sample isolates the module's own execution cost. A warm-up import first
  compiles the ``.pyc`` and warms OS caches.
- Assertions use the **median** of ``RUNS`` samples, which shrugs off GC
  pauses and scheduler noise that would sink a mean or a single sample.
- Budgets are generous ceilings (~200x/~10000x measured medians), sized for
  slow shared CI runners, not targets.

Division of labor: the timing budgets catch gross regressions (accidental
I/O, quadratic work, per-field parsing at import). They deliberately cannot
catch eager materialization itself — building all 3912 wlan descriptors
costs only ~8 ms, inside any flake-safe ceiling — so
``test_import_materializes_no_descriptors`` pins laziness structurally and
deterministically instead.

Budgets and rationale:

- ``IMPORT_BUDGET_S``: importing the largest committed generated module
  (wlan, 3912 fields, ~360 KB source) measured a 1.3 ms median on a 2024
  laptop; 250 ms leaves ~200x headroom for slow shared CI runners.
- ``FIRST_ACCESS_BUDGET_S``: cold first access materializes exactly one
  descriptor, measured ~2 us median; 25 ms is ~10000x headroom.
- Field-count independence is enforced two ways. Exactly:
  ``test_import_materializes_no_descriptors`` asserts importing does zero
  per-field descriptor work — the guard for cheap per-field regressions
  (descriptor construction costs only ~2 us/field, too little for a
  flake-safe timing ceiling). Measurably: ``PER_FIELD_IMPORT_BUDGET_S``
  bounds the marginal wall-clock cost per field — the slope between the
  smallest (vlan, 10 fields) and largest (wlan) committed generated
  modules — at 5 us/field. The measured slope is ~0.33 us/field (executing
  one more precompiled ``_table_`` dict entry), so the budget has ~15x
  headroom for slow CI runners while still failing on any added per-field
  import-time work (parsing, I/O, object construction) beyond raw table
  entry cost.
"""

from __future__ import annotations

import importlib
import statistics
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from types import ModuleType
from typing import Any

from remora.fields import Field, MultiField

RUNS = 15

IMPORT_BUDGET_S = 0.250
FIRST_ACCESS_BUDGET_S = 0.025
PER_FIELD_IMPORT_BUDGET_S = 5e-6

#: Largest committed generated protocol module (remora-wireless workspace
#: package, always installed via the dev dependency group — do not skip when
#: missing, a skip would silently disable this guard).
LARGEST_MODULE = "remora.proto.wlan"
LARGEST_CLASS = "WLAN"
#: Smallest committed generated core module, the field-count-independence baseline.
SMALLEST_MODULE = "remora.proto.vlan"
SMALLEST_CLASS = "VLAN"


@contextmanager
def _restore_module(name: str) -> Iterator[None]:
    """Undo re-imports afterwards so other test files see the original state.

    Restores both places the import system mutates: the ``sys.modules`` entry
    and the attribute on the parent package. When the module was absent on
    entry, both are removed again — a run of this file leaves no trace either
    way, regardless of test order.
    """
    parent_name, _, child = name.rpartition(".")
    original = sys.modules.get(name)
    try:
        yield
    finally:
        parent = sys.modules[parent_name]
        if original is not None:
            sys.modules[name] = original
            setattr(parent, child, original)
        else:
            sys.modules.pop(name, None)
            if child in vars(parent):
                delattr(parent, child)


def _reimport(name: str) -> ModuleType:
    sys.modules.pop(name, None)
    return importlib.import_module(name)


def _table_of(module: ModuleType, class_name: str) -> dict[str, tuple[str, str, int]]:
    table: dict[str, tuple[str, str, int]] = getattr(module, class_name)._table_
    return table


def _median_import_s(name: str) -> float:
    with _restore_module(name):
        _reimport(name)  # warm-up: compile the .pyc, warm OS caches
        samples: list[float] = []
        for _ in range(RUNS):
            sys.modules.pop(name)
            start = time.perf_counter()
            importlib.import_module(name)
            samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _median_cold_first_access_s(name: str, class_name: str) -> float:
    with _restore_module(name):
        samples: list[float] = []
        for _ in range(RUNS):
            module = _reimport(name)  # fresh class objects: cold descriptor cache
            cls: Any = getattr(module, class_name)
            attr = next(iter(cls._table_))
            start = time.perf_counter()
            getattr(cls, attr)
            samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _materialized_descriptor_count(cls: type) -> int:
    return sum(isinstance(value, (Field, MultiField)) for value in vars(cls).values())


def test_largest_module_import_within_budget() -> None:
    median = _median_import_s(LARGEST_MODULE)
    assert median < IMPORT_BUDGET_S, (
        f"median import of {LARGEST_MODULE} took {median * 1000:.1f} ms "
        f"(budget {IMPORT_BUDGET_S * 1000:.0f} ms)"
    )


def test_cold_first_field_access_within_budget() -> None:
    median = _median_cold_first_access_s(LARGEST_MODULE, LARGEST_CLASS)
    assert median < FIRST_ACCESS_BUDGET_S, (
        f"median cold first-field access on {LARGEST_CLASS} took "
        f"{median * 1000:.3f} ms (budget {FIRST_ACCESS_BUDGET_S * 1000:.0f} ms)"
    )


def test_import_cost_independent_of_field_count() -> None:
    largest_s = _median_import_s(LARGEST_MODULE)
    smallest_s = _median_import_s(SMALLEST_MODULE)
    with _restore_module(LARGEST_MODULE), _restore_module(SMALLEST_MODULE):
        largest_fields = len(_table_of(_reimport(LARGEST_MODULE), LARGEST_CLASS))
        smallest_fields = len(_table_of(_reimport(SMALLEST_MODULE), SMALLEST_CLASS))
    per_field_s = (largest_s - smallest_s) / (largest_fields - smallest_fields)
    assert per_field_s < PER_FIELD_IMPORT_BUDGET_S, (
        f"marginal import cost is {per_field_s * 1e6:.2f} us per field "
        f"(budget {PER_FIELD_IMPORT_BUDGET_S * 1e6:.0f} us) — importing is doing per-field work"
    )


def test_import_materializes_no_descriptors() -> None:
    with _restore_module(LARGEST_MODULE):
        module = _reimport(LARGEST_MODULE)
        cls: Any = getattr(module, LARGEST_CLASS)
        assert _materialized_descriptor_count(cls) == 0, (
            "importing the module materialized descriptors eagerly"
        )
        getattr(cls, next(iter(cls._table_)))
        assert _materialized_descriptor_count(cls) == 1, (
            "first field access should materialize exactly one descriptor"
        )
