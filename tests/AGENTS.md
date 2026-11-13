# tests/AGENTS.md

The root `AGENTS.md` has the commands and the five-part CI gate. Tests that freeze a module's contract are named in that module's `AGENTS.md`.

## Typing

- mypy verifies the `assert_type(...)` calls in `tests/`. Put them before runtime asserts, because `assert x == value` narrows a type and can break a later `assert_type`.

## Doubles and dependency guards

- `tests/conftest.py` provides `FakePacket`, the standard `RawPacket` double, and the dependency guard. Workspace suites `importorskip("duckdb")`, and `REMORA_REQUIRE_DUCKDB=1` / `REMORA_REQUIRE_TSHARK=1` (set in CI) turn a missing dependency into a failed run instead of a skipped one.

## CI legs

- CI's `checks` job installs Ubuntu 24.04's stock tshark (4.2.2), not the codegen pin. Behavior asserted against a live binary must hold on both, so measure on 4.2.2 first.
- The `windows` CI job runs `mypy --strict src tests` and `pytest -m "not integration"` on `windows-latest`, minus the three codegen suites that fail there for test-only reasons (#129). The tshark integration suite stays Linux-only.

## Workspace integration suites (`integration/workspace/`)

- `test_parity_matrix.py` asserts parity between the workspace and the pcap path operator by operator (#38).
- `test_benchmark.py` (`slow`) asserts `MIN_SPEEDUP = 5.0` for a cached repeat query against the projected `Capture.select(...)` baseline, an order of magnitude under the measured speedup so a shared runner cannot flake it. The `-T ek` side is printed and never asserted (#105).
