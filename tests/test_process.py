"""Tests for tshark subprocess lifecycle management (uses fake python children)."""

from __future__ import annotations

import sys
import time
from collections.abc import Generator

import pytest

from remora.reader.process import TsharkError, TsharkNotFoundError, TsharkProcess


def _fake_child(code: str) -> list[str]:
    """Build an argv running an inline python script as a stand-in for tshark."""
    return [sys.executable, "-u", "-c", code]


def test_stderr_flood_does_not_deadlock() -> None:
    """Child writes > 64 KiB to stderr interleaved with stdout; iteration completes."""
    code = (
        "import sys\n"
        "for i in range(10):\n"
        "    sys.stdout.write(f'line{i}\\n')\n"
        "    sys.stdout.flush()\n"
        "    sys.stderr.write(('e' * 1023 + '\\n') * 16)\n"  # 16 KiB per stdout line
        "    sys.stderr.flush()\n"
    )
    with TsharkProcess(_fake_child(code)) as proc:
        lines = list(proc)
    assert lines == [f"line{i}" for i in range(10)]


def test_early_break_terminates_child_bounded() -> None:
    """Breaking out of iteration inside `with` terminates and reaps the child quickly."""
    code = (
        "import sys, time\n"
        "i = 0\n"
        "while True:\n"
        "    print(i, flush=True)\n"
        "    i += 1\n"
        "    time.sleep(0.01)\n"
    )
    proc = TsharkProcess(_fake_child(code))
    with proc:
        for line in proc:
            assert line == "0"
            break
        start = time.monotonic()
    elapsed = time.monotonic() - start
    # Generous ceiling: asserts boundedness (terminate is ~ms; the 3s grace
    # before kill is the theoretical worst case), not speed. Keeps CI stable.
    assert elapsed < 10.0, f"close() took {elapsed:.1f}s; termination must be bounded"
    assert proc.returncode is not None, "child was not reaped (potential zombie)"


def test_iterator_close_without_context_manager_reaps_child() -> None:
    """Closing the stdout iterator (no `with` block) terminates and reaps the child."""
    code = "import time\nwhile True:\n    print('tick', flush=True)\n    time.sleep(0.01)\n"
    proc = TsharkProcess(_fake_child(code))
    it = iter(proc)
    assert isinstance(it, Generator)
    assert next(it) == "tick"
    it.close()  # raises GeneratorExit at the yield; finally must run close()
    assert proc.returncode is not None, "child was not reaped (potential zombie)"


def test_consumer_exception_without_context_manager_reaps_child() -> None:
    """An exception thrown into iteration (no `with` block) still reaps the child."""
    code = "import time\nwhile True:\n    print('tick', flush=True)\n    time.sleep(0.01)\n"
    proc = TsharkProcess(_fake_child(code))
    with pytest.raises(RuntimeError, match="consumer blew up"):
        for _line in proc:
            raise RuntimeError("consumer blew up")
    assert proc.returncode is not None, "child was not reaped (potential zombie)"


def test_nonzero_exit_raises_with_stderr_tail() -> None:
    code = "import sys\nsys.stderr.write('boom: capture interface exploded\\n')\nsys.exit(2)\n"
    with pytest.raises(TsharkError) as excinfo, TsharkProcess(_fake_child(code)) as proc:
        list(proc)
    message = str(excinfo.value)
    assert "code 2" in message
    assert "boom: capture interface exploded" in message


def test_stderr_tail_is_bounded_to_the_tail() -> None:
    """Only the tail of a huge stderr stream appears in the error message."""
    code = "import sys\nfor i in range(5000):\n    sys.stderr.write(f'noise-{i}\\n')\nsys.exit(1)\n"
    with pytest.raises(TsharkError) as excinfo, TsharkProcess(_fake_child(code)) as proc:
        list(proc)
    message = str(excinfo.value)
    assert "noise-4999" in message, "tail (most recent stderr) must be kept"
    assert "noise-0\n" not in message, "oldest stderr must have been evicted"


def test_missing_binary_raises_not_found_naming_it() -> None:
    binary = "definitely-not-a-real-binary-xyz"
    with pytest.raises(TsharkNotFoundError) as excinfo:
        TsharkProcess([binary, "-i", "any"])
    assert binary in str(excinfo.value)
    assert issubclass(TsharkNotFoundError, TsharkError)


def test_double_close_and_close_after_exhaustion_are_noops() -> None:
    code = "print('only-line')\n"
    proc = TsharkProcess(_fake_child(code))
    with proc:
        assert list(proc) == ["only-line"]
    # __exit__ already closed once; explicit closes must be safe no-ops.
    proc.close()
    proc.close()
    assert proc.returncode == 0
