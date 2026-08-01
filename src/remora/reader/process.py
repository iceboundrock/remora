"""tshark subprocess lifecycle management.

This module owns exactly one concern: the lifecycle of a single tshark child
process. It knows nothing about capture filters, field selection, or output
parsing — callers hand it a fully-formed argv and consume stdout lines.

Two failure modes are engineered away at this layer:

1. **stderr pipe deadlock** — tshark writes progress/diagnostics to stderr; if
   nobody drains that pipe it fills (typically at 64 KiB) and the child blocks
   forever mid-write. A daemon thread drains stderr from the moment the child
   is spawned, keeping only a bounded tail of lines for error messages.
2. **orphaned children** — a consumer that breaks out of the stdout iterator
   early must not leak a running tshark. ``close()`` (invoked by ``__exit__``)
   terminates, waits with a timeout, escalates to kill, and always reaps the
   child, so cleanup is bounded in time and leaves no zombies.
"""

from __future__ import annotations

import contextlib
import subprocess
import threading
from collections import deque
from collections.abc import Iterator, Sequence

#: Number of trailing stderr lines retained for diagnostics.
_STDERR_TAIL_LINES = 256

#: Seconds to wait after terminate() before escalating to kill().
_TERMINATE_TIMEOUT = 3.0

#: Seconds to wait for the stderr drain thread to finish.
_THREAD_JOIN_TIMEOUT = 3.0


class TsharkError(RuntimeError):
    """tshark exited nonzero; message includes the tail of captured stderr."""


class TsharkNotFoundError(TsharkError):
    """tshark binary missing; message names the binary and how to point Remora at one."""


class TsharkProcess:
    """Context manager owning one tshark subprocess.

    - stdout: line iterator (text, utf-8, ``errors='replace'``, line separators stripped)
    - stderr: drained on a background thread into a bounded buffer (tail only)
    - ``close()``/``__exit__``: terminate -> wait(timeout) -> kill -> reap; bounded
      in time; no zombies
    - natural EOF with ``returncode != 0`` raises :class:`TsharkError` with the
      stderr tail; an exit we caused via ``close()`` never does
    - double-close and close-after-exhaustion are safe no-ops
    """

    def __init__(self, argv: Sequence[str]) -> None:
        self._argv = list(argv)
        self._closed = False
        self._we_terminated = False
        self._stderr_lines: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        try:
            self._proc = subprocess.Popen(
                self._argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise TsharkNotFoundError(
                f"tshark binary not found: {self._argv[0]!r}. Install Wireshark "
                "(which provides tshark) or point Remora at an explicit tshark "
                "executable path."
            ) from exc
        # Drain stderr immediately so the child can never block on a full
        # stderr pipe while we are (or are not yet) reading stdout.
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="remora-tshark-stderr",
            daemon=True,
        )
        self._stderr_thread.start()

    def __enter__(self) -> TsharkProcess:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __iter__(self) -> Iterator[str]:
        stdout = self._proc.stdout
        if stdout is None:  # pragma: no cover - stdout=PIPE guarantees a stream
            return
        for line in stdout:
            yield line.rstrip("\r\n")
        # Natural EOF: reap the child and surface its failure, if any.
        returncode = self._proc.wait()
        self._stderr_thread.join(timeout=_THREAD_JOIN_TIMEOUT)
        if returncode != 0 and not self._we_terminated:
            message = f"tshark exited with code {returncode}"
            tail = self._stderr_tail()
            if tail:
                message = f"{message}; stderr tail:\n{tail}"
            raise TsharkError(message)

    def close(self) -> None:
        """Stop the child if still running and reap it. Idempotent and bounded."""
        if self._closed:
            return
        self._closed = True
        if self._proc.poll() is None:
            # Remember that *we* stopped the child so a subsequent iterator
            # EOF does not mistake the signal exit for a tshark failure.
            self._we_terminated = True
            self._proc.terminate()
            try:
                self._proc.wait(timeout=_TERMINATE_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._stderr_thread.join(timeout=_THREAD_JOIN_TIMEOUT)
        for stream in (self._proc.stdout, self._proc.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()

    def _drain_stderr(self) -> None:
        stderr = self._proc.stderr
        if stderr is None:  # pragma: no cover - stderr=PIPE guarantees a stream
            return
        try:
            for line in stderr:
                self._stderr_lines.append(line.rstrip("\r\n"))
        except ValueError:  # pragma: no cover - stream closed during shutdown
            pass

    def _stderr_tail(self) -> str:
        return "\n".join(self._stderr_lines)
