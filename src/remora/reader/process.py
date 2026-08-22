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
   early must not leak a running tshark. ``close()`` terminates, waits with a
   timeout, escalates to kill, and always reaps the child, so cleanup is
   bounded in time and leaves no zombies. It is invoked by ``__exit__``, by
   the iterator's ``finally`` clause (early break, iterator close, consumer
   exception, or GC of the generator), and as a last resort by ``__del__``.
"""

from __future__ import annotations

import contextlib
import subprocess
import threading
from collections import deque
from collections.abc import Iterator, Sequence

__all__ = ["TsharkError", "TsharkNotFoundError", "TsharkProcess", "probe_tshark_version"]

#: Number of trailing stderr lines retained for diagnostics.
_STDERR_TAIL_LINES = 256

#: Seconds to wait after terminate() before escalating to kill().
_TERMINATE_TIMEOUT = 3.0

#: Seconds to wait for the stderr drain thread to finish.
_THREAD_JOIN_TIMEOUT = 3.0

#: Seconds allowed for the ``--version`` probe. A binary that cannot answer
#: that fast is broken, and the reader must not hang waiting to find out.
_VERSION_PROBE_TIMEOUT = 10.0


def probe_tshark_version(tshark: str) -> str | None:
    """Best-effort ``X.Y.Z`` version of the *tshark* binary; ``None`` if unknown.

    This deliberately never raises, which is what separates it from
    :func:`remora.workspace.materialize.detect_tshark_version`: that one is a
    cache-key component and must fail loudly about which binary produced a
    materialization, whereas this one only picks a *conservative default* for
    :func:`remora.reader.fields_reader.escaping_is_reversible`, where "cannot
    tell" and "too old to trust" want exactly the same answer. A binary that
    is genuinely missing or broken surfaces a moment later from the real run,
    with a better message than a version probe could give.
    """
    # Imported in the function body, not at module scope: remora.codegen is
    # the code generator, and importing the reader must not drag it in for a
    # parse that only this probe performs.
    from remora.codegen.fingerprint import parse_tshark_version

    try:
        output = subprocess.run(
            [tshark, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=_VERSION_PROBE_TIMEOUT,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return parse_tshark_version(output)
    except ValueError:
        return None


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

    def __del__(self) -> None:
        # Last-resort safety net for consumers that use neither the context
        # manager nor the iterator; close() is idempotent and bounded.
        with contextlib.suppress(Exception):
            self.close()

    @property
    def returncode(self) -> int | None:
        """The child's exit code, or None while it is still running."""
        return self._proc.poll()

    def __iter__(self) -> Iterator[str]:
        stdout = self._proc.stdout
        if stdout is None:  # pragma: no cover - stdout=PIPE guarantees a stream
            return
        # The finally clause honors "terminate-and-reap on iterator close":
        # closing this generator (explicitly, on early break, or via GC)
        # raises GeneratorExit at the yield point, and any consumer exception
        # unwinds through here too — with or without the context manager.
        try:
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
        finally:
            self.close()

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
