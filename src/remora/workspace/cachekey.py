"""Pcap fingerprint and materialization cache key (issue #27).

Reusing a materialized table is only correct when the key covers everything
that can change tshark's output. The notorious omission is the argument
vector: a different ``-X lua_script:`` or ``-d`` dissects the same bytes into
different fields, so argv is hashed verbatim alongside the capture's identity.

The pcap fingerprint is deliberately **not** a whole-file digest — it is
``st_size``, ``st_mtime_ns``, and a sha256 over the first and last 64 KiB.
Materializing a multi-gigabyte capture must not be preceded by reading that
capture twice. The price is a real blind spot: editing the middle of a large
file in place, without changing its length or mtime, produces the same
fingerprint. A test pins that behaviour so it stays a known trade-off.

This module computes; it stores nothing. :func:`make_cache_key` returns the
:class:`~remora.workspace.schema.CacheKeyRecord` that
:func:`~remora.workspace.schema.record_cache_key` persists, so the components
that were hashed and the components that get written cannot drift apart.
Hit/miss and backfill are issue #32's.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Final

__all__ = [
    "FINGERPRINT_VERSION",
    "PROBE_BYTES",
    "PcapFingerprint",
    "fingerprint_pcap",
]

PROBE_BYTES: Final[int] = 64 * 1024
"""Bytes sampled from the head and, separately, from the tail of a capture."""

FINGERPRINT_VERSION: Final[str] = "fp1"
"""Fingerprint scheme version, rendered as the leading component."""


def _to_bytes(text: str) -> bytes:
    """Encode a caller-supplied string, tolerating non-UTF-8 paths and argv."""
    return text.encode("utf-8", "surrogateescape")


@dataclass(frozen=True)
class PcapFingerprint:
    """Cheap identity of a capture file: size, mtime, and a content sample.

    Attributes:
        size: File size in bytes.
        mtime_ns: Modification time in integer nanoseconds — exact and
            platform-stable, unlike the float ``st_mtime``.
        probe_sha256: Digest over the sampled head and tail *only*. Size and
            mtime are deliberately outside it, so touching a file's mtime
            leaves this digest identical while :meth:`render` changes.
    """

    size: int
    mtime_ns: int
    probe_sha256: str

    def render(self) -> str:
        """Render the fingerprint as one diagnosable line."""
        return (
            f"{FINGERPRINT_VERSION}:size={self.size}"
            f":mtime={self.mtime_ns}:probe={self.probe_sha256}"
        )


def _probe_digest(head: bytes, tail: bytes) -> str:
    """Digest the two samples, length-tagged so their boundary is unambiguous."""
    hasher = hashlib.sha256()
    hasher.update(_to_bytes(f"{FINGERPRINT_VERSION}\n"))
    for chunk in (head, tail):
        hasher.update(_to_bytes(f"{len(chunk)}:"))
        hasher.update(chunk)
    return hasher.hexdigest()


def fingerprint_pcap(path: str | os.PathLike[str]) -> PcapFingerprint:
    """Fingerprint a capture file, reading at most 128 KiB of it.

    Files of ``PROBE_BYTES`` or smaller are read once, in full: the tail
    sample is skipped rather than overlapping the head.

    Args:
        path: Capture file to fingerprint.

    Returns:
        The file's fingerprint.

    Raises:
        OSError: If the file cannot be stat-ed or read. Deliberately
            unwrapped — the caller wants the real errno.
    """
    stat = os.stat(path)
    size = stat.st_size
    with open(path, "rb") as handle:
        head = handle.read(min(PROBE_BYTES, size))
        tail = b""
        if size > PROBE_BYTES:
            handle.seek(size - PROBE_BYTES)
            tail = handle.read(PROBE_BYTES)
    return PcapFingerprint(
        size=size,
        mtime_ns=stat.st_mtime_ns,
        probe_sha256=_probe_digest(head, tail),
    )
