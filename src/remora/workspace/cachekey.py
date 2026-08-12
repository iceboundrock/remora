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
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from remora.workspace.schema import CacheKeyRecord

__all__ = [
    "CACHE_KEY_VERSION",
    "FINGERPRINT_VERSION",
    "PROBE_BYTES",
    "PcapFingerprint",
    "fingerprint_pcap",
    "make_cache_key",
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


CACHE_KEY_VERSION: Final[str] = "ck1"
"""Cache-key scheme version, prefixed onto every key.

Stored keys carry it, so changing the scheme invalidates old entries visibly
instead of letting two schemes share one namespace.
"""


def _encode(value: bytes) -> bytes:
    """Length-prefix one component so no separator can be confused with data."""
    return _to_bytes(f"{len(value)}:") + value


def _encode_sequence(items: tuple[str, ...]) -> bytes:
    """Encode an ordered sequence, count first, each element length-prefixed."""
    parts = [_to_bytes(f"{len(items)}#")]
    parts.extend(_encode(_to_bytes(item)) for item in items)
    return b"".join(parts)


def _encode_optional(value: str | None) -> bytes:
    """Encode an optional component; absent digests differently from empty."""
    if value is None:
        return b"-"
    return b"+" + _encode(_to_bytes(value))


def _cache_key_digest(
    *,
    fingerprint: str,
    fields: tuple[str, ...],
    dfilter: str | None,
    tshark_version: str,
    argv: tuple[str, ...],
) -> str:
    """Digest the canonicalized components in a fixed order."""
    hasher = hashlib.sha256()
    hasher.update(_encode(_to_bytes(CACHE_KEY_VERSION)))
    hasher.update(_encode(_to_bytes(fingerprint)))
    hasher.update(_encode_sequence(fields))
    hasher.update(_encode_optional(dfilter))
    hasher.update(_encode(_to_bytes(tshark_version)))
    hasher.update(_encode_sequence(argv))
    return hasher.hexdigest()


def make_cache_key(
    *,
    pcap: str | os.PathLike[str],
    fields: Iterable[str],
    dfilter: str | None,
    tshark_version: str,
    argv: Iterable[str],
    fingerprint: PcapFingerprint | None = None,
    created_at: datetime | None = None,
) -> CacheKeyRecord:
    """Compute a materialization cache key and the record that stores it.

    The digest covers the capture's fingerprint, the canonicalized projection,
    the display filter, the tshark version, and the **full effective argv**,
    verbatim and order-sensitive — a different ``-X lua_script:``, ``-d`` or
    ``-o`` dissects identical bytes differently, so it must produce a
    different key.

    ``pcap_path`` is stored for diagnostics but is **not** hashed: argv
    already carries the path tshark was given, and hashing it a second time
    would turn "same capture, different relative path" into a needless miss.

    Args:
        pcap: Capture file the materialization reads.
        fields: tshark field abbrevs to project. Sorted and deduplicated, so
            the same set in any order yields the same key — and so #32's
            ``list_has_all`` subset test sees a canonical set.
        dfilter: Display filter pushed down, or None when unfiltered. None and
            ``""`` digest differently.
        tshark_version: Version string of the tshark that produces the data.
        argv: The exact argv that will be run.
        fingerprint: Precomputed fingerprint of ``pcap``; computed here when
            omitted. Pass one to avoid re-reading a capture already sampled.
        created_at: Record timestamp; ``now`` in UTC when omitted. Not hashed.

    Returns:
        A :class:`~remora.workspace.schema.CacheKeyRecord` holding the digest
        and every component it was computed from.

    Raises:
        OSError: If ``fingerprint`` is omitted and ``pcap`` cannot be read.
    """
    resolved = fingerprint if fingerprint is not None else fingerprint_pcap(pcap)
    canonical_fields = tuple(sorted(set(fields)))
    canonical_argv = tuple(argv)
    rendered = resolved.render()
    digest = _cache_key_digest(
        fingerprint=rendered,
        fields=canonical_fields,
        dfilter=dfilter,
        tshark_version=tshark_version,
        argv=canonical_argv,
    )
    return CacheKeyRecord(
        key=f"{CACHE_KEY_VERSION}:{digest}",
        pcap_path=os.fsdecode(pcap),
        pcap_fingerprint=rendered,
        fields=canonical_fields,
        dfilter=dfilter,
        tshark_version=tshark_version,
        argv=canonical_argv,
        created_at=created_at if created_at is not None else datetime.now(timezone.utc),
    )
