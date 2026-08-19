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
Hit/miss and backfill belong to :mod:`remora.workspace.materialize` (#32),
which compares these components one by one rather than the digest — the digest
covers the requested field set, so two requests differing only in their
projection have different digests by construction.

Hashing and storing draw their boundaries in different places, deliberately.
Hashing tolerates any ``str``: :func:`_to_bytes` encodes with
``surrogateescape``, so a path or argv element that :func:`os.fsdecode` turned
into lone surrogates still digests. The *record* is stricter, because its
string components land in DuckDB ``VARCHAR``/``VARCHAR[]`` columns and DuckDB
refuses a string that is not valid UTF-8. :func:`make_cache_key` therefore
rejects an unstorable component up front, naming it, rather than letting the
write fail later inside pybind11 with a message that identifies neither the
component nor the value. Ordinary non-ASCII Unicode is unaffected — only lone
surrogates are refused. Encoding arbitrary bytes losslessly into ``VARCHAR``
would need a reversible tag scheme, hence a storage-format change and a
``SCHEMA_VERSION`` bump, at the cost of the workspace file staying directly
queryable; narrowing the guarantee is the cheaper trade for a rare case.
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
    """Encode a caller-supplied string, tolerating non-UTF-8 paths and argv.

    A hashing primitive, and total by design: it hashes anything and never
    raises. Do not "simplify" it to strict UTF-8 — storability is a separate
    concern, checked by :func:`_check_storable` with an error that names the
    offending component. Tightening this instead would move the failure back
    into the digest, where there is no such context.
    """
    return text.encode("utf-8", "surrogateescape")


def _check_storable(component: str, value: str) -> None:
    """Refuse a string the workspace's ``VARCHAR`` columns cannot hold.

    Args:
        component: Name of the record component, used in the message.
        value: The string to check.

    Raises:
        ValueError: If ``value`` is not encodable as strict UTF-8 — in
            practice, a lone surrogate from :func:`os.fsdecode` of a non-UTF-8
            path or argv element.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"cache key {component} is not storable: DuckDB VARCHAR holds only "
            f"valid UTF-8, and this string is not: {value!r}"
        ) from exc


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
        OSError: If the file cannot be opened, stat-ed or read. Deliberately
            unwrapped — the caller wants the real errno.
    """
    # Size, mtime and the sampled bytes all come from one descriptor: an
    # os.stat before the open would let a growing or rotating capture pair a
    # stale size with fresh bytes, and the fingerprint would describe neither.
    with open(path, "rb") as handle:
        stat = os.fstat(handle.fileno())
        size = stat.st_size
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

    ``pcap_path`` is stored for diagnostics but is **not** hashed: argv already
    carries the path tshark was given, and ``pcap`` need not spell that same
    file the same way argv's ``-r`` does. Hashing it too would add a second,
    independent path dependence to a key that already has one.

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
        TypeError: If ``fields`` or ``argv`` is a ``str``. Both are iterables
            of strings, and a bare ``str`` iterates into characters — silently
            keying on six one-character "abbrevs" instead of ``"ip.src"``.
        ValueError: If any string that lands in the record — ``pcap``, a field,
            ``dfilter``, ``tshark_version`` or an argv element — is not valid
            UTF-8 and so cannot be stored in a DuckDB ``VARCHAR``. Checked
            before any file is read, so a doomed call costs no I/O.
        OSError: If ``fingerprint`` is omitted and ``pcap`` cannot be read.
    """
    if isinstance(fields, str) or isinstance(argv, str):
        raise TypeError(
            "fields and argv must be iterables of strings, not a single str: "
            "a bare str iterates into its characters"
        )
    canonical_fields = tuple(sorted(set(fields)))
    canonical_argv = tuple(argv)
    pcap_path = os.fsdecode(pcap)
    # Before the fingerprint, so an unstorable component costs no file read.
    _check_storable("pcap_path", pcap_path)
    for field in canonical_fields:
        _check_storable("fields element", field)
    if dfilter is not None:
        _check_storable("dfilter", dfilter)
    _check_storable("tshark_version", tshark_version)
    for argument in canonical_argv:
        _check_storable("argv element", argument)
    resolved = fingerprint if fingerprint is not None else fingerprint_pcap(pcap)
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
        pcap_path=pcap_path,
        pcap_fingerprint=rendered,
        fields=canonical_fields,
        dfilter=dfilter,
        tshark_version=tshark_version,
        argv=canonical_argv,
        created_at=created_at if created_at is not None else datetime.now(timezone.utc),
    )
