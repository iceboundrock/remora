"""Workspace cache key tests (issue #27)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import pytest

from remora.workspace.cachekey import (
    PROBE_BYTES,
    fingerprint_pcap,
)

LARGE = 300 * 1024  # comfortably past head + tail, so the middle is unsampled


def write_pcap(path: Path, payload: bytes) -> Path:
    """Write payload and return the path."""
    path.write_bytes(payload)
    return path


def large_payload(fill: bytes = b"\x00") -> bytearray:
    """A LARGE-byte body with distinguishable head, middle and tail."""
    body = bytearray(fill * LARGE)
    body[:4] = b"HEAD"
    body[LARGE // 2 : LARGE // 2 + 3] = b"MID"
    body[-4:] = b"TAIL"
    return body


class CountingHandle:
    """Binary file wrapper that tallies every byte handed back by read()."""

    def __init__(self, handle: IO[bytes]) -> None:
        self.handle = handle
        self.read_bytes = 0

    def read(self, size: int = -1) -> bytes:
        data = self.handle.read(size)
        self.read_bytes += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.handle.seek(offset, whence)

    def __enter__(self) -> CountingHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.handle.close()


def count_reads(monkeypatch: pytest.MonkeyPatch, call: Callable[[], object]) -> int:
    """Run `call` with builtins.open instrumented; return total bytes read."""
    real_open = open
    counters: list[CountingHandle] = []

    def counting_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        handle = real_open(file, mode, *args, **kwargs)
        counter = CountingHandle(handle)
        counters.append(counter)
        return counter

    monkeypatch.setattr("builtins.open", counting_open)
    try:
        call()
    finally:
        monkeypatch.undo()
    return sum(counter.read_bytes for counter in counters)


class TestFingerprint:
    def test_same_content_different_path_same_probe(self, tmp_path: Path) -> None:
        a = write_pcap(tmp_path / "a.pcap", b"same bytes")
        b = write_pcap(tmp_path / "b.pcap", b"same bytes")
        assert fingerprint_pcap(a).probe_sha256 == fingerprint_pcap(b).probe_sha256

    def test_head_change_flips(self, tmp_path: Path) -> None:
        body = large_payload()
        before = fingerprint_pcap(write_pcap(tmp_path / "c.pcap", bytes(body)))
        body[:4] = b"XXXX"
        after = fingerprint_pcap(write_pcap(tmp_path / "c.pcap", bytes(body)))
        assert before.probe_sha256 != after.probe_sha256

    def test_tail_change_flips(self, tmp_path: Path) -> None:
        body = large_payload()
        before = fingerprint_pcap(write_pcap(tmp_path / "d.pcap", bytes(body)))
        body[-4:] = b"ZZZZ"
        after = fingerprint_pcap(write_pcap(tmp_path / "d.pcap", bytes(body)))
        assert before.probe_sha256 != after.probe_sha256

    def test_middle_change_does_not_flip(self, tmp_path: Path) -> None:
        """The deliberate blind spot: this is a sample, not a whole-file digest."""
        body = large_payload()
        before = fingerprint_pcap(write_pcap(tmp_path / "e.pcap", bytes(body)))
        body[LARGE // 2 : LARGE // 2 + 3] = b"ZAP"
        after = fingerprint_pcap(write_pcap(tmp_path / "e.pcap", bytes(body)))
        assert before.probe_sha256 == after.probe_sha256

    def test_size_alone_flips_the_fingerprint(self, tmp_path: Path) -> None:
        """Uniform fill: head and tail bytes match, only the length differs."""
        short = fingerprint_pcap(write_pcap(tmp_path / "f.pcap", b"x" * LARGE))
        longer = fingerprint_pcap(write_pcap(tmp_path / "g.pcap", b"x" * (LARGE + 1)))
        assert short.probe_sha256 == longer.probe_sha256
        assert short.size != longer.size
        assert short.render() != longer.render()

    def test_mtime_alone_flips_the_fingerprint(self, tmp_path: Path) -> None:
        path = write_pcap(tmp_path / "h.pcap", b"stable bytes")
        before = fingerprint_pcap(path)
        stamp = before.mtime_ns + 1_000_000
        os.utime(path, ns=(stamp, stamp))
        after = fingerprint_pcap(path)
        assert before.probe_sha256 == after.probe_sha256
        assert before.mtime_ns != after.mtime_ns
        assert before.render() != after.render()

    def test_render_is_diagnosable(self, tmp_path: Path) -> None:
        fp = fingerprint_pcap(write_pcap(tmp_path / "i.pcap", b"abc"))
        rendered = fp.render()
        assert rendered.startswith("fp1:")
        assert f"size={fp.size}" in rendered
        assert f"mtime={fp.mtime_ns}" in rendered
        assert f"probe={fp.probe_sha256}" in rendered

    def test_missing_file_raises_oserror(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            fingerprint_pcap(tmp_path / "nope.pcap")

    def test_empty_file(self, tmp_path: Path) -> None:
        fp = fingerprint_pcap(write_pcap(tmp_path / "j.pcap", b""))
        assert fp.size == 0
        assert len(fp.probe_sha256) == 64


class TestReadCeiling:
    def test_large_file_reads_at_most_128_kib(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        big = tmp_path / "big.pcap"
        with open(big, "wb") as handle:
            handle.write(b"HEAD")
            handle.truncate(512 * 1024 * 1024)
            handle.seek(512 * 1024 * 1024 - 4)
            handle.write(b"TAIL")
        assert big.stat().st_size == 512 * 1024 * 1024
        assert count_reads(monkeypatch, lambda: fingerprint_pcap(big)) <= 2 * PROBE_BYTES

    def test_small_file_reads_no_more_than_its_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        small = write_pcap(tmp_path / "small.pcap", b"y" * 1000)
        assert count_reads(monkeypatch, lambda: fingerprint_pcap(small)) <= 1000
