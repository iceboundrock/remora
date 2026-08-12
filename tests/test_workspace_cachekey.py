"""Workspace cache key tests (issue #27)."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

import pytest

from remora.workspace.cachekey import (
    CACHE_KEY_VERSION,
    PROBE_BYTES,
    PcapFingerprint,
    fingerprint_pcap,
    make_cache_key,
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

    def fileno(self) -> int:
        return self.handle.fileno()

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
        """The deliberate blind spot: this is a sample, not a whole-file digest.

        Pinned on the *whole* fingerprint, which is what the docs claim: an
        in-place middle edit that changes neither length nor mtime is
        indistinguishable. Hence rewrite_keeping_mtime — a plain rewrite would
        bump mtime and only the probe digest would still match.
        """
        body = large_payload()
        path = write_pcap(tmp_path / "e.pcap", bytes(body))
        before = fingerprint_pcap(path)
        body[LARGE // 2 : LARGE // 2 + 3] = b"ZAP"
        rewrite_keeping_mtime(path, bytes(body))
        after = fingerprint_pcap(path)
        assert before == after

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
        # The lower bound is not pedantry: count_reads instruments builtins.open,
        # so a refactor to Path.read_bytes/mmap/os.pread would count 0 and pass
        # this vacuously, silently unguarding the read ceiling.
        count = count_reads(monkeypatch, lambda: fingerprint_pcap(big))
        assert 0 < count <= 2 * PROBE_BYTES

    def test_small_file_reads_no_more_than_its_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        small = write_pcap(tmp_path / "small.pcap", b"y" * 1000)
        count = count_reads(monkeypatch, lambda: fingerprint_pcap(small))
        assert 0 < count <= 1000


BASE_ARGV = (
    "tshark",
    "-r",
    "cap.pcap",
    "-T",
    "fields",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
)

# Pinned so an accidental change to the key scheme fails loudly. Regenerating
# this value is a deliberate act: it means every stored key just went stale.
GOLDEN_KEY = "ck1:fa6dcc3d30d9f05d80b69a56ac63fed117b7113a40cbbdcb56cdd43182d78b21"


def rewrite_keeping_mtime(path: Path, body: bytes) -> None:
    """Replace a capture's bytes and restore its mtime.

    mtime is part of the hashed fingerprint, so a plain `write_bytes` would
    flip the key on its own — a content-blind fingerprint would still pass.
    Restoring the stamp leaves content as the only difference.
    """
    stamp = path.stat().st_mtime_ns
    path.write_bytes(body)
    os.utime(path, ns=(stamp, stamp))


def key_for(path: Path, **overrides: Any) -> str:
    """Build a cache key over a fixed baseline, with named overrides."""
    kwargs: dict[str, Any] = {
        "pcap": path,
        "fields": ["ip.src", "ip.dst"],
        "dfilter": "tcp",
        "tshark_version": "4.6.7",
        "argv": BASE_ARGV,
    }
    kwargs.update(overrides)
    return make_cache_key(**kwargs).key


@pytest.fixture
def cap(tmp_path: Path) -> Path:
    """A capture large enough that head, middle and tail are distinct."""
    return write_pcap(tmp_path / "cap.pcap", bytes(large_payload()))


class TestCacheKeyComponents:
    def test_identical_inputs_give_identical_keys(self, cap: Path) -> None:
        assert key_for(cap) == key_for(cap)

    def test_key_carries_the_scheme_version(self, cap: Path) -> None:
        key = key_for(cap)
        assert key.startswith(f"{CACHE_KEY_VERSION}:")
        assert len(key.split(":")[1]) == 64

    def test_pcap_head_change_flips(self, cap: Path) -> None:
        before = key_for(cap)
        body = bytearray(cap.read_bytes())
        body[:4] = b"XXXX"
        rewrite_keeping_mtime(cap, bytes(body))
        assert key_for(cap) != before

    def test_pcap_tail_change_flips(self, cap: Path) -> None:
        before = key_for(cap)
        body = bytearray(cap.read_bytes())
        body[-4:] = b"ZZZZ"
        rewrite_keeping_mtime(cap, bytes(body))
        assert key_for(cap) != before

    def test_size_change_flips(self, cap: Path) -> None:
        before = key_for(cap)
        rewrite_keeping_mtime(cap, cap.read_bytes() + b"!")
        assert key_for(cap) != before

    def test_mtime_change_flips(self, cap: Path) -> None:
        before = key_for(cap)
        stamp = cap.stat().st_mtime_ns + 1_000_000
        os.utime(cap, ns=(stamp, stamp))
        assert key_for(cap) != before

    def test_projection_change_flips(self, cap: Path) -> None:
        assert key_for(cap, fields=["ip.src"]) != key_for(cap)

    def test_projection_is_order_insensitive(self, cap: Path) -> None:
        assert key_for(cap, fields=["ip.dst", "ip.src"]) == key_for(cap)

    def test_projection_is_deduplicated(self, cap: Path) -> None:
        assert key_for(cap, fields=["ip.src", "ip.dst", "ip.src"]) == key_for(cap)

    def test_bare_str_fields_is_rejected(self, cap: Path) -> None:
        """A str is an Iterable[str]; iterating it would key on characters."""
        with pytest.raises(TypeError, match="fields and argv"):
            key_for(cap, fields="ip.src")

    def test_bare_str_argv_is_rejected(self, cap: Path) -> None:
        with pytest.raises(TypeError, match="fields and argv"):
            key_for(cap, argv="tshark -r cap.pcap")

    def test_dfilter_change_flips(self, cap: Path) -> None:
        assert key_for(cap, dfilter="udp") != key_for(cap)

    def test_absent_dfilter_differs_from_empty_dfilter(self, cap: Path) -> None:
        assert key_for(cap, dfilter=None) != key_for(cap, dfilter="")

    def test_tshark_version_change_flips(self, cap: Path) -> None:
        assert key_for(cap, tshark_version="4.6.8") != key_for(cap)


class TestArgvClasses:
    """Every argument class that changes tshark's parse must flip the key."""

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param(("-X", "lua_script:custom.lua"), id="lua-script"),
            pytest.param(("-d", "tcp.port==8888,http"), id="decode-as"),
            pytest.param(("-o", "tcp.desegment_tcp_streams:FALSE"), id="pref-override"),
            pytest.param(("-Y", "http"), id="display-filter-arg"),
            pytest.param(("--disable-protocol", "tls"), id="disable-protocol"),
        ],
    )
    def test_added_argument_flips(self, cap: Path, extra: tuple[str, ...]) -> None:
        assert key_for(cap, argv=(*BASE_ARGV, *extra)) != key_for(cap)

    def test_changed_lua_script_flips(self, cap: Path) -> None:
        one = key_for(cap, argv=(*BASE_ARGV, "-X", "lua_script:a.lua"))
        two = key_for(cap, argv=(*BASE_ARGV, "-X", "lua_script:b.lua"))
        assert one != two

    def test_changed_decode_as_flips(self, cap: Path) -> None:
        one = key_for(cap, argv=(*BASE_ARGV, "-d", "tcp.port==8888,http"))
        two = key_for(cap, argv=(*BASE_ARGV, "-d", "tcp.port==9999,http"))
        assert one != two

    def test_removed_argument_flips(self, cap: Path) -> None:
        assert key_for(cap, argv=BASE_ARGV[:-2]) != key_for(cap)

    def test_reordered_argv_flips(self, cap: Path) -> None:
        """argv order is meaningful to tshark, so it is meaningful to the key."""
        reordered = ("tshark", "-T", "fields", "-r", "cap.pcap", "-e", "ip.src", "-e", "ip.dst")
        assert key_for(cap, argv=reordered) != key_for(cap)

    def test_argument_boundaries_are_unambiguous(self, cap: Path) -> None:
        """Splitting one argument in two must not digest the same."""
        joined = key_for(cap, argv=("tshark", "-rcap.pcap"))
        split = key_for(cap, argv=("tshark", "-r", "cap.pcap"))
        assert joined != split


class TestRecordAndStability:
    def test_record_stores_canonicalized_components(self, cap: Path) -> None:
        stamp = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
        record = make_cache_key(
            pcap=cap,
            fields=["ip.dst", "ip.src", "ip.dst"],
            dfilter="tcp",
            tshark_version="4.6.7",
            argv=BASE_ARGV,
            created_at=stamp,
        )
        assert record.fields == ("ip.dst", "ip.src")
        assert record.argv == BASE_ARGV
        assert record.dfilter == "tcp"
        assert record.tshark_version == "4.6.7"
        assert record.pcap_path == str(cap)
        assert record.pcap_fingerprint == fingerprint_pcap(cap).render()
        assert record.created_at == stamp

    def test_created_at_defaults_to_aware_utc(self, cap: Path) -> None:
        record = make_cache_key(
            pcap=cap,
            fields=["ip.src"],
            dfilter=None,
            tshark_version="4.6.7",
            argv=BASE_ARGV,
        )
        assert record.created_at.tzinfo is timezone.utc

    def test_supplied_fingerprint_skips_the_file_read(
        self, cap: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fingerprint = fingerprint_pcap(cap)

        def build() -> str:
            return make_cache_key(
                pcap=cap,
                fields=["ip.src"],
                dfilter=None,
                tshark_version="4.6.7",
                argv=BASE_ARGV,
                fingerprint=fingerprint,
            ).pcap_fingerprint

        assert count_reads(monkeypatch, build) == 0

    def test_key_is_stable_across_processes(self, cap: Path) -> None:
        """Randomized hashing must not reach the digest."""
        expected = key_for(cap)
        snippet = (
            "import sys;"
            "from remora.workspace.cachekey import make_cache_key;"
            "print(make_cache_key("
            "pcap=sys.argv[1], fields=['ip.dst','ip.src'], dfilter='tcp',"
            f"tshark_version='4.6.7', argv={BASE_ARGV!r}).key)"
        )
        env = {**os.environ, "PYTHONHASHSEED": "random"}
        result = subprocess.run(
            [sys.executable, "-c", snippet, str(cap)],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        assert result.stdout.strip() == expected

    def test_key_digest_is_pinned(self) -> None:
        """Golden digest: an accidental change to the scheme fails loudly here."""
        fingerprint = PcapFingerprint(
            size=1234,
            mtime_ns=1_700_000_000_000_000_000,
            probe_sha256="a" * 64,
        )
        record = make_cache_key(
            pcap="/captures/example.pcap",
            fields=["ip.src", "ip.dst"],
            dfilter="tcp",
            tshark_version="4.6.7",
            argv=BASE_ARGV,
            fingerprint=fingerprint,
        )
        assert record.key == GOLDEN_KEY


class TestPackageSurface:
    def test_public_names_are_exported(self) -> None:
        import remora.workspace as workspace

        for name in (
            "CACHE_KEY_VERSION",
            "FINGERPRINT_VERSION",
            "PROBE_BYTES",
            "PcapFingerprint",
            "fingerprint_pcap",
            "make_cache_key",
        ):
            assert name in workspace.__all__
            assert hasattr(workspace, name)

    def test_module_is_import_pure(self) -> None:
        """The workspace layer never imports duckdb at runtime."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import remora.workspace.cachekey; "
                "sys.exit(1 if 'duckdb' in sys.modules else 0)",
            ],
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr.decode()


class TestStorageRoundTrip:
    def test_record_round_trips_through_the_workspace(self, tmp_path: Path) -> None:
        duckdb = pytest.importorskip("duckdb")
        from remora.workspace.schema import create_schema, read_cache_key, record_cache_key

        pcap = write_pcap(tmp_path / "cap.pcap", bytes(large_payload()))
        record = make_cache_key(
            pcap=pcap,
            fields=["ip.dst", "ip.src"],
            dfilter="tcp",
            tshark_version="4.6.7",
            argv=BASE_ARGV,
            created_at=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        )
        con = duckdb.connect(str(tmp_path / "ws.duckdb"))
        try:
            create_schema(con)
            record_cache_key(con, record)
            assert read_cache_key(con, record.key) == record
        finally:
            con.close()
