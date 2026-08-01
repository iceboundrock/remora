"""Regenerate the golden ``-T fields`` sample (``fields_sample.txt``).

Builds ``sample.pcap`` from hand-crafted bytes (no scapy — pure struct
packing of the pcap global header, per-record headers, and Ethernet/IPv4
frames), then runs the local tshark with exactly the argv produced by
:func:`remora.reader.fields_reader.fields_argv` and writes its stdout.

The three packets exercise the parse rules the reader must honor:

1. **TCP SYN** ``10.0.0.1 -> 10.0.0.2`` — ``tcp.port`` dissects twice
   (srcport 51234, dstport 443), so the column carries two occurrences
   joined by the aggregator byte.
2. **ARP request** — no IP or TCP layer at all, so ``ip.src``,
   ``tcp.port``, and ``dns.qry.name`` are all absent (empty columns).
3. **DNS query** over UDP for ``foo,bar.example`` — the query name
   contains a comma, the classic value that breaks naive CSV-style
   splitting and the reason the reader uses US/RS control bytes. (A
   comma was chosen over a tab because tshark backslash-escapes control
   characters inside string field values, which would test tshark's
   escaping rather than our separator handling.)

Checksums (IPv4 header, TCP, UDP) are computed properly so the capture
is clean even with checksum validation enabled.

Usage (requires the remora package to be installed, e.g. via ``uv sync``)::

    uv run python tests/data/make_fields_sample.py

tshark is located via the ``TSHARK`` environment variable if set, else
``shutil.which("tshark")``, else the Homebrew default path.

Writes ``sample.pcap`` and ``fields_sample.txt`` next to this file — and
only after tshark has succeeded, so a failed run never leaves partial
artifacts behind. Both are checked in; rerun only to regenerate against a
different tshark.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from remora.fields import FieldRef
from remora.reader.fields_reader import fields_argv

HERE = Path(__file__).resolve().parent


def find_tshark() -> str:
    """Resolve tshark: $TSHARK, then PATH, then the Homebrew default."""
    candidate = os.environ.get("TSHARK") or shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    if not Path(candidate).is_file():
        raise SystemExit(
            f"error: tshark not found at {candidate!r}; install tshark "
            "or point the TSHARK environment variable at the binary"
        )
    return candidate


def checksum(data: bytes) -> int:
    """RFC 1071 ones-complement sum over 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    words: tuple[int, ...] = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0,  # DSCP/ECN
        20 + len(payload),  # total length
        0x1234,  # identification
        0x4000,  # flags: DF
        64,  # TTL
        proto,
        0,  # checksum placeholder
        src,
        dst,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def l4_checksum(src: bytes, dst: bytes, proto: int, segment: bytes) -> int:
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment) or 0xFFFF


def tcp_syn(src_ip: bytes, dst_ip: bytes, sport: int, dport: int) -> bytes:
    segment = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        0,  # seq
        0,  # ack
        5 << 4,  # data offset 5 words
        0x02,  # SYN
        65535,  # window
        0,  # checksum placeholder
        0,  # urgent pointer
    )
    csum = l4_checksum(src_ip, dst_ip, 6, segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = l4_checksum(src_ip, dst_ip, 17, header + payload)
    return header[:6] + struct.pack("!H", csum) + payload


def dns_query(qname: str) -> bytes:
    question = b"".join(
        struct.pack("!B", len(label)) + label.encode("ascii") for label in qname.split(".")
    )
    question += b"\x00" + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question


def arp_request(sha: bytes, spa: bytes, tpa: bytes) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sha + spa + b"\x00" * 6 + tpa


def build_pcap() -> bytes:
    mac_a = bytes.fromhex("aabbccddeeff")
    mac_b = bytes.fromhex("112233445566")
    ip_1 = bytes([10, 0, 0, 1])
    ip_2 = bytes([10, 0, 0, 2])
    ip_3 = bytes([10, 0, 0, 3])
    ip_53 = bytes([10, 0, 0, 53])

    frames = [
        # 1: TCP SYN — tcp.port gets two occurrences (51234, 443).
        ethernet(mac_b, mac_a, 0x0800, ipv4(ip_1, ip_2, 6, tcp_syn(ip_1, ip_2, 51234, 443))),
        # 2: ARP request — ip.src / tcp.port / dns.qry.name all absent.
        ethernet(b"\xff" * 6, mac_a, 0x0806, arp_request(mac_a, ip_1, ip_2)),
        # 3: DNS query whose qname contains a comma.
        ethernet(
            mac_b,
            mac_a,
            0x0800,
            ipv4(ip_3, ip_53, 17, udp(ip_3, ip_53, 40000, 53, dns_query("foo,bar.example"))),
        ),
    ]

    # pcap global header: magic, v2.4, tz 0, sigfigs 0, snaplen, linktype 1 (Ethernet)
    out = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("!IIII", 1_700_000_000 + i, 0, len(frame), len(frame)) + frame
    return out


def main() -> None:
    pcap_bytes = build_pcap()

    projection: list[FieldRef[Any]] = [
        FieldRef[int]("frame.number", "FT_FRAMENUM", False),
        FieldRef[str]("ip.src", "FT_IPv4", False),
        FieldRef[int]("tcp.port", "FT_UINT16", True),
        FieldRef[str]("dns.qry.name", "FT_STRING", False),
    ]

    # Run tshark against a temporary pcap; write both checked-in artifacts
    # only after it succeeds, so a failure leaves no partial artifacts.
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_pcap = Path(tmpdir) / "sample.pcap"
        tmp_pcap.write_bytes(pcap_bytes)
        argv = [find_tshark(), "-r", str(tmp_pcap), *fields_argv(projection)]
        result = subprocess.run(argv, capture_output=True, text=True, check=True)

    pcap_path = HERE / "sample.pcap"
    pcap_path.write_bytes(pcap_bytes)
    (HERE / "fields_sample.txt").write_text(result.stdout)
    # NB: count "\n" rather than splitlines() — str.splitlines() also splits
    # on \x1e, the very aggregator byte this output embeds.
    print(f"wrote {pcap_path} and fields_sample.txt ({result.stdout.count(chr(10))} rows)")


if __name__ == "__main__":
    main()
