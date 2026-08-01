"""Regenerate the checked-in ek golden sample (ek_sample.pcap + ek_sample.ndjson).

Builds a minimal pcap by hand (pure struct packing, no capture libraries), then
runs a real tshark with ``-T ek`` over it and checks the output in verbatim.
The pcap is deliberately tiny but exercises the shapes EkReader must handle:

- packet 1: Ethernet/IPv4/TCP SYN        (tcp fields present, dns absent)
- packet 2: Ethernet/IPv4/TCP SYN-ACK    (reverse direction)
- packet 3: Ethernet/IPv4/UDP/DNS query  (two questions -> multi-occurrence
  dns.qry.name; tcp fields absent)

Multi-occurrence fields (e.g. ``ip.addr``, ``tcp.port``, and the doubled
``dns.qry.name``) let the golden test pin down tshark's scalar-vs-array ek
encoding. Regenerate with::

    python tests/data/make_ek_sample.py

Requires tshark on PATH (or at /opt/homebrew/bin/tshark). The .ndjson output
is version-dependent cosmetically (layer contents), but the key/array shapes
the tests assert are stable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
PCAP_PATH = DATA_DIR / "ek_sample.pcap"
NDJSON_PATH = DATA_DIR / "ek_sample.ndjson"

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])


def checksum(data: bytes) -> int:
    """RFC 1071 ones'-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0,  # DSCP/ECN
        20 + len(payload),
        0x1234,  # identification
        0x4000,  # flags: don't fragment
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
    return checksum(pseudo + segment)


def tcp(
    src_ip: bytes, dst_ip: bytes, sport: int, dport: int, seq: int, ack: int, flags: int
) -> bytes:
    segment = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        0x50,  # data offset 5 words
        flags,
        64240,  # window
        0,  # checksum placeholder
        0,  # urgent pointer
    )
    csum = l4_checksum(src_ip, dst_ip, 6, segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    datagram = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = l4_checksum(src_ip, dst_ip, 17, datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", csum) + datagram[8:]


def dns_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode("ascii")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(txid: int, names_and_types: list[tuple[str, int]]) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, len(names_and_types), 0, 0, 0)
    questions = b"".join(
        dns_qname(name) + struct.pack("!HH", qtype, 1)  # class IN
        for name, qtype in names_and_types
    )
    return header + questions


def ether(dst: bytes, src: bytes, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", 0x0800) + payload


def pcap_record(ts_sec: int, ts_usec: int, frame: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


def build_pcap() -> bytes:
    # Classic pcap global header: magic, v2.4, tz 0, sigfigs 0, snaplen, LINKTYPE_ETHERNET.
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    syn = ether(
        SERVER_MAC,
        CLIENT_MAC,
        ipv4(CLIENT_IP, SERVER_IP, 6, tcp(CLIENT_IP, SERVER_IP, 51234, 443, 1000, 0, 0x02)),
    )
    syn_ack = ether(
        CLIENT_MAC,
        SERVER_MAC,
        ipv4(SERVER_IP, CLIENT_IP, 6, tcp(SERVER_IP, CLIENT_IP, 443, 51234, 5000, 1001, 0x12)),
    )
    # Two questions in one DNS message -> dns.qry.name occurs twice (ek array).
    dns = ether(
        SERVER_MAC,
        CLIENT_MAC,
        ipv4(
            CLIENT_IP,
            SERVER_IP,
            17,
            udp(
                CLIENT_IP,
                SERVER_IP,
                53534,
                53,
                dns_query(0xBEEF, [("example.com", 1), ("www.example.com", 28)]),
            ),
        ),
    )

    records = b"".join(
        pcap_record(1700000000 + i, i * 1000, frame) for i, frame in enumerate([syn, syn_ack, dns])
    )
    return header + records


def find_tshark() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    fallback = "/opt/homebrew/bin/tshark"
    if Path(fallback).exists():
        return fallback
    sys.exit("tshark not found; install Wireshark to regenerate the sample")


def main() -> None:
    PCAP_PATH.write_bytes(build_pcap())
    result = subprocess.run(
        [find_tshark(), "-r", str(PCAP_PATH), "-T", "ek"],
        check=True,
        capture_output=True,
        text=True,
    )
    NDJSON_PATH.write_text(result.stdout)
    lines = result.stdout.splitlines()
    print(f"wrote {PCAP_PATH.name} and {NDJSON_PATH.name} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
