"""Regenerate the checked-in integration-test pcap fixtures (issue #20).

Pure struct packing — no capture libraries, fixed timestamps, no randomness —
so regeneration is byte-for-byte deterministic (pinned by
tests/test_fixture_repro.py).

tcp_mixed.pcap (5 packets) — multi-value and absent-field semantics:

1. TCP SYN      10.0.0.1:51234 -> 10.0.0.2:443   tcp.port = (51234, 443)
2. TCP SYN-ACK  10.0.0.2:443   -> 10.0.0.1:51234
3. TCP SYN      10.0.0.3:52000 -> 10.0.0.2:8080  second flow
4. UDP/DNS      10.0.0.1:53534 -> 10.0.0.9:53    "mixed.example" A; tcp.* absent
5. ARP request  who-has 10.0.0.2 tell 10.0.0.1   ip.* and tcp.* absent

dns_multi.pcap (3 packets) — multi-occurrence dns.qry.name:

1. UDP/DNS  10.0.1.1:50001 -> 10.0.1.53:53  2 questions: "alpha.example" A,
   "beta.example" AAAA -> dns.qry.name occurs twice
2. UDP/DNS  10.0.1.2:50002 -> 10.0.1.53:53  1 question: "gamma.example" A
3. TCP SYN  10.0.1.1:40000 -> 10.0.1.53:80  dns.* and udp.* absent

Regenerate with::

    uv run python tests/fixtures/make_fixtures.py

``build_bulk_tcp(n)`` (issue #38) is the odd one out: it builds a large
synthetic capture for the workspace break-even benchmark, is never written to
this directory, and ``main()`` does not call it.
"""

from __future__ import annotations

import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
MAC_C = bytes.fromhex("020000000003")
BROADCAST = bytes.fromhex("ffffffffffff")


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


def ether(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def arp_request(sender_mac: bytes, sender_ip: bytes, target_ip: bytes) -> bytes:
    # HW type 1 (Ethernet), proto 0x0800 (IPv4), hlen 6, plen 4, opcode 1.
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + sender_ip + b"\x00" * 6 + target_ip
    )


def pcap_record(ts_sec: int, ts_usec: int, frame: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame


#: Classic pcap global header: magic, v2.4, tz 0, sigfigs 0, snaplen,
#: LINKTYPE_ETHERNET. Every capture this module builds starts with these bytes,
#: so it is packed once — the committed fixtures are pinned byte-for-byte by
#: tests/test_fixture_repro.py, and a second copy is a second thing to get wrong.
PCAP_GLOBAL_HEADER: bytes = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def pcap_file(frames: list[bytes], base_ts: int) -> bytes:
    records = b"".join(pcap_record(base_ts + i, i * 1000, frame) for i, frame in enumerate(frames))
    return PCAP_GLOBAL_HEADER + records


def build_tcp_mixed() -> bytes:
    ip_a = bytes([10, 0, 0, 1])
    ip_b = bytes([10, 0, 0, 2])
    ip_c = bytes([10, 0, 0, 3])
    ip_dns = bytes([10, 0, 0, 9])

    syn = ether(
        MAC_B, MAC_A, 0x0800, ipv4(ip_a, ip_b, 6, tcp(ip_a, ip_b, 51234, 443, 1000, 0, 0x02))
    )
    syn_ack = ether(
        MAC_A, MAC_B, 0x0800, ipv4(ip_b, ip_a, 6, tcp(ip_b, ip_a, 443, 51234, 5000, 1001, 0x12))
    )
    other_flow = ether(
        MAC_B, MAC_C, 0x0800, ipv4(ip_c, ip_b, 6, tcp(ip_c, ip_b, 52000, 8080, 2000, 0, 0x02))
    )
    dns = ether(
        MAC_B,
        MAC_A,
        0x0800,
        ipv4(
            ip_a,
            ip_dns,
            17,
            udp(ip_a, ip_dns, 53534, 53, dns_query(0x1001, [("mixed.example", 1)])),
        ),
    )
    arp = ether(BROADCAST, MAC_A, 0x0806, arp_request(MAC_A, ip_a, ip_b))
    return pcap_file([syn, syn_ack, other_flow, dns, arp], base_ts=1700000100)


def build_dns_multi() -> bytes:
    ip_a = bytes([10, 0, 1, 1])
    ip_b = bytes([10, 0, 1, 2])
    ip_srv = bytes([10, 0, 1, 53])

    two_questions = ether(
        MAC_B,
        MAC_A,
        0x0800,
        ipv4(
            ip_a,
            ip_srv,
            17,
            udp(
                ip_a,
                ip_srv,
                50001,
                53,
                dns_query(0x2001, [("alpha.example", 1), ("beta.example", 28)]),
            ),
        ),
    )
    one_question = ether(
        MAC_B,
        MAC_A,
        0x0800,
        ipv4(
            ip_b,
            ip_srv,
            17,
            udp(ip_b, ip_srv, 50002, 53, dns_query(0x2002, [("gamma.example", 1)])),
        ),
    )
    plain_tcp = ether(
        MAC_B, MAC_A, 0x0800, ipv4(ip_a, ip_srv, 6, tcp(ip_a, ip_srv, 40000, 80, 3000, 0, 0x02))
    )
    return pcap_file([two_questions, one_question, plain_tcp], base_ts=1700000200)


# Destination ports and source hosts build_bulk_tcp cycles through, in order.
# Ten hosts and four ports, so a host selects a tenth of the capture, a port a
# quarter, and a (host, port) conjunction a twentieth — known fractions the
# benchmark asserts against rather than trusting.
BULK_DEST_PORTS = (443, 80, 8080, 9000)
BULK_SRC_LAST_OCTETS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)


def build_bulk_tcp(packet_count: int, base_ts: int = 1700001000) -> bytes:
    """A large synthetic TCP-over-IPv4 capture for the workspace benchmark.

    Deliberately NOT one of the committed fixtures: the break-even benchmark
    (tests/integration/workspace/test_benchmark.py) builds ~20k packets into
    tmp_path, which has no business in the repository. It lives here so the
    packing helpers above are written once, and it touches neither committed
    builder (tests/test_fixture_repro.py pins their bytes).

    Packet ``i`` is a TCP SYN ``10.0.0.<BULK_SRC_LAST_OCTETS[i % 10]>:<40000 +
    i % 1000>`` -> ``10.0.0.200:<BULK_DEST_PORTS[i % 4]>``. Timestamps advance
    a millisecond per packet (the microsecond field must stay below 1e6, which
    is why this does not go through ``pcap_file``).
    """
    chunks = [PCAP_GLOBAL_HEADER]
    dst_ip = bytes([10, 0, 0, 200])
    for index in range(packet_count):
        src_ip = bytes([10, 0, 0, BULK_SRC_LAST_OCTETS[index % len(BULK_SRC_LAST_OCTETS)]])
        sport = 40000 + index % 1000
        dport = BULK_DEST_PORTS[index % len(BULK_DEST_PORTS)]
        frame = ether(
            MAC_B,
            MAC_A,
            0x0800,
            ipv4(src_ip, dst_ip, 6, tcp(src_ip, dst_ip, sport, dport, 1000 + index, 0, 0x02)),
        )
        chunks.append(pcap_record(base_ts + index // 1000, (index % 1000) * 1000, frame))
    return b"".join(chunks)


def main() -> None:
    for name, build in [("tcp_mixed.pcap", build_tcp_mixed), ("dns_multi.pcap", build_dns_multi)]:
        path = FIXTURES_DIR / name
        data = build()
        path.write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
