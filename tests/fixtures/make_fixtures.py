r"""Regenerate the checked-in integration-test pcap fixtures (issue #20).

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

ctrl_comments.pcapng (7 packets) — control characters in a string value
(issue #74). pcapng rather than pcap because a frame *comment* is the one
place a capture can carry arbitrary bytes verbatim: every string field a
dissector builds (``dns.qry.name`` included) is already ``format_text``-ed
by the dissector, so it can never hold a raw control byte. Each frame is the
same TCP SYN; only ``frame.comment`` differs:

1. ``tab<0x09>here``       — escaped by ``-T fields`` as ``\t``
2. ``vt<0x0b>here``        — escaped as ``\v``; 0x0b is also the reader's
   column separator, so this frame proves the separator cannot be forged
3. ``back<0x5c>slash``     — escaped as ``\\`` (the doubling that makes the
   escaping invertible)
4. ``us<0x1f>here``        — passed through RAW; 0x1f was the reader's column
   separator before #74 and used to split the column and abort the parse
5. ``C:<0x5c>temp``        — the load-bearing collision: a literal backslash
   immediately followed by ``t``. A build that doubles backslashes prints
   ``C:\\temp`` and the value survives the round trip; one that does not
   prints ``C:\temp``, which is byte-identical to what it prints for a value
   holding a real TAB — so unescaping there would rewrite this into
   ``C:<0x09>emp``. This is the frame that proves the version gate is
   necessary rather than merely cautious.
6. (no comment)            — ``frame.comment`` absent
7. ``rs<0x1e>here``        — passed through RAW like 0x1f, but 0x1e is the
   reader's *occurrence* separator, so this frame forks into two occurrences
   (``("rs", "here")``) where ``-T ek`` reports the one true value. That is
   the residual #74 accepts rather than fixes: tshark returns
   ``escape(occ1 + SEP + occ2)``, a function of the joined string alone, so
   no single-byte aggregator can recover the join positions — an escaped
   byte never arrives raw to split on, and an unescaped one is forgeable by
   the value. This frame witnesses that end to end.

ntp_times.pcap (2 packets) — FT_ABSOLUTE_TIME renderings (issue #117). NTP
carries absolute-time fields with the UTC display base, which renders the zero
time as ``NULL`` in ``-T fields`` and as the epoch in ``-T ek``. The capture
starts on the 5th of a month so a pre-4.6 ``-T fields`` rendering carries a
space-padded day (``"Nov  5, 2023 ..."``):

1. NTP client request  10.0.3.1:123 -> 10.0.3.123:123  only ``ntp.xmt`` set;
   ``ntp.reftime``/``ntp.org``/``ntp.rec`` are the zero time
2. NTP server reply    10.0.3.123:123 -> 10.0.3.1:123  all four set, with
   fractional seconds

guid_eui64.pcap (5 packets) — FT_GUID and FT_EUI64 values (issue #69):

1. DHCP DISCOVER  option 97 client UUID, wire bytes 00 11 22 .. ff, which the
   dissector reads little-endian: ``dhcp.client_id.uuid`` prints
   ``33221100-5544-7766-8899-aabbccddeeff``
2. SIP OPTIONS    ``Session-ID: AB30317F1a78...;remote=47755a9d...``:
   ``sip.Session-ID.local_uuid`` / ``.remote_uuid`` (the mixed case on the wire
   prints lower-case)
3. DNS response   one EUI64 record: ``dns.eui64`` = ``02:11:22:33:44:55:66:77``
4. ICMPv6 NS      a 16-byte Source Link-layer Address option holding an EUI-64
   (``icmpv6.opt.src_linkaddr_eui64`` = ``fe:00:00:00:00:00:a1:b2``) and an
   Address Registration Option (``icmpv6.opt.aro.eui64`` =
   ``02:11:22:33:44:55:66:77``)
5. DHCP DISCOVER  client UUID printing ``00000034-0000-0000-0000-000000000000``:
   below frame 1's by text order, above it by tshark 4.2.2's host-endian
   struct order, so an ordered GUID filter that tshark evaluated would split
   the two builds

oid.pcap (10 packets) — FT_OID renderings (issue #149). Every frame is an SNMP
message ``10.0.5.1 -> 10.0.5.2``; ``snmp.name`` is the varbind name, so it
occurs once per varbind. Frames 4 to 7 carry encodings no conforming agent
sends, to pin what tshark prints for them:

1. GetResponse    ``snmp.name`` = ``1.3.6.1.2.1.1.2.0`` (sysObjectID.0, whose
   ``snmp.value.oid`` = ``1.3.6.1.4.1.8072.3.2.10``) and ``1.3.6.1.2.1.1.1.0``
2. SNMPv1 Trap    ``snmp.enterprise`` = ``1.3.6.1.4.1.9``
3. GetResponse    ``snmp.name`` = ``1.3.6.1.2.1.1.10`` and ``1.3.6.1.2.1.1.9``:
   arc order and text order disagree on which is smaller
4. GetResponse    ``snmp.name`` = ``1.3``, ``2.999.1`` (a first arc of 2 takes
   a second arc above 39) and an arc of 2**32, which tshark cannot hold and
   prints as the empty string, then stops dissecting the packet
5. GetResponse    ``snmp.name`` encoded ``2b 06 81``, whose last arc never
   ends: prints ``1.3.6``
6. GetResponse    ``snmp.name`` encoded ``2b 80 01``, a non-minimal arc:
   prints ``1.3.1``
7. GetResponse    ``snmp.name`` encoded with no content octets: prints ``0``
8. GetResponse    ``snmp.name`` = ``1.3.6.16383`` (``2b 06 ff 7f``)
9. GetResponse    ``snmp.name`` = ``1.3.6.16384`` (``2b 06 81 80 00``): the
   arc one above frame 8's, whose encoding tshark sorts below it
10. GetResponse   ``snmp.name`` = ``1.3.6.1.2.1.0`` and ``1.3.6.1.2.1.3``: one
   occurrence on each side of the subtree ``1.3.6.1.2.1.1``, none inside it

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


#: Frame comments carried by ctrl_comments.pcapng, in frame order; ``None``
#: means the frame carries no comment option at all. See the module docstring
#: for what each one exercises.
CTRL_COMMENTS: tuple[str | None, ...] = (
    "tab\there",
    "vt\vhere",
    "back\\slash",
    "us\x1fhere",
    "C:\\temp",
    None,
    # Appended after the no-comment frame on purpose: frames 1-6 keep the
    # numbers the integration suite already pins, so adding this one moves
    # no existing expectation. It carries the OCC_SEP byte itself, which
    # tshark escapes on no version, so the -T fields path forks it into two
    # occurrences where ek reports one value. That fork is the residual #74
    # accepts (no single-byte aggregator can survive it) and this frame is
    # what witnesses it end to end.
    "rs\x1ehere",
)


def pcapng_option(code: int, value: bytes) -> bytes:
    """One pcapng option, padded to the 4-byte boundary the format requires."""
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


#: opt_endofopt — terminates an option list.
PCAPNG_OPT_END: bytes = struct.pack("<HH", 0, 0)


def pcapng_block(block_type: int, body: bytes) -> bytes:
    """Wrap an already 4-byte-aligned *body* in a pcapng block frame."""
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def pcapng_file(frames: list[tuple[bytes, str | None]], base_ts: int) -> bytes:
    """A single-section, single-interface pcapng of ``(frame, comment)`` pairs.

    Little-endian, LINKTYPE_ETHERNET, section length -1 (unspecified) and the
    default ``if_tsresol`` of 6, so timestamps are microseconds since the
    epoch. A ``None`` comment emits no option list at all, which is how the
    fixture gets a frame whose ``frame.comment`` is absent rather than empty.
    """
    shb = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + PCAPNG_OPT_END)
    idb = pcapng_block(0x00000001, struct.pack("<HHI", 1, 0, 65535) + PCAPNG_OPT_END)
    out = [shb, idb]
    for index, (frame, comment) in enumerate(frames):
        stamp = (base_ts + index) * 1_000_000
        body = (
            struct.pack("<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame))
            + frame
        )
        body += b"\x00" * (-len(frame) % 4)
        if comment is not None:
            body += pcapng_option(1, comment.encode("utf-8")) + PCAPNG_OPT_END
        out.append(pcapng_block(0x00000006, body))
    return b"".join(out)


def build_ctrl_comments() -> bytes:
    """Six identical TCP SYNs distinguished only by their frame comments."""
    ip_a = bytes([10, 0, 2, 1])
    ip_b = bytes([10, 0, 2, 2])
    frames = [
        (
            ether(
                MAC_B,
                MAC_A,
                0x0800,
                ipv4(ip_a, ip_b, 6, tcp(ip_a, ip_b, 40000 + index, 443, 1000 + index, 0, 0x02)),
            ),
            comment,
        )
        for index, comment in enumerate(CTRL_COMMENTS)
    ]
    return pcapng_file(frames, base_ts=1700000300)


#: 1900-01-01 (the NTP era origin) to 1970-01-01, in seconds.
NTP_UNIX_OFFSET = 2_208_988_800

#: The Unix instant ntp_times.pcap starts at: 2023-11-05T00:00:05Z.
NTP_BASE_TS = 1699142405


def ntp_timestamp(unix_seconds: int | None, fraction: int = 0) -> bytes:
    """A 64-bit NTP timestamp; ``None`` is the all-zero "not set" value."""
    if unix_seconds is None:
        return b"\x00" * 8
    return struct.pack("!II", unix_seconds + NTP_UNIX_OFFSET, fraction)


def ntp_packet(mode: int, stratum: int, stamps: tuple[bytes, bytes, bytes, bytes]) -> bytes:
    """An NTPv4 header: LI 0, *mode*, then reference/origin/receive/transmit stamps."""
    header = struct.pack(
        "!BBbbII4s",
        (4 << 3) | mode,  # LI 0, VN 4
        stratum,
        6,  # poll: 64 s
        -20,  # precision: ~1 us
        0,  # root delay
        0,  # root dispersion
        b"GPS\x00" if stratum == 1 else b"\x00" * 4,
    )
    return header + b"".join(stamps)


def build_ntp_times() -> bytes:
    """An NTP request/reply pair whose absolute times exercise every rendering."""
    client = bytes([10, 0, 3, 1])
    server = bytes([10, 0, 3, 123])
    request = ntp_packet(
        3,
        0,
        (
            ntp_timestamp(None),
            ntp_timestamp(None),
            ntp_timestamp(None),
            ntp_timestamp(NTP_BASE_TS, 0x80000000),  # .5
        ),
    )
    reply = ntp_packet(
        4,
        1,
        (
            ntp_timestamp(NTP_BASE_TS - 60),
            ntp_timestamp(NTP_BASE_TS, 0x80000000),  # echoes the request's xmt
            ntp_timestamp(NTP_BASE_TS + 1, 0x40000000),  # .25
            ntp_timestamp(NTP_BASE_TS + 1, 0xC0000000),  # .75
        ),
    )
    to_server = udp(client, server, 123, 123, request)
    to_client = udp(server, client, 123, 123, reply)
    frames = [
        ether(MAC_B, MAC_A, 0x0800, ipv4(client, server, 17, to_server)),
        ether(MAC_A, MAC_B, 0x0800, ipv4(server, client, 17, to_client)),
    ]
    return pcap_file(frames, base_ts=NTP_BASE_TS)


#: Option 97 (client machine identifier) bodies of guid_eui64.pcap's two DHCP
#: frames: type 0, then 16 bytes the dissector reads as a little-endian GUID.
DHCP_UUID_WIRE: tuple[bytes, bytes] = (
    bytes.fromhex("00112233445566778899aabbccddeeff"),
    bytes.fromhex("34000000000000000000000000000000"),
)
#: The two EUI-64s guid_eui64.pcap carries, in wire (= printed) order.
EUI64_A = bytes.fromhex("0211223344556677")
EUI64_B = bytes.fromhex("fe0000000000a1b2")


def dhcp_discover(xid: int, client_mac: bytes, client_uuid: bytes) -> bytes:
    """A BOOTP request with options 53 (DISCOVER) and 97 (client UUID)."""
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # op: BOOTREQUEST
        1,  # htype: Ethernet
        6,  # hlen
        0,  # hops
        xid,
        0,  # secs
        0x8000,  # flags: broadcast
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        b"\x00" * 4,
        client_mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = bytes([99, 130, 83, 99])  # magic cookie
    options += bytes([53, 1, 1])  # DHCP message type: DISCOVER
    options += bytes([97, 17, 0]) + client_uuid  # client machine identifier, UUID
    return bootp + options + bytes([255])


SIP_OPTIONS: bytes = (
    b"OPTIONS sip:bob@example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.0.4.1:5060;branch=z9hG4bK1\r\n"
    b"From: <sip:alice@example.com>;tag=1\r\n"
    b"To: <sip:bob@example.com>\r\n"
    b"Call-ID: 1@example\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Session-ID: AB30317F1a784dc48ff824d0d3715d86;remote=47755a9de7794ba387653f2099600ef2\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def dns_eui64_response(txid: int, name: str, eui64: bytes) -> bytes:
    """A DNS response answering *name* with one EUI64 (type 109) record."""
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = dns_qname(name) + struct.pack("!HH", 109, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 109, 1, 300, 8) + eui64  # name: pointer to qname
    return header + question + answer


def ipv6(src: bytes, dst: bytes, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 6 << 28, len(payload), next_header, 255) + src + dst + payload


def icmpv6_ns_eui64(src: bytes, dst: bytes, target: bytes) -> bytes:
    """A Neighbor Solicitation whose SLLA and ARO options each carry an EUI-64."""
    body = struct.pack("!BBHI", 135, 0, 0, 0) + target
    # Source Link-layer Address, 2 units (16 bytes): an EUI-64 and 6 bytes of padding.
    body += bytes([1, 2]) + EUI64_B + b"\x00" * 6
    # Address Registration Option (RFC 6775): status, 3 reserved, lifetime, EUI-64.
    body += bytes([33, 2, 0, 0, 0, 0]) + struct.pack("!H", 60) + EUI64_A
    pseudo = src + dst + struct.pack("!I", len(body)) + b"\x00" * 3 + bytes([58])
    return body[:2] + struct.pack("!H", checksum(pseudo + body)) + body[4:]


def build_guid_eui64() -> bytes:
    """Every FT_GUID and FT_EUI64 rendering the #69 integration suite reads."""
    unspecified = bytes(4)
    limited = b"\xff" * 4
    client = bytes([10, 0, 4, 1])
    server = bytes([10, 0, 4, 2])
    v6_src = bytes.fromhex("fe80000000000000fc000000000000a1")
    v6_dst = bytes.fromhex("ff0200000000000000000001ff0000a2")
    v6_target = bytes.fromhex("20010db80000000000000000000000a2")

    def discover(xid: int, client_uuid: bytes) -> bytes:
        datagram = udp(unspecified, limited, 68, 67, dhcp_discover(xid, MAC_A, client_uuid))
        return ether(BROADCAST, MAC_A, 0x0800, ipv4(unspecified, limited, 17, datagram))

    sip = udp(client, server, 5060, 5060, SIP_OPTIONS)
    dns = udp(server, client, 53, 53000, dns_eui64_response(0x3001, "eui.example", EUI64_A))
    frames = [
        discover(0x3903F326, DHCP_UUID_WIRE[0]),
        ether(MAC_B, MAC_A, 0x0800, ipv4(client, server, 17, sip)),
        ether(MAC_A, MAC_B, 0x0800, ipv4(server, client, 17, dns)),
        ether(
            bytes.fromhex("3333ff0000a2"),
            MAC_A,
            0x86DD,
            ipv6(v6_src, v6_dst, 58, icmpv6_ns_eui64(v6_src, v6_dst, v6_target)),
        ),
        discover(0x3903F327, DHCP_UUID_WIRE[1]),
    ]
    return pcap_file(frames, base_ts=1700000400)


def ber(tag: int, content: bytes) -> bytes:
    """One BER TLV, with a definite length in short or long form."""
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        octets = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + length + content


def ber_int(value: int) -> bytes:
    """A non-negative BER INTEGER."""
    return ber(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def oid_content(arcs: tuple[int, ...]) -> bytes:
    """The minimal BER encoding of an OID's arcs (X.690 8.19), content octets only."""

    def base128(value: int) -> bytes:
        out = [value & 0x7F]
        value >>= 7
        while value:
            out.append(0x80 | (value & 0x7F))
            value >>= 7
        return bytes(reversed(out))

    first, second, *rest = arcs
    return base128(first * 40 + second) + b"".join(base128(arc) for arc in rest)


BER_NULL = ber(0x05, b"")
SNMP_A = bytes([10, 0, 5, 1])
SNMP_B = bytes([10, 0, 5, 2])


def snmp_response(request_id: int, varbinds: list[tuple[bytes, bytes]]) -> bytes:
    """An SNMPv2c GetResponse; each varbind is (OID content octets, value TLV)."""
    bindings = b"".join(ber(0x30, ber(0x06, name) + value) for name, value in varbinds)
    pdu = ber(0xA2, ber_int(request_id) + ber_int(0) + ber_int(0) + ber(0x30, bindings))
    return ber(0x30, ber_int(1) + ber(0x04, b"public") + pdu)


def snmp_v1_trap(enterprise: tuple[int, ...]) -> bytes:
    """An SNMPv1 enterpriseSpecific Trap-PDU with no varbinds."""
    pdu = ber(
        0xA4,
        ber(0x06, oid_content(enterprise))
        + ber(0x40, SNMP_A)  # agent-addr
        + ber_int(6)  # generic-trap: enterpriseSpecific
        + ber_int(1)  # specific-trap
        + ber(0x43, b"\x01")  # time-stamp
        + ber(0x30, b""),
    )
    return ber(0x30, ber_int(0) + ber(0x04, b"public") + pdu)


def build_oid() -> bytes:
    """Every FT_OID rendering the #149 integration suite reads."""

    def frame(message: bytes, sport: int, dport: int) -> bytes:
        datagram = udp(SNMP_A, SNMP_B, sport, dport, message)
        return ether(MAC_B, MAC_A, 0x0800, ipv4(SNMP_A, SNMP_B, 17, datagram))

    def response(request_id: int, *names: bytes) -> bytes:
        return frame(snmp_response(request_id, [(name, BER_NULL) for name in names]), 161, 50000)

    sys_object_id = ber(0x06, oid_content((1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)))
    frames = [
        frame(
            snmp_response(
                1,
                [
                    (oid_content((1, 3, 6, 1, 2, 1, 1, 2, 0)), sys_object_id),
                    (oid_content((1, 3, 6, 1, 2, 1, 1, 1, 0)), ber(0x04, b"Linux")),
                ],
            ),
            161,
            50000,
        ),
        frame(snmp_v1_trap((1, 3, 6, 1, 4, 1, 9)), 50001, 162),
        response(3, oid_content((1, 3, 6, 1, 2, 1, 1, 10)), oid_content((1, 3, 6, 1, 2, 1, 1, 9))),
        response(
            4,
            oid_content((1, 3)),
            oid_content((2, 999, 1)),
            oid_content((1, 3, 6, 1, 4, 1, 2**32)),
        ),
        response(5, b"\x2b\x06\x81"),
        response(6, b"\x2b\x80\x01"),
        response(7, b""),
        response(8, oid_content((1, 3, 6, 16383))),
        response(9, oid_content((1, 3, 6, 16384))),
        response(10, oid_content((1, 3, 6, 1, 2, 1, 0)), oid_content((1, 3, 6, 1, 2, 1, 3))),
    ]
    return pcap_file(frames, base_ts=1700000500)


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
    for name, build in [
        ("tcp_mixed.pcap", build_tcp_mixed),
        ("dns_multi.pcap", build_dns_multi),
        ("ctrl_comments.pcapng", build_ctrl_comments),
        ("ntp_times.pcap", build_ntp_times),
        ("guid_eui64.pcap", build_guid_eui64),
        ("oid.pcap", build_oid),
    ]:
        path = FIXTURES_DIR / name
        data = build()
        path.write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
