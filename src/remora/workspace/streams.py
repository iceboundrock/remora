"""Sessionization: roll ``pkts`` up into the ``main.streams`` table (#33).

This is the headline capability a display filter cannot express. tshark
already assigns every TCP and UDP packet a per-capture stream index
(``tcp.stream`` / ``udp.stream``); what a filter cannot do is *aggregate* over
one — count a conversation's packets, total its bytes, measure how long it
ran, or join a packet back to the conversation it belongs to. One set-based
``INSERT ... SELECT ... GROUP BY`` over ``pkts`` produces exactly that, so
nothing here loops over rows in Python.

Record shape
------------
One row per ``(protocol, stream_id)`` pair. Both protocols number their
streams from zero, so the stream id alone is *not* a key — ``protocol`` is
half of it, which is also why ``pkts`` joins to ``streams`` on both columns.

==================  =====================================================
Column              Holds
==================  =====================================================
``stream_id``       ``tcp.stream`` / ``udp.stream`` as tshark assigned it.
``protocol``        ``'tcp'`` or ``'udp'`` (:data:`STREAM_PROTOCOLS`).
``src_addr``        Initiator's IPv4 address as an integer.
``src_port``        Initiator's port.
``dst_addr``        Responder's IPv4 address as an integer.
``dst_port``        Responder's port.
``first_frame``     Lowest ``frame_number`` in the stream.
``last_frame``      Highest ``frame_number`` in the stream.
``pkt_count``       Packets in the stream.
``byte_count``      Total ``frame.len`` over those packets.
``first_time``      Earliest ``frame_time`` (naive UTC).
``last_time``       Latest ``frame_time``; the duration is the difference.
==================  =====================================================

Endpoints are read from the stream's **first frame by frame number** — all
four in one aggregate ordered the same way, so they always describe one packet
rather than a mix of directions. That makes ``src``/``dst`` mean initiator and
responder, matching the A/B ordering of tshark's own ``-z conv,tcp``
statistics, and it means a reverse-direction packet later in the stream never
flips them.

Addresses are stored exactly as ``pkts`` stores them — the ``FT_IPv4``
integer of :mod:`remora.workspace.types` — so ``s.src_addr = p.ip_src`` is a
plain integer comparison and no representation is invented here.

Addresses are IPv4-only, and NULL is the signal
-----------------------------------------------
``src_addr``/``dst_addr`` are sourced from ``ip.src``/``ip.dst``, which are
IPv4 header fields, so they are populated only for streams whose first frame
carries an IPv4 header. That is a deliberate scope limit rather than an
oversight, and it is unambiguous, because for a stream-bearing packet the two
cases cannot overlap:

**``src_addr``/``dst_addr`` are NULL ⇔ the stream's first frame carries no
IPv4 header.**

The forward direction is the IPv4 header's own shape — ``ip.src`` and
``ip.dst`` are fixed fields every IPv4 header has, so a frame tshark dissected
as IPv4 always yields both. The reverse direction holds because a frame too
damaged to yield them is also too damaged to be given a stream index: a
truncated IPv4 packet whose transport header is cut off gets no ``tcp.stream``
at all and therefore never reaches a rollup. So a NULL address never means
"IPv4 packet that happened to be missing one"; it means the stream is IPv6 (or
some other non-IPv4 network layer).

The **ports are not affected**. ``tcp.srcport``/``udp.srcport`` and their
``dstport`` counterparts are transport-layer fields, independent of the
network layer, so an IPv6 stream's row carries its real ports alongside its
real stream id, counts and timestamps — the addresses are the only part
missing. Those rows are therefore kept rather than dropped, and a caller
wanting only the fully-addressed streams filters on ``src_addr IS NOT NULL``.

Supporting IPv6 addresses properly needs ``ipv6.src``/``ipv6.dst`` added to
the prerequisites, ``UHUGEINT`` columns (``FT_IPv6``'s storage type) and an
address-family discriminator to tell the two integer spaces apart — a
storage-format change, and a follow-up rather than part of this issue.

What ``byte_count`` counts
--------------------------
``frame.len``: the packet's length on the wire, link-layer header included.
That is deliberately the same definition tshark's conversation statistics use
for their Bytes column, so ``build_streams`` output and ``tshark -q -z
conv,tcp`` agree packet for packet and byte for byte — which
``tests/integration/test_streams_integration.py`` checks against a live
tshark. It is *not* payload bytes, and not ``ip.len`` (which excludes the
Ethernet header).

The prerequisite rule
---------------------
Sessionization reads nine fields out of ``pkts`` (:data:`REQUIRED_FIELDS`),
and :func:`build_streams` requires **all** of them — both protocols' — before
it runs any SQL over ``pkts``. Validating tcp and udp independently and
building whichever protocol's prerequisites happen to be satisfied was the
tempting alternative and is worse: a capture with no udp packets would build
"successfully" while silently producing no udp streams, and the analyst would
discover the omission only on the next capture. So a workspace materialized
with tcp fields alone is refused with
:exc:`~remora.workspace.errors.MissingStreamFieldsError` naming the udp
abbrevs to add, and the fix is to rematerialize with them.

The check reads ``meta.fields``, not ``pkts``' catalog: the field registry is
what records that a column was materialized and how, and its ``multi`` flag is
what tells this module whether a column holds a scalar or a ``LIST``. A
prerequisite materialized multi-value — ``ip.src`` can dissect twice on a
tunnelled packet — is read at occurrence one, the outer header.

Idempotence
-----------
One workspace holds one capture (``pkts`` has no capture column, so the file
*is* the capture identity), which makes a rebuild the whole table's business:
:func:`build_streams` deletes every row and re-inserts, so rerunning it after
a re-materialization replaces the rollups rather than duplicating them, and
drops streams whose packets are gone.

Connections are supplied by the caller — this module never opens one, because
connection and lock ownership belongs to ``Workspace`` (#28), whose
:meth:`~remora.workspace.workspace.Workspace.build_streams` wraps this in
exactly one short transaction. It therefore imports duckdb only for typing and
stays importable without it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from remora.workspace.errors import MissingStreamFieldsError
from remora.workspace.schema import FieldRecord, read_fields

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "REQUIRED_FIELDS",
    "STREAM_PROTOCOLS",
    "StreamsResult",
    "build_streams",
]

STREAM_PROTOCOLS: Final[tuple[str, ...]] = ("tcp", "udp")
"""Transport protocols tshark assigns stream indices to, and this module rolls up."""

#: Abbrevs read for every stream regardless of protocol.
_SHARED_FIELDS: Final[tuple[str, ...]] = ("frame.len", "ip.src", "ip.dst")

#: Per-protocol abbrevs: the stream index and the two directional ports.
_PROTOCOL_FIELDS: Final[dict[str, tuple[str, str, str]]] = {
    protocol: (f"{protocol}.stream", f"{protocol}.srcport", f"{protocol}.dstport")
    for protocol in STREAM_PROTOCOLS
}

REQUIRED_FIELDS: Final[tuple[str, ...]] = tuple(
    sorted({*_SHARED_FIELDS, *(field for fields in _PROTOCOL_FIELDS.values() for field in fields)})
)
"""Every abbrev :func:`build_streams` needs materialized, sorted.

Both protocols' fields are required together — see the module docstring for
why an independent per-protocol rule was rejected.
"""

# One aggregate per stream. Endpoints all use `first(... ORDER BY
# frame_number)` so they describe one packet — the stream's first — instead of
# a mixture of directions; `min`/`max` would take each column independently.
# The protocol is bound rather than interpolated even though it comes from a
# frozen constant, so no value reaches the statement text.
_INSERT_SQL: Final[str] = """
INSERT INTO main.streams (
    stream_id, protocol,
    src_addr, src_port, dst_addr, dst_port,
    first_frame, last_frame, pkt_count, byte_count, first_time, last_time
)
SELECT
    {stream},
    ?,
    first({src_addr} ORDER BY frame_number),
    first({src_port} ORDER BY frame_number),
    first({dst_addr} ORDER BY frame_number),
    first({dst_port} ORDER BY frame_number),
    min(frame_number),
    max(frame_number),
    count(*),
    sum({frame_len}),
    min(frame_time),
    max(frame_time)
FROM main.pkts
WHERE {stream} IS NOT NULL
GROUP BY {stream}
"""


@dataclass(frozen=True)
class StreamsResult:
    """What one :func:`build_streams` call wrote.

    Attributes:
        tcp_streams: Rows written for ``protocol = 'tcp'``.
        udp_streams: Rows written for ``protocol = 'udp'``.
    """

    tcp_streams: int
    udp_streams: int

    @property
    def total(self) -> int:
        """Rows in ``main.streams`` after the rebuild."""
        return self.tcp_streams + self.udp_streams


def _quote_identifier(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


def _value_sql(record: FieldRecord) -> str:
    """SQL reading one packet's value for a materialized field.

    A multi-value field's column is a ``LIST``, and a rollup wants one value
    per packet: occurrence one, which for a tunnelled packet is the outer
    header. DuckDB lists are 1-indexed, and indexing past the end (or into a
    NULL list) yields NULL, so an absent field stays absent.
    """
    column = _quote_identifier(record.column_name)
    return f"{column}[1]" if record.multi else column


def _require_fields(con: DuckDBPyConnection) -> dict[str, FieldRecord]:
    """Return the registry entries sessionization needs, or refuse by name.

    Args:
        con: An open connection to the workspace.

    Returns:
        The :class:`~remora.workspace.schema.FieldRecord` for each of
        :data:`REQUIRED_FIELDS`, keyed by abbrev.

    Raises:
        MissingStreamFieldsError: If any required abbrev is absent from
            ``meta.fields``. Nothing is read from ``pkts`` first, so the
            failure names the fields instead of a missing column.
    """
    registry = {record.abbrev: record for record in read_fields(con)}
    missing = tuple(abbrev for abbrev in REQUIRED_FIELDS if abbrev not in registry)
    if missing:
        raise MissingStreamFieldsError(
            "cannot build streams: this workspace never materialized "
            f"{', '.join(missing)}. Sessionization reads {', '.join(REQUIRED_FIELDS)} "
            "from pkts — both protocols' fields, so that a capture holding only one "
            "of them still builds a complete streams table — so materialize the "
            "capture again with the missing abbrevs in materialize()'s field set. "
            "Nothing has been modified.",
            missing,
        )
    return {abbrev: registry[abbrev] for abbrev in REQUIRED_FIELDS}


def build_streams(con: DuckDBPyConnection) -> StreamsResult:
    """Rebuild ``main.streams`` from the packets in ``main.pkts``.

    One ``DELETE`` plus one ``INSERT ... SELECT ... GROUP BY`` per protocol:
    set-based throughout, and a whole rebuild rather than an update, so
    rerunning it after a re-materialization replaces the rollups without
    duplicating them (one workspace holds one capture; see the module
    docstring).

    One row per ``(protocol, stream_id)`` — the table's ``UNIQUE`` key, since
    tcp and udp each number their streams from zero.

    Addresses are **IPv4-only**, and their absence is unambiguous:
    ``src_addr``/``dst_addr`` are NULL exactly when the stream's first frame
    carries no IPv4 header, i.e. the stream is IPv6. An IPv4 frame always
    yields ``ip.src``/``ip.dst``, and one damaged enough not to is also never
    given a stream index, so a NULL address never means "IPv4 packet missing
    one". The **ports are unaffected** — they are transport-layer fields — so
    such a row still carries its real ports, stream id, counts and timestamps
    and is kept rather than dropped; filter on ``src_addr IS NOT NULL`` to
    select only fully-addressed streams. The module docstring covers what
    IPv6 address support would take.

    Args:
        con: A read-write connection to the workspace, **inside a transaction
            the caller drives** — ``Workspace.write()`` provides exactly that,
            so the empty window between the delete and the inserts is never
            visible to another reader.

    Returns:
        How many rows were written, per protocol.

    Raises:
        MissingStreamFieldsError: If :data:`REQUIRED_FIELDS` are not all in
            ``meta.fields``. Raised before the delete, so a workspace that
            cannot be built keeps whatever it had.
    """
    registry = _require_fields(con)
    con.execute("DELETE FROM main.streams")
    counts: dict[str, int] = {}
    for protocol in STREAM_PROTOCOLS:
        stream, srcport, dstport = _PROTOCOL_FIELDS[protocol]
        sql = _INSERT_SQL.format(
            stream=_value_sql(registry[stream]),
            src_addr=_value_sql(registry["ip.src"]),
            src_port=_value_sql(registry[srcport]),
            dst_addr=_value_sql(registry["ip.dst"]),
            dst_port=_value_sql(registry[dstport]),
            frame_len=_value_sql(registry["frame.len"]),
        )
        row = con.execute(sql, [protocol]).fetchone()
        counts[protocol] = 0 if row is None else int(row[0])
    return StreamsResult(tcp_streams=counts["tcp"], udp_streams=counts["udp"])
