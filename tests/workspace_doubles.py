"""Shared doubles and probes for the workspace materialize suites (#31, #32).

The unit suites never spawn a process: :class:`FakeRunner` stands in for the
``TsharkRunner`` seam and streams canned ``-T fields`` lines. Everything here
is import-pure, so importing it without duckdb installed is safe — the suites
that use it guard with ``pytest.importorskip`` before they *run*.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import TYPE_CHECKING, Any

from remora.fields import FieldRef
from remora.reader.fields_reader import OCC_SEP, UNIT_SEP
from remora.workspace import Workspace

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

IP_SRC: FieldRef[IPv4Address] = FieldRef("ip.src", "FT_IPv4", False)
IP_DST: FieldRef[IPv4Address] = FieldRef("ip.dst", "FT_IPv4", False)
TCP_PORT: FieldRef[int] = FieldRef("tcp.port", "FT_UINT16", True)
FRAME_TIME_T: FieldRef[datetime] = FieldRef("frame.time", "FT_ABSOLUTE_TIME", False)
FRAME_NUMBER: FieldRef[int] = FieldRef("frame.number", "FT_FRAMENUM", False)
IPV6_ADDR: FieldRef[IPv6Address] = FieldRef("ipv6.addr", "FT_IPv6", True)


def line(*cols: tuple[str, ...] | str) -> str:
    """Join projected columns with the real separators tshark uses."""
    return UNIT_SEP.join(OCC_SEP.join((c,) if isinstance(c, str) else c) for c in cols)


#: Three frames projecting ``frame.number``, ``frame.time_epoch``, ``ip.src``
#: and (multi) ``tcp.port``; the third frame has neither IP nor TCP.
ROWS = [
    line("1", "1614597071.5", "10.0.0.1", ("51234", "443")),
    line("2", "1614597072.25", "10.0.0.2", ("443", "51234")),
    line("3", "1614597073.0", "", ""),
]


class FakeRunner:
    """Runner double: records argv, streams canned lines, optionally fails mid-stream.

    ``fail_after`` equal to the line count fails at end of stream instead —
    which is where the real ``TsharkProcess`` raises ``TsharkError`` on a
    nonzero exit — and ``fail_with`` picks the exception raised either way.

    ``lines`` is held as given and iterated lazily, never materialized: that
    is what lets a test drive a large synthetic capture from a generator and
    watch how much of it is resident at each flush. One runner therefore
    consumes its iterable once.
    """

    def __init__(
        self,
        lines: Iterable[str],
        fail_after: int | None = None,
        fail_with: BaseException | None = None,
    ) -> None:
        self._lines = lines
        self._fail_after = fail_after
        self._fail_with = fail_with
        self.argv: list[str] | None = None
        self.pulled = 0

    def __call__(self, argv: Sequence[str]) -> Any:
        self.argv = list(argv)

        @contextmanager
        def ctx() -> Iterator[Iterable[str]]:
            yield self._iter()

        return ctx()

    def projected(self) -> list[str]:
        """Field abbrevs the recorded argv projects, in ``-e`` order."""
        argv = self.argv
        assert argv is not None
        return [argv[i + 1] for i, arg in enumerate(argv) if arg == "-e"]

    def _failure(self) -> BaseException:
        if self._fail_with is not None:
            return self._fail_with
        return RuntimeError("mid-stream failure injected by test")

    def _iter(self) -> Iterator[str]:
        produced = 0
        for i, text in enumerate(self._lines):
            if self._fail_after is not None and i >= self._fail_after:
                raise self._failure()
            self.pulled += 1
            produced += 1
            yield text
        # Counted rather than len()'d: the input may be a lazy generator.
        if self._fail_after is not None and self._fail_after >= produced:
            raise self._failure()


def make_pcap(tmp_path: Path, name: str = "cap.pcap", filler: bytes = b"\x00") -> Path:
    """A real (tiny) file for make_cache_key to fingerprint; tshark never runs."""
    pcap = tmp_path / name
    pcap.write_bytes(filler * 128)
    return pcap


@contextmanager
def reading(ws_path: Path) -> Iterator[DuckDBPyConnection]:
    """Reopen a workspace read-only and yield its connection."""
    with Workspace(ws_path, mode="ro") as ws, ws.read() as con:
        yield con


def pkts_columns(con: DuckDBPyConnection) -> list[str]:
    """Column names of ``main.pkts``, in ordinal order."""
    rows = con.execute(
        "SELECT column_name FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' ORDER BY column_index"
    ).fetchall()
    return [str(row[0]) for row in rows]


def pkts_column_type(con: DuckDBPyConnection, column: str) -> str:
    """DuckDB type of one ``main.pkts`` column."""
    row = con.execute(
        "SELECT data_type FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = 'pkts' AND column_name = ?",
        [column],
    ).fetchone()
    assert row is not None
    return str(row[0])


def count(con: DuckDBPyConnection, table: str) -> int:
    """Row count of a table, by name."""
    row = con.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])
