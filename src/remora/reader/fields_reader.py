r"""The ``-T fields`` projection reader: parse tshark's columnar field output.

When the query's field set is statically known, projection pushdown via
``-T fields`` makes tshark emit only the needed columns. Field values can
contain tabs, commas, and quotes, so the columns are delimited with ASCII
control characters that cannot appear in dissected field text:

- :data:`UNIT_SEP` (``0x1f``, unit separator) between columns, and
- :data:`OCC_SEP` (``0x1e``, record separator) between multiple occurrences
  of one field within a column (e.g. ``tcp.port`` dissects twice per packet).

Separator syntax (verified against tshark 4.6.7, Homebrew)
----------------------------------------------------------
tshark's ``-E separator=``/``-E aggregator=`` options accept only ``/t``
(tab), ``/s`` (space), or a single **literal** character — there is no
``/xNN`` hex-escape form. A live probe with ``separator=/x1f`` did not
error but silently set the separator to a literal backslash (``0x5c``),
which would corrupt parsing. :func:`fields_argv` therefore embeds the raw
control bytes directly in the argv strings (``"separator=\x1f"`` with the
actual ``0x1f`` byte); this is safe because argv is passed to ``exec``
without a shell. Verified by running the exact argv against a hand-crafted
pcap and observing ``0x1f``/``0x1e`` bytes in stdout.

Absent vs. empty (known tshark-level limitation)
------------------------------------------------
An empty column means the field is ABSENT and :meth:`FieldsRow.get_raw`
returns ``()`` (this is how ``None`` is modeled by the packet contract).
Consequently a *present but genuinely empty* single value is emitted by
tshark as an empty column too, indistinguishable from absence in
``-T fields`` output. Empty occurrences AMONG multiple are preserved,
however: a column of just ``OCC_SEP`` parses to ``("", "")``.

This reader deals in raw strings only — no value conversion happens here.
Conversion lives in ``Field.__get__``/the predicate backend, which keeps
the reader/descriptor contract one seam (:class:`remora.fields.RawPacket`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any, TypeVar, cast

from remora.fields import FieldNotProjectedError, FieldRef

__all__ = ["OCC_SEP", "UNIT_SEP", "FieldsReader", "FieldsRow", "fields_argv"]

#: Between columns: ``-E separator=`` (ASCII unit separator).
UNIT_SEP = "\x1f"

#: Between occurrences of one field: ``-E aggregator=`` (ASCII record separator).
OCC_SEP = "\x1e"

P = TypeVar("P")


def fields_argv(projection: Sequence[FieldRef[Any]]) -> list[str]:
    """Build the ``-T fields`` argv fragment for *projection*, in order.

    Always includes ``-E occurrence=a`` (all occurrences) and both control
    separators as raw bytes (see module docstring for why not ``/xNN``).
    """
    argv = [
        "-T",
        "fields",
        "-E",
        f"separator={UNIT_SEP}",
        "-E",
        f"aggregator={OCC_SEP}",
        "-E",
        "occurrence=a",
    ]
    for ref in projection:
        argv += ["-e", ref.name]
    return argv


class FieldsRow:
    """One packet's projected columns; implements the ``Packet`` contract.

    ``get_raw`` serves raw string occurrences for projected fields and
    raises :class:`FieldNotProjectedError` for anything outside the
    projection (unlike ek-mode packets, absence of knowledge here is a
    caller bug, not field absence). ``row[Proto]`` returns ``Proto(row)``
    so protocol-class descriptors read through this row.
    """

    __slots__ = ("_columns",)

    def __init__(self, columns: dict[str, tuple[str, ...]]) -> None:
        self._columns = columns

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        """Raw occurrences of *field_name*; ``()`` means absent."""
        try:
            return self._columns[field_name]
        except KeyError:
            raise FieldNotProjectedError(
                f"field {field_name!r} is not in this row's projection "
                f"({sorted(self._columns)}); add it to the projected field set"
            ) from None

    def __getitem__(self, proto: type[P]) -> P:
        return cast("Callable[[FieldsRow], P]", proto)(self)

    def __repr__(self) -> str:
        cols = ", ".join(f"{name}={occs!r}" for name, occs in self._columns.items())
        return f"<FieldsRow {cols}>"


class FieldsReader:
    """Iterate :class:`FieldsRow` over raw stdout lines of a ``-T fields`` run.

    *lines* is any iterable of already-newline-stripped lines (e.g. a
    :class:`remora.reader.process.TsharkProcess`); *projection* must be the
    same field refs, in the same order, that produced the argv via
    :func:`fields_argv`.
    """

    def __init__(self, lines: Iterable[str], projection: Sequence[FieldRef[Any]]) -> None:
        self._lines = lines
        self._names = tuple(ref.name for ref in projection)

    def __iter__(self) -> Iterator[FieldsRow]:
        names = self._names
        expected = len(names)
        for lineno, line in enumerate(self._lines, start=1):
            parts = line.split(UNIT_SEP)
            if len(parts) != expected:
                raise ValueError(
                    f"fields line {lineno}: expected {expected} column(s) "
                    f"for projection {list(names)}, got {len(parts)}"
                )
            columns = {
                name: () if part == "" else tuple(part.split(OCC_SEP))
                for name, part in zip(names, parts, strict=True)
            }
            yield FieldsRow(columns)
