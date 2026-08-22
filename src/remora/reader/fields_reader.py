r"""The ``-T fields`` projection reader: parse tshark's columnar field output.

When the query's field set is statically known, projection pushdown via
``-T fields`` makes tshark emit only the needed columns. Columns are framed
with ASCII control bytes rather than a printable delimiter, because field
text can hold tabs, commas and quotes:

- :data:`UNIT_SEP` (``0x0b``, vertical tab) between columns, and
- :data:`OCC_SEP` (``0x1e``, record separator) between multiple occurrences
  of one field within a column (e.g. ``tcp.port`` dissects twice per packet).

tshark C-escapes control bytes in values, and HOW changed in 4.4
------------------------------------------------------------------
``-T fields`` does **not** print string field values verbatim: it runs them
through a C-style escaper, while the display-filter engine and ``-T ek`` both
operate on the true value. That is the divergence issue #74 was filed for — a
fields-mode residual predicate and a pushed-down ``-Y`` filter selecting
different packets for the same expression.

The escaper is **not stable across releases**. Probing every byte from
``0x01`` to ``0x20`` plus ``0x5c`` and ``0x7f`` through a pcapng frame
comment, on three builds (4.2.2 and 4.4.5 from the Ubuntu archives, 4.6.8
from Homebrew)::

    byte        4.2.2       4.4.5 / 4.6.8
    0x07        raw         \a
    0x08        \b          \b
    0x09        \t          \t
    0x0a        \n          \n
    0x0b        \v          \v
    0x0c        \f          \f
    0x0d        \r          \r
    0x5c        raw         \\
    all others  raw         raw

("all others" is ``0x01`` to ``0x06``, ``0x0e`` to ``0x1f``, and ``0x7f``. ``0x00``
is out of scope: it cannot be carried through the tooling that builds the
fixture, and would truncate the C strings tshark builds internally.)

The ``0x5c`` row decides whether the escaping can be inverted at all. From
4.4 a literal backslash is doubled, so a backslash in the output always
begins one of the eight escapes and :func:`unescape` inverts the table
exactly. On 4.2.2 it is **not** doubled and the mapping collapses: the value
``C:\temp`` and the value ``C:`` + TAB + ``emp`` are *both* printed as
``C:\temp`` (measured, not reasoned). Nothing in the output tells them apart,
so unescaping on such a build would silently rewrite ``C:\temp`` into
``C:<TAB>emp`` — and backslash-bearing values are everywhere in real traffic
(SMB paths, Windows filenames). Corrupting a common value is strictly worse
than the divergence #74 set out to fix.

Unescaping is therefore **gated**: :func:`escaping_is_reversible` decides from
the tshark version, :data:`UNESCAPE_MIN_VERSION` is the boundary, and
:class:`FieldsReader` unescapes only when its caller passes
``unescape_values=True``. The default is ``False``, which is also what an
unknown or unparseable version yields — the safe direction in both cases. On
a pre-4.4 build the reader keeps returning escaped text exactly as it did
before #74: the divergence remains, documented, instead of becoming
corruption. 4.3.x is a development series between the two measured releases
and is treated as old for the same reason.

``ek_reader`` needs no gate on any version — JSON string decoding already
yields the true value — which is why it is the reference the parity tests in
``tests/integration/test_control_chars.py`` compare against.

Why the separators are the bytes they are (load-bearing, and version-proof)
-----------------------------------------------------------------------------
Framing, unlike unescaping, is fixed **unconditionally**: both choices below
hold on all three builds measured above. The two separators sit on **opposite
sides** of the escaper, so their requirements are opposite and getting either
backwards corrupts data silently:

- The **column separator** is written to the stream raw, *after* each
  column's text has been escaped. It must therefore be a byte the escaper
  replaces, so that no field value can ever forge it: a real ``0x0b`` inside
  a value arrives as the two characters ``\v``, and the only raw ``0x0b`` on
  the line is a column boundary. ``0x0b`` is escaped on 4.2.2, 4.4.5 and
  4.6.8 alike, so column framing is unambiguous everywhere. The old choice
  ``0x1f`` was escaped by none of them, so a value carrying one split the
  column and the reader aborted a perfectly valid capture with
  ``expected N column(s) ... got N+1``.
- The **occurrence aggregator** must be a byte the escaper leaves alone, and
  ``0x1e`` is raw on every measured version. This side changed in 4.4 too,
  in the *opposite* direction: 4.2.2 splices the aggregator in **after**
  escaping (so ``aggregator=0x0c`` arrives as a raw ``0x0c``), while 4.4.5
  and 4.6.8 splice it in **before** (so the same option arrives as the two
  characters ``\f`` and never splits at all). An escaped byte is thus usable
  as the aggregator on 4.2.2 and unusable on 4.4+, which is exactly why the
  never-escaped ``0x1e`` — and not the escaped-byte trick that secures the
  column separator — is the only choice that splits correctly on both.

The aggregator's residual is inherent, and is stated rather than implied:
what tshark hands back for a column is ``escape(occ1 + SEP + occ2)``, a
function of the joined string alone, so the join positions are simply not
recoverable — a value genuinely containing ``0x1e`` forks into two
occurrences. No byte choice fixes that on 4.4+ (an escaped byte collides on
its escape form instead, which is strictly worse because it also stops
splitting real occurrences); only a tshark-side change could, so the case is
pinned as a known trade-off rather than papered over. Line framing has no
such residual: ``0x0a`` is escaped on every measured version, so a newline
inside a value cannot break the line split.

Unescaping, when it runs at all, happens **after** splitting, never before.
Splitting first is what makes the column rule above sound — unescaping first
would turn a value's ``\v`` into a real ``0x0b`` that then framed a spurious
column.

Separator syntax (verified against tshark 4.6.7/4.6.8, Homebrew)
------------------------------------------------------------------
tshark's ``-E separator=``/``-E aggregator=`` options accept only ``/t``
(tab), ``/s`` (space), or a single **literal** character — there is no
``/xNN`` hex-escape form. A live probe with ``separator=/x1f`` did not
error but silently set the separator to a literal backslash (``0x5c``),
which would corrupt parsing. :func:`fields_argv` therefore embeds the raw
control bytes directly in the argv strings (``"separator=\x0b"`` with the
actual ``0x0b`` byte); this is safe because argv is passed to ``exec``
without a shell. Verified by running the exact argv against a hand-crafted
pcap and observing ``0x0b``/``0x1e`` bytes in stdout.

Absent vs. empty (known tshark-level limitation)
------------------------------------------------
An empty column means the field is ABSENT and :meth:`FieldsRow.get_raw`
returns ``()`` (this is how ``None`` is modeled by the packet contract).
Consequently a *present but genuinely empty* single value is emitted by
tshark as an empty column too, indistinguishable from absence in
``-T fields`` output. Empty occurrences AMONG multiple are preserved,
however: a column of just ``OCC_SEP`` parses to ``("", "")``.

This reader deals in raw strings only — undoing tshark's transport escaping
is *recovery* of the value tshark dissected, not conversion, and no type
conversion happens here. Conversion lives in ``Field.__get__``/the predicate
backend, which keeps the reader/descriptor contract one seam
(:class:`remora.fields.RawPacket`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Final, TypeVar, cast

from remora.fields import FieldNotProjectedError, FieldRef

__all__ = [
    "ESCAPED_CHARS",
    "OCC_SEP",
    "UNESCAPE_MIN_VERSION",
    "UNIT_SEP",
    "FieldsReader",
    "FieldsRow",
    "escaping_is_reversible",
    "fields_argv",
    "unescape",
]

#: Between columns: ``-E separator=`` (ASCII vertical tab).
#:
#: MUST be a key of :data:`ESCAPED_CHARS` — see the module docstring.
UNIT_SEP = "\x0b"

#: Between occurrences of one field: ``-E aggregator=`` (ASCII record separator).
#:
#: MUST NOT be a key of :data:`ESCAPED_CHARS` — see the module docstring.
OCC_SEP = "\x1e"

#: tshark's ``-T fields`` escape table: byte -> the letter following the
#: backslash in its printed form. Measured, not assumed (module docstring).
ESCAPED_CHARS: Mapping[str, str] = MappingProxyType(
    {
        "\a": "a",
        "\b": "b",
        "\t": "t",
        "\n": "n",
        "\v": "v",
        "\f": "f",
        "\r": "r",
        "\\": "\\",
    }
)

#: The inverse used by :func:`unescape`, escape letter -> byte.
_UNESCAPE: Mapping[str, str] = MappingProxyType(
    {letter: char for char, letter in ESCAPED_CHARS.items()}
)

#: First tshark release whose ``-T fields`` escaping is invertible — i.e. the
#: first that doubles a literal backslash. Below it the escaping is lossy and
#: :func:`unescape` MUST NOT run (module docstring). 4.2.2 and 4.4.5 were
#: measured either side of this line; the 4.3.x development series in between
#: was not, and falls on the safe side.
UNESCAPE_MIN_VERSION: Final = (4, 4)


def escaping_is_reversible(tshark_version: str | None) -> bool:
    """Whether *tshark_version* escapes ``-T fields`` values invertibly.

    *tshark_version* is an ``X.Y.Z`` string as
    :func:`remora.codegen.fingerprint.parse_tshark_version` returns it (a
    bare ``X`` or ``X.Y`` is accepted too). ``True`` only from
    :data:`UNESCAPE_MIN_VERSION` upward.

    Anything unrecognizable — ``None``, empty, or not starting with numeric
    components — is ``False``. That default is deliberate and is the whole
    safety property: a caller that cannot establish the version gets the
    pre-#74 behavior (escaped text, a known divergence) rather than a lossy
    round trip that would corrupt every literal backslash.
    """
    if not tshark_version:
        return False
    parts = tshark_version.split(".")
    try:
        numbers = tuple(int(part) for part in parts[:2])
    except ValueError:
        return False
    # A bare "4" is 4.0 — below the boundary either way, but spelled out so
    # the comparison never comes down to tuple-length ordering.
    if len(numbers) == 1:
        numbers = (numbers[0], 0)
    return numbers >= UNESCAPE_MIN_VERSION


P = TypeVar("P")


def unescape(text: str) -> str:
    r"""Invert tshark's ``-T fields`` value escaping (:data:`ESCAPED_CHARS`).

    Backslash sequences the table does not name are passed through verbatim,
    as is a trailing lone backslash. tshark emits neither, so refusing would
    only turn an unknown build's quirk into a crash on otherwise valid data;
    passing through keeps the value as close to the truth as we can get. The
    scan is left to right, so ``\\t`` is a literal backslash followed by
    ``t`` and never a tab.
    """
    if "\\" not in text:  # overwhelmingly the common case
        return text
    out: list[str] = []
    index = 0
    length = len(text)
    while True:
        hit = text.find("\\", index)
        if hit < 0:
            out.append(text[index:])
            return "".join(out)
        out.append(text[index:hit])
        if hit + 1 == length:  # trailing lone backslash
            out.append("\\")
            return "".join(out)
        out.append(_UNESCAPE.get(text[hit + 1], text[hit : hit + 2]))
        index = hit + 2


def _identity(text: str) -> str:
    """Leave a value exactly as tshark printed it (the pre-4.4 gate's branch)."""
    return text


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

    *unescape_values* inverts tshark's value escaping (:func:`unescape`). It
    defaults to ``False`` because the escaping is only invertible from tshark
    4.4 — below that, undoing it corrupts literal backslashes (module
    docstring). Callers that know the binary's version pass
    ``escaping_is_reversible(version)``; callers that do not get the safe
    behavior by default. Column and occurrence framing is unaffected either
    way, being version-proof by construction.
    """

    __slots__ = ("_lines", "_names", "_unescape")

    def __init__(
        self,
        lines: Iterable[str],
        projection: Sequence[FieldRef[Any]],
        *,
        unescape_values: bool = False,
    ) -> None:
        self._lines = lines
        self._names = tuple(ref.name for ref in projection)
        self._unescape = unescape_values

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
            # Split all framing FIRST, then unescape each occurrence: the
            # column rule only holds while a value's escaped VT is still two
            # characters (module docstring).
            decode = unescape if self._unescape else _identity
            columns = {
                name: () if part == "" else tuple(decode(occ) for occ in part.split(OCC_SEP))
                for name, part in zip(names, parts, strict=True)
            }
            yield FieldsRow(columns)
