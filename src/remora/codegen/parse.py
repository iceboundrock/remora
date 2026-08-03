"""Parse ``tshark -G fields`` dumps into the field-dictionary model.

Input format (tab-separated, one record per line):

- ``P`` records, exactly 3 columns: ``P<TAB>display name<TAB>abbrev``
- ``F`` records, exactly 8 columns: ``F<TAB>display name<TAB>abbrev<TAB>
  ftype<TAB>parent protocol abbrev<TAB>display base<TAB>bitmask<TAB>blurb``

Robustness policy — no line is ever silently dropped:

- Unknown record types are skipped and recorded as :class:`ParseWarning`.
- Records with the wrong column count are skipped and recorded as warnings.
- Duplicate abbrevs (protocol and field namespaces are independent): the
  *first* occurrence wins; every later duplicate is skipped and recorded as
  a warning. Input line order makes this deterministic. Real dumps contain
  duplicate protocol abbrevs (e.g. ``tpkt`` in tshark 4.6.x).
- Blank lines (empty or whitespace-only) are skipped silently.

The bitmask and blurb columns are currently not modeled (nothing consumes
them); ``base`` keeps the raw text of the display-base column, which may be
empty, a ``BASE_*`` name, or a bare integer (boolean field width).

``-G fields`` carries no multiplicity signal at all, so the ``multi`` flag of
the frozen ``_table_`` format (see :mod:`remora.proto._meta`) must come from
another source — that is the emitter's (#14) problem, out of scope here.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["FieldDef", "FieldDictionary", "ParseWarning", "Protocol", "parse_fields_dump"]


@dataclass(frozen=True)
class Protocol:
    """One ``P`` record: a dissector protocol."""

    name: str
    abbrev: str


@dataclass(frozen=True)
class FieldDef:
    """One ``F`` record: a dissector field."""

    name: str
    abbrev: str
    ftype: str
    parent: str
    base: str


@dataclass(frozen=True)
class ParseWarning:
    """A skipped input line: where and why. ``line_no`` is 1-based."""

    line_no: int
    message: str


@dataclass(frozen=True)
class FieldDictionary:
    """Everything one ``tshark -G fields`` dump parses into, in input order."""

    protocols: tuple[Protocol, ...]
    fields: tuple[FieldDef, ...]
    warnings: tuple[ParseWarning, ...]


_P_COLUMNS = 3
_F_COLUMNS = 8


def parse_fields_dump(text: str) -> FieldDictionary:
    """Parse a full ``tshark -G fields`` dump (see module docs for policy)."""
    protocols: list[Protocol] = []
    fields: list[FieldDef] = []
    warnings: list[ParseWarning] = []
    seen_protocols: set[str] = set()
    seen_fields: set[str] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        columns = line.split("\t")
        tag = columns[0]
        if tag == "P":
            if len(columns) != _P_COLUMNS:
                warnings.append(
                    ParseWarning(
                        line_no,
                        f"malformed P record: expected {_P_COLUMNS} columns, got {len(columns)}",
                    )
                )
                continue
            _, name, abbrev = columns
            if abbrev in seen_protocols:
                warnings.append(ParseWarning(line_no, f"duplicate protocol abbrev {abbrev!r}"))
                continue
            seen_protocols.add(abbrev)
            protocols.append(Protocol(name=name, abbrev=abbrev))
        elif tag == "F":
            if len(columns) != _F_COLUMNS:
                warnings.append(
                    ParseWarning(
                        line_no,
                        f"malformed F record: expected {_F_COLUMNS} columns, got {len(columns)}",
                    )
                )
                continue
            _, name, abbrev, ftype, parent, base, _bitmask, _blurb = columns
            if abbrev in seen_fields:
                warnings.append(ParseWarning(line_no, f"duplicate field abbrev {abbrev!r}"))
                continue
            seen_fields.add(abbrev)
            fields.append(FieldDef(name=name, abbrev=abbrev, ftype=ftype, parent=parent, base=base))
        else:
            warnings.append(ParseWarning(line_no, f"unknown record type {tag!r}"))

    return FieldDictionary(
        protocols=tuple(protocols), fields=tuple(fields), warnings=tuple(warnings)
    )
