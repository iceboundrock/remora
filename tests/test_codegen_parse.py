"""Tests for parsing ``tshark -G fields`` dumps into the field-dictionary model."""

from __future__ import annotations

from remora.codegen.parse import (
    FieldDef,
    FieldDictionary,
    Protocol,
    parse_fields_dump,
)

P_DNS = "P\tDomain Name System\tdns"
F_DNS_QRY_NAME = "F\tName\tdns.qry.name\tFT_STRING\tdns\t\t0x0\tQuery Name"
F_IP_SRC = "F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\t"
F_6LOWPAN_CLASS = "F\tTraffic class\t6lowpan.class\tFT_UINT8\t6lowpan\tBASE_HEX\t0x0\t"


class TestRecordParsing:
    def test_protocol_record(self) -> None:
        result = parse_fields_dump(P_DNS + "\n")
        assert result.protocols == (Protocol(name="Domain Name System", abbrev="dns"),)
        assert result.fields == ()
        assert result.warnings == ()

    def test_field_record(self) -> None:
        result = parse_fields_dump(F_DNS_QRY_NAME + "\n")
        assert result.fields == (
            FieldDef(name="Name", abbrev="dns.qry.name", ftype="FT_STRING", parent="dns", base=""),
        )

    def test_field_record_with_base(self) -> None:
        result = parse_fields_dump(F_6LOWPAN_CLASS + "\n")
        assert result.fields[0].base == "BASE_HEX"

    def test_mixed_records_preserve_order(self) -> None:
        text = "\n".join([P_DNS, F_DNS_QRY_NAME, F_IP_SRC]) + "\n"
        result = parse_fields_dump(text)
        assert [p.abbrev for p in result.protocols] == ["dns"]
        assert [f.abbrev for f in result.fields] == ["dns.qry.name", "ip.src"]

    def test_empty_input(self) -> None:
        assert parse_fields_dump("") == FieldDictionary(protocols=(), fields=(), warnings=())

    def test_blank_lines_skipped_silently(self) -> None:
        result = parse_fields_dump("\n\n" + P_DNS + "\n\n")
        assert len(result.protocols) == 1
        assert result.warnings == ()


class TestWarnings:
    def test_unknown_record_type_collected_not_dropped(self) -> None:
        result = parse_fields_dump("X\tsomething\tweird\n" + P_DNS + "\n")
        assert len(result.protocols) == 1
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 1
        assert "unknown record type 'X'" in result.warnings[0].message

    def test_malformed_protocol_record_wrong_columns(self) -> None:
        result = parse_fields_dump("P\tonly-two-columns\n")
        assert result.protocols == ()
        assert len(result.warnings) == 1
        assert "malformed P record" in result.warnings[0].message

    def test_malformed_field_record_wrong_columns(self) -> None:
        result = parse_fields_dump("F\tName\tdns.qry.name\tFT_STRING\tdns\n")
        assert result.fields == ()
        assert len(result.warnings) == 1
        assert "malformed F record" in result.warnings[0].message


class TestDuplicatePolicy:
    """Duplicates: first occurrence wins; later ones become warnings."""

    def test_duplicate_protocol_abbrev_first_wins(self) -> None:
        text = "P\tTPKT - ISO on TCP - RFC1006\ttpkt\nP\tTPKT Heuristic (for RDP)\ttpkt\n"
        result = parse_fields_dump(text)
        assert result.protocols == (Protocol(name="TPKT - ISO on TCP - RFC1006", abbrev="tpkt"),)
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 2
        assert "duplicate protocol abbrev 'tpkt'" in result.warnings[0].message

    def test_duplicate_field_abbrev_first_wins(self) -> None:
        first = "F\tFirst\tdns.id\tFT_UINT16\tdns\tBASE_HEX\t0x0\t"
        second = "F\tSecond\tdns.id\tFT_UINT32\tdns\tBASE_DEC\t0x0\t"
        result = parse_fields_dump(first + "\n" + second + "\n")
        assert len(result.fields) == 1
        assert result.fields[0].name == "First"
        assert result.fields[0].ftype == "FT_UINT16"
        assert len(result.warnings) == 1
        assert result.warnings[0].line_no == 2
        assert "duplicate field abbrev 'dns.id'" in result.warnings[0].message

    def test_protocol_and_field_abbrev_namespaces_are_independent(self) -> None:
        # A field abbrev may equal a protocol abbrev (e.g. checksum-carrying
        # pseudo-fields); that is not a duplicate.
        text = P_DNS + "\n" + "F\tDNS\tdns\tFT_NONE\tdns\t\t0x0\t\n"
        result = parse_fields_dump(text)
        assert len(result.protocols) == 1
        assert len(result.fields) == 1
        assert result.warnings == ()
