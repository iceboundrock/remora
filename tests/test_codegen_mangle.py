"""Tests for the field-abbrev -> Python attribute name mangling policy."""

from __future__ import annotations

import pytest

from remora.codegen.mangle import mangle_field


class TestParentStripping:
    def test_strips_parent_prefix_and_replaces_dots(self) -> None:
        assert mangle_field("dns.qry.name", "dns") == "qry_name"

    def test_abbrev_equal_to_parent_keeps_full_name(self) -> None:
        assert mangle_field("dns", "dns") == "dns"

    def test_field_not_under_parent_prefix_uses_full_abbrev(self) -> None:
        # Real case: protocol "acf-can" registers field "can.len".
        assert mangle_field("can.len", "acf-can") == "can_len"

    def test_prefix_must_match_whole_segment(self) -> None:
        # "ip" is not a dot-terminated prefix of "ipv6.src".
        assert mangle_field("ipv6.src", "ip") == "ipv6_src"


class TestCharacterReplacement:
    def test_hyphens_become_underscores(self) -> None:
        assert mangle_field("acf-can.flags", "acf-can") == "flags"
        assert mangle_field("dns.qry-name", "dns") == "qry_name"

    def test_case_is_preserved(self) -> None:
        assert mangle_field("iso.SS", "iso") == "SS"


class TestLeadingDigit:
    def test_leading_digit_gets_f_prefix(self) -> None:
        # Real case: iec61883.4_incorrect_cip_fn under parent iec61883.
        assert mangle_field("iec61883.4_incorrect_cip_fn", "iec61883") == "f_4_incorrect_cip_fn"

    def test_full_abbrev_with_leading_digit(self) -> None:
        assert mangle_field("6lowpan", "nonmatching") == "f_6lowpan"


class TestLeadingUnderscore:
    def test_leading_underscore_gets_f_prefix(self) -> None:
        # Underscore-prefixed attributes are reserved on protocol classes.
        assert mangle_field("_ws.short", "_ws.short") == "f_ws_short"


class TestKeywords:
    def test_hard_keyword_gets_trailing_underscore(self) -> None:
        # Real case: 6lowpan.class under parent 6lowpan.
        assert mangle_field("6lowpan.class", "6lowpan") == "class_"
        assert mangle_field("afp.spotlight.return", "afp") == "spotlight_return"
        assert mangle_field("afs.reassembled.in", "afs") == "reassembled_in"
        assert mangle_field("dns.in", "dns") == "in_"

    def test_soft_keywords_left_alone(self) -> None:
        assert mangle_field("dns.match", "dns") == "match"
        assert mangle_field("dns.type", "dns") == "type"


class TestInvalidInput:
    def test_empty_abbrev_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            mangle_field("", "dns")
