"""Column-name policy tests (issue #25)."""

from __future__ import annotations

import pytest

from remora.workspace.naming import SKELETON_COLUMNS, column_name, find_collisions


class TestColumnName:
    def test_dotted_abbrev_becomes_underscored(self) -> None:
        assert column_name("tcp.port") == "tcp_port"

    def test_full_abbrev_is_kept_no_parent_stripping(self) -> None:
        # Column names share one flat namespace: udp.port must not become "port".
        assert column_name("udp.port") == "udp_port"
        assert column_name("dns.qry.name") == "dns_qry_name"

    def test_hyphens_and_exotic_chars_become_underscores(self) -> None:
        assert column_name("acf-can.len") == "acf_can_len"
        assert column_name("x11.rgb-color") == "x11_rgb_color"

    def test_lowercased(self) -> None:
        # DuckDB identifiers compare case-insensitively.
        assert column_name("BThci_evt.code") == "bthci_evt_code"

    def test_leading_digit_gets_prefix(self) -> None:
        assert column_name("iec61883.4_incorrect_cip_fn") == "iec61883_4_incorrect_cip_fn"
        assert column_name("6lowpan.pattern") == "f_6lowpan_pattern"

    def test_frame_skeleton_columns(self) -> None:
        # The pkts skeleton columns are exactly these, so materializing
        # frame.number / frame.time is not a special case.
        assert column_name("frame.number") == "frame_number"
        assert column_name("frame.time") == "frame_time"

    def test_non_ascii_alphanumerics_become_underscores(self) -> None:
        # "µ".isalnum() is True but it is not ASCII, so the isascii() guard is
        # what keeps it out of the identifier.
        assert column_name("tcp.µs") == "tcp__s"

    def test_deterministic(self) -> None:
        assert column_name("tcp.analysis.flags") == column_name("tcp.analysis.flags")

    def test_empty_abbrev_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            column_name("")


class TestFindCollisions:
    def test_no_collisions_returns_empty(self) -> None:
        assert find_collisions(["tcp.port", "udp.port", "ip.src"]) == {}

    def test_dot_and_underscore_pair_collides(self) -> None:
        assert find_collisions(["tcp.port", "tcp_port"]) == {
            "tcp_port": ("tcp.port", "tcp_port"),
        }

    def test_case_only_pair_collides(self) -> None:
        assert find_collisions(["ip.Src", "ip.src"]) == {"ip_src": ("ip.Src", "ip.src")}

    def test_duplicate_abbrev_is_not_a_collision(self) -> None:
        assert find_collisions(["tcp.port", "tcp.port"]) == {}

    def test_colliding_abbrevs_are_sorted(self) -> None:
        assert find_collisions(["b.x", "b_x", "a.b.x"]) == {"b_x": ("b.x", "b_x")}

    def test_the_leading_digit_prefix_creates_its_own_collision(self) -> None:
        # The f_ rule is not injective either: a real abbrev already starting
        # with "f_" can claim the column a digit-leading abbrev is prefixed into.
        assert find_collisions(["6lowpan.x", "f_6lowpan.x"]) == {
            "f_6lowpan_x": ("6lowpan.x", "f_6lowpan.x"),
        }


class TestSkeletonColumns:
    def test_matches_the_pkts_skeleton_under_the_policy(self) -> None:
        # The pkts skeleton is built from these two abbrevs; if the policy ever
        # changes, this fails rather than letting the skeleton drift out of it.
        assert {column_name("frame.number"), column_name("frame.time")} == SKELETON_COLUMNS
