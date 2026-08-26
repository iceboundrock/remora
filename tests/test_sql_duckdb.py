"""SQL backend tests that run against a real DuckDB (issue #29).

Gated on duckdb like tests/test_workspace_types.py: the shape tests in
tests/test_sql.py must keep running without it, but hostile literals, the
FT_IPv6 CAST and the semantics-table equivalence suite only mean anything when
DuckDB actually executes them.

No DDL is written here: tables come from remora.workspace.schema, which is the
single source of the workspace layout.

Import-purity testing is in tests/test_sql_import_purity.py (ungated so it
runs in core-only environments).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Any

import pytest

from remora.compile.sql import UnsupportedSqlExprError, compile_sql
from remora.expr import Expr, field_refs
from remora.fields import FieldRef
from remora.workspace.naming import SKELETON_COLUMNS
from remora.workspace.schema import add_field_column, create_schema
from remora.workspace.types import ColumnSpec, column_spec
from test_semantics_table import CASES, Case

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

duckdb = pytest.importorskip("duckdb")

HOST = FieldRef[str]("http.host", "FT_STRING", False)
SRC = FieldRef[IPv4Address]("ip.src", "FT_IPv4", False)
V6SRC = FieldRef[IPv6Address]("ipv6.src", "FT_IPv6", False)
V6ADDR = FieldRef[IPv6Address]("ipv6.addr", "FT_IPv6", True)
DVAL = FieldRef[float]("x.value", "FT_DOUBLE", False)
DVALS = FieldRef[float]("x.values", "FT_DOUBLE", True)
PORTS = FieldRef[int]("tcp.port", "FT_UINT16", True)
QNAME = FieldRef[str]("dns.qry.name", "FT_STRING", True)

NAN = float("nan")


@pytest.fixture
def con() -> Iterator[DuckDBPyConnection]:
    """An in-memory workspace with the layout created."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


def materialize(
    connection: DuckDBPyConnection,
    fields: tuple[FieldRef[Any], ...],
    rows: tuple[dict[str, tuple[str, ...]], ...],
) -> None:
    """Add a column per field and insert one pkts row per raw-occurrence dict."""
    specs = [column_spec(field.name, field.ftype, field.multi) for field in fields]
    for spec in specs:
        add_field_column(connection, spec.column_name, spec.sql_type)
    columns = ", ".join(f'"{spec.column_name}"' for spec in specs)
    placeholders = ", ".join("?" for _ in specs)
    for index, raw in enumerate(rows):
        values_: list[Any] = [index]
        values_.extend(spec.encode_raw(raw.get(spec.abbrev, ())) for spec in specs)
        connection.execute(
            f'INSERT INTO main.pkts ("frame_number", {columns}) VALUES (?, {placeholders})',
            values_,
        )


def select(connection: DuckDBPyConnection, expr: Expr) -> set[int]:
    """Frame numbers selected by an expression's compiled SQL predicate."""
    predicate = compile_sql(expr)
    rows = connection.execute(
        f"SELECT frame_number FROM main.pkts WHERE {predicate.sql} ORDER BY frame_number",
        list(predicate.params),
    ).fetchall()
    return {int(row[0]) for row in rows}


class TestNoInjectionPathAgainstRealDuckDB:
    @pytest.mark.parametrize(
        "hostile",
        [
            "'; DROP TABLE pkts; --",
            '" OR "1"="1',
            "x' UNION SELECT * FROM meta.info --",
        ],
    )
    def test_hostile_literal_matches_only_itself_and_destroys_nothing(
        self, con: DuckDBPyConnection, hostile: str
    ) -> None:
        materialize(con, (HOST,), ({"http.host": (hostile,)}, {"http.host": ("example.com",)}))
        assert select(con, HOST == hostile) == {0}  # noqa: SIM300
        assert select(con, HOST == "example.com") == {1}
        remaining = con.execute("SELECT count(*) FROM main.pkts").fetchone()
        assert remaining is not None
        assert remaining[0] == 2


class TestIPv6BindingAgainstRealDuckDB:
    def test_scalar_high_bit_address_binds_through_the_cast(self, con: DuckDBPyConnection) -> None:
        # ff02::1 is above 2^127: bound as an int it would overflow HUGEINT.
        # The decimal-text encoder plus CAST(? AS UHUGEINT) is what makes it work.
        materialize(con, (V6SRC,), ({"ipv6.src": ("ff02::1",)}, {"ipv6.src": ("2001:db8::1",)}))
        assert select(con, V6SRC == "ff02::1") == {0}

    def test_list_contains_on_a_mixed_magnitude_column(self, con: DuckDBPyConnection) -> None:
        # A DAD Neighbour Solicitation: "::" and a solicited-node multicast
        # address in one ipv6.addr list — the pair that forces decimal text.
        materialize(
            con,
            (V6ADDR,),
            ({"ipv6.addr": ("::", "ff02::1:2")}, {"ipv6.addr": ("2001:db8::1",)}),
        )
        assert select(con, V6ADDR == "ff02::1:2") == {0}
        assert select(con, V6ADDR == "::") == {0}

    def test_ipv6_subnet_range_selects_the_prefix(self, con: DuckDBPyConnection) -> None:
        materialize(
            con,
            (V6SRC,),
            ({"ipv6.src": ("2001:db8::1",)}, {"ipv6.src": ("2001:db9::1",)}),
        )
        expr = V6SRC.in_([(IPv6Address("2001:db8::"), IPv6Address("2001:db8:ffff::ffff"))])
        assert select(con, expr) == {0}


class TestIPv4SubnetAgainstRealDuckDB:
    def test_between_over_the_integer_column(self, con: DuckDBPyConnection) -> None:
        materialize(
            con,
            (SRC,),
            (
                {"ip.src": ("10.0.0.1",)},
                {"ip.src": ("10.0.0.255",)},
                {"ip.src": ("10.0.1.0",)},
                {"ip.src": ("9.255.255.255",)},
                {},
            ),
        )
        expr = SRC.in_([(IPv4Address("10.0.0.0"), IPv4Address("10.0.0.255"))])
        assert select(con, expr) == {0, 1}


class TestNaNAgainstRealDuckDB:
    """The NaN rules, executed — DuckDB's total order is the whole reason.

    In DuckDB a stored NaN equals itself and sorts greater than everything, so
    an unguarded ``"col" > ?`` would select the NaN row for any literal. Rows:
    0 is NaN, 1 is 1.5, 2 has no x.value at all (NULL).
    """

    @pytest.fixture
    def seeded(self, con: DuckDBPyConnection) -> DuckDBPyConnection:
        materialize(con, (DVAL,), ({"x.value": ("nan",)}, {"x.value": ("1.5",)}, {}))
        return con

    def test_the_nan_row_really_holds_a_nan(self, seeded: DuckDBPyConnection) -> None:
        # The codec path is what puts it there: values.py parses "nan" with
        # float(), and DOUBLE's encoder is the identity.
        rows = seeded.execute(
            'SELECT frame_number, isnan("x_value") FROM main.pkts ORDER BY frame_number'
        ).fetchall()
        assert [(int(number), flag) for number, flag in rows] == [(0, True), (1, False), (2, None)]

    def test_gt_excludes_the_stored_nan(self, seeded: DuckDBPyConnection) -> None:
        # Without the guard this would be {0, 1}: NaN sorts greatest.
        assert select(seeded, DVAL > 0.0) == {1}

    def test_ge_excludes_the_stored_nan(self, seeded: DuckDBPyConnection) -> None:
        assert select(seeded, DVAL >= 0.0) == {1}

    def test_lt_needs_no_guard(self, seeded: DuckDBPyConnection) -> None:
        # NaN sorting greatest already makes NaN < 100.0 false.
        assert select(seeded, DVAL < 100.0) == {1}

    def test_between_needs_no_guard(self, seeded: DuckDBPyConnection) -> None:
        assert select(seeded, DVAL.in_([(0.0, 100.0)])) == {1}

    def test_nan_literal_matches_nothing(self, seeded: DuckDBPyConnection) -> None:
        # Even though DuckDB's own `NaN = NaN` is true, the compiled predicate is
        # FALSE, so the stored-NaN row is not selected.
        assert select(seeded, DVAL == NAN) == set()

    def test_negated_nan_literal_selects_every_row(self, seeded: DuckDBPyConnection) -> None:
        # NOT (FALSE) — the NaN row and the absent row included. Pinned
        # deliberately: this is the predicate backend's `not False`, and the
        # FALSE constant is never coalesced (#36) because a constant is never
        # NULL; no column is referenced at all.
        assert select(seeded, ~(DVAL == NAN)) == {0, 1, 2}

    def test_multi_ordered_comparison_guards_each_element(self, con: DuckDBPyConnection) -> None:
        materialize(
            con,
            (DVALS,),
            ({"x.values": ("nan",)}, {"x.values": ("nan", "1.5")}, {"x.values": ("0.5",)}, {}),
        )
        # Row 1 qualifies on its 1.5 alone; row 0's lone NaN must not qualify.
        assert select(con, DVALS > 1.0) == {1}


class TestBackfilledNullMultiColumn:
    """A multi column added after older rows back-fills NULL, not [].

    #26 encodes an absent multi field as [], but ALTER TABLE ... ADD COLUMN
    back-fills NULL on rows that predate the column. Negation over such a row
    must still match the predicate backend's "no occurrences".
    """

    def test_negated_comparison_includes_the_backfilled_row(self, con: DuckDBPyConnection) -> None:
        spec = column_spec(PORTS.name, PORTS.ftype, PORTS.multi)
        con.execute('INSERT INTO main.pkts ("frame_number") VALUES (0)')
        add_field_column(con, spec.column_name, spec.sql_type)
        con.execute(
            f'INSERT INTO main.pkts ("frame_number", "{spec.column_name}") VALUES (?, ?)',
            [1, spec.encode_raw(("443",))],
        )
        assert select(con, PORTS == 443) == {1}
        assert select(con, ~(PORTS == 443)) == {0}
        assert select(con, PORTS.present()) == {1}
        assert select(con, ~PORTS.present()) == {0}


class TestMultiOrderedComparisonAgainstRealDuckDB:
    """``len(list_filter(col, x -> x <op> ?)) > 0``, executed (issue #89).

    The float version is covered by ``TestNaNAgainstRealDuckDB``, where the
    ``NOT isnan(x)`` guard is the point. This is the *unguarded* shape — an
    integer LIST column — which was pinned only as a string, so nothing checked
    that DuckDB reads it as any-occurrence rather than all-occurrence.

    Absence reaches this shape in **two** forms and both are executed here: a
    row materialized while the field was absent holds ``[]``, and a row that
    predates the column holds the ``NULL`` its ``ALTER TABLE ... ADD COLUMN``
    back-filled. They are not interchangeable — ``[]`` makes the leaf ``FALSE``
    where ``NULL`` makes it ``NULL`` — so the negated form is where they could
    part company, and ``coalesce(..., FALSE)`` is what stops them.
    """

    @pytest.fixture
    def seeded(self, con: DuckDBPyConnection) -> DuckDBPyConnection:
        # Row 3 is materialized-absent ([]). The back-filled NULL row cannot be
        # produced this way — every row here is written after the column
        # exists — so it gets its own fixture below.
        materialize(
            con,
            (PORTS,),
            (
                {"tcp.port": ("80", "52034")},
                {"tcp.port": ("80", "443")},
                {"tcp.port": ("52034", "8080")},
                {},
            ),
        )
        return con

    @pytest.fixture
    def back_filled(self, con: DuckDBPyConnection) -> DuckDBPyConnection:
        """Row 0 predates the column (NULL), row 1 is absent ([]), row 2 has ports."""
        spec = column_spec(PORTS.name, PORTS.ftype, PORTS.multi)
        con.execute('INSERT INTO main.pkts ("frame_number") VALUES (0)')
        add_field_column(con, spec.column_name, spec.sql_type)
        for frame_number, raw in ((1, ()), (2, ("80", "443"))):
            con.execute(
                f'INSERT INTO main.pkts ("frame_number", "{spec.column_name}") VALUES (?, ?)',
                [frame_number, spec.encode_raw(raw)],
            )
        return con

    def test_gt_matches_on_any_occurrence(self, seeded: DuckDBPyConnection) -> None:
        # Row 0 qualifies on its 52034 alone, even though its 80 does not; row 1
        # has no occurrence above 1024, and row 3 has no occurrence at all.
        assert select(seeded, PORTS > 1024) == {0, 2}

    def test_lt_matches_on_any_occurrence(self, seeded: DuckDBPyConnection) -> None:
        # The mirror direction: rows 0 and 1 qualify on their 80, and row 2 —
        # which qualified above — does not, so this is not an all-occurrence
        # test read in reverse.
        assert select(seeded, PORTS < 1024) == {0, 1}

    def test_ge_and_le_include_the_endpoint_where_gt_and_lt_do_not(
        self, seeded: DuckDBPyConnection
    ) -> None:
        # 52034 is the highest occurrence anywhere and 80 the lowest, so the
        # inclusive forms select every row carrying one and the strict forms
        # select none — the boundary the lambda's operator decides.
        assert select(seeded, PORTS >= 52034) == {0, 2}
        assert select(seeded, PORTS > 52034) == set()
        assert select(seeded, PORTS <= 80) == {0, 1}
        assert select(seeded, PORTS < 80) == set()

    def test_the_empty_list_row_never_qualifies(self, seeded: DuckDBPyConnection) -> None:
        # list_filter over [] is [], so len(...) > 0 is false — not NULL, which
        # is why the negated form selects the row rather than dropping it.
        assert select(seeded, ~(PORTS > 1024)) == {1, 3}

    def test_the_two_absences_really_are_null_and_empty(
        self, back_filled: DuckDBPyConnection
    ) -> None:
        rows = back_filled.execute(
            'SELECT frame_number, "tcp_port" FROM main.pkts ORDER BY frame_number'
        ).fetchall()
        assert [(int(number), value) for number, value in rows] == [
            (0, None),
            (1, []),
            (2, [80, 443]),
        ]

    def test_positive_ordered_comparison_excludes_the_back_filled_row(
        self, back_filled: DuckDBPyConnection
    ) -> None:
        # len(list_filter(NULL, ...)) > 0 is NULL, which the WHERE clause filters
        # out — the same answer the other two backends give for an absent field,
        # and the reason a positive leaf needs no coalesce (#36).
        assert select(back_filled, PORTS > 100) == {2}

    def test_negated_ordered_comparison_includes_the_back_filled_row(
        self, back_filled: DuckDBPyConnection
    ) -> None:
        # The case three-valued SQL could get wrong: NOT (NULL) is NULL, so
        # without #36's coalesce the back-filled row would drop out where
        # Wireshark and the predicate backend include a packet missing the
        # field. Both absences must come back, and for the same reason.
        assert select(back_filled, ~(PORTS > 100)) == {0, 1}

    def test_the_null_the_coalesce_exists_for_is_real(
        self, back_filled: DuckDBPyConnection
    ) -> None:
        # The unguarded leaf, run directly: NULL for the back-filled row and
        # FALSE for the materialized-absent one. Proven rather than asserted
        # about, so the coalesce above is visibly load-bearing on this shape
        # too — presence is not the only place it matters.
        rows = back_filled.execute(
            'SELECT frame_number, len(list_filter("tcp_port", x -> x > 100)) > 0 '
            "FROM main.pkts ORDER BY frame_number"
        ).fetchall()
        assert [(int(number), flag) for number, flag in rows] == [
            (0, None),
            (1, False),
            (2, True),
        ]


class TestMultiPresenceAgainstRealDuckDB:
    """``len(coalesce(col, [])) > 0``, executed — the presence NULL-guard.

    Three states reach one column: a row that predates the column (back-filled
    NULL), a row materialized while the field was absent ([]), and a row
    carrying occurrences. Only the first needs the ``coalesce``, and without it
    ``len(NULL) > 0`` is NULL — so the row silently leaves *both* the presence
    and the negated-presence row set instead of exactly one of them.
    """

    @pytest.fixture
    def seeded(self, con: DuckDBPyConnection) -> DuckDBPyConnection:
        spec = column_spec(PORTS.name, PORTS.ftype, PORTS.multi)
        con.execute('INSERT INTO main.pkts ("frame_number") VALUES (0)')
        add_field_column(con, spec.column_name, spec.sql_type)
        for frame_number, raw in ((1, ()), (2, ("443",))):
            con.execute(
                f'INSERT INTO main.pkts ("frame_number", "{spec.column_name}") VALUES (?, ?)',
                [frame_number, spec.encode_raw(raw)],
            )
        return con

    def test_the_three_states_really_are_null_empty_and_populated(
        self, seeded: DuckDBPyConnection
    ) -> None:
        rows = seeded.execute(
            'SELECT frame_number, "tcp_port" FROM main.pkts ORDER BY frame_number'
        ).fetchall()
        assert [(int(number), value) for number, value in rows] == [
            (0, None),
            (1, []),
            (2, [443]),
        ]

    def test_presence_selects_only_the_populated_row(self, seeded: DuckDBPyConnection) -> None:
        assert select(seeded, PORTS.present()) == {2}

    def test_negated_presence_selects_both_absent_rows(self, seeded: DuckDBPyConnection) -> None:
        # Two-valued already, so #36 adds no coalesce here: the NULL row must
        # come back from the negation on the strength of the presence test's
        # own coalesce.
        assert select(seeded, ~PORTS.present()) == {0, 1}

    def test_the_null_the_coalesce_exists_for_is_real(self, seeded: DuckDBPyConnection) -> None:
        # The unguarded form, run directly: len(NULL) > 0 is NULL, so the
        # back-filled row answers neither the test nor its negation. Proven
        # rather than asserted about, so the coalesce is visibly load-bearing.
        rows = seeded.execute(
            'SELECT frame_number, len("tcp_port") > 0 FROM main.pkts ORDER BY frame_number'
        ).fetchall()
        assert [(int(number), flag) for number, flag in rows] == [
            (0, None),
            (1, False),
            (2, True),
        ]


class TestMatchesAgainstRealDuckDB:
    """matches executes as RE2, guarded (issue #36)."""

    def test_case_insensitive_like_the_other_backends(self, con: DuckDBPyConnection) -> None:
        materialize(
            con,
            (HOST,),
            ({"http.host": ("example.com",)}, {"http.host": ("EXAMPLE.COM",)}, {}),
        )
        assert select(con, HOST.matches("^ex.*com$")) == {0, 1}

    def test_absent_scalar_does_not_match(self, con: DuckDBPyConnection) -> None:
        materialize(con, (HOST,), ({"http.host": ("example.com",)}, {}))
        assert select(con, HOST.matches("com")) == {0}

    def test_negated_matches_includes_the_absent_row(self, con: DuckDBPyConnection) -> None:
        # The issue's named regression: `matches` on an absent field used to be
        # refused outright, and negation over a NULL column used to drop the row.
        materialize(con, (HOST,), ({"http.host": ("example.com",)}, {}))
        assert select(con, ~HOST.matches("com")) == {1}

    def test_multi_value_any_occurrence(self, con: DuckDBPyConnection) -> None:
        materialize(
            con,
            (QNAME,),
            (
                {"dns.qry.name": ("beta.io", "alpha.example")},
                {"dns.qry.name": ("beta.io", "gamma.net")},
                {},
            ),
        )
        assert select(con, QNAME.matches("^alpha")) == {0}

    def test_pattern_binds_and_destroys_nothing(self, con: DuckDBPyConnection) -> None:
        materialize(con, (HOST,), ({"http.host": ("a');x",)}, {"http.host": ("b",)}))
        assert select(con, HOST.matches("a'\\);x")) == {0}
        remaining = con.execute("SELECT count(*) FROM main.pkts").fetchone()
        assert remaining is not None
        assert remaining[0] == 2


class TestPortableTextGuard:
    """Text the three engines disagree on fails loudly instead of forking."""

    def test_non_ascii_value_raises(self, con: DuckDBPyConnection) -> None:
        materialize(con, (HOST,), ({"http.host": ("café",)},))
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, HOST.matches("^.{5}$"))

    def test_newline_value_raises(self, con: DuckDBPyConnection) -> None:
        materialize(con, (HOST,), ({"http.host": ("abc\n",)},))
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, HOST.matches("^abc$"))

    def test_vertical_tab_value_raises(self, con: DuckDBPyConnection) -> None:
        # The fourth divergence mechanism, and the only residual the reviewer's
        # exhaustive sweep found: RE2's \s is [\t\n\f\r ], while Python re and
        # PCRE2 also count U+000B. VT is pure ASCII and is not a newline, so it
        # passes the other two disjuncts — without chr(11) this query silently
        # returns the wrong row set instead of refusing.
        materialize(con, (HOST,), ({"http.host": ("a\x0bb",)},))
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, HOST.matches(r"a\sb"))

    def test_the_vertical_tab_divergence_the_guard_exists_for_is_real(
        self, con: DuckDBPyConnection
    ) -> None:
        # Proven directly against the two engines this file can run, so the
        # chr(11) disjunct is visibly load-bearing rather than defensive noise.
        # Wireshark's PCRE2 sides with Python (reproduced on tshark 4.6.7 with
        # -Y 'http.host matches "a\\sb"'), which is why RE2 is the odd one out.
        row = con.execute("SELECT regexp_matches(?, ?, 'i')", ["a\x0bb", r"a\sb"]).fetchone()
        assert row is not None
        assert row[0] is False
        assert re.search(rb"a\sb", b"a\x0bb") is not None

    def test_error_message_names_the_column_and_the_pcap_path(
        self, con: DuckDBPyConnection
    ) -> None:
        materialize(con, (HOST,), ({"http.host": ("café",)},))
        with pytest.raises(duckdb.Error, match="http_host"):
            select(con, HOST.matches("x"))
        with pytest.raises(duckdb.Error, match="Capture"):
            select(con, HOST.matches("x"))

    def test_ascii_rows_beside_a_null_row_are_fine(self, con: DuckDBPyConnection) -> None:
        materialize(con, (HOST,), ({"http.host": ("abc",)}, {}))
        assert select(con, HOST.matches("^abc$")) == {0}

    def test_multi_value_guard_fires_per_occurrence(self, con: DuckDBPyConnection) -> None:
        materialize(con, (QNAME,), ({"dns.qry.name": ("ok", "café")},))
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, QNAME.matches("ok"))

    def test_the_divergence_the_guard_exists_for_is_real(self, con: DuckDBPyConnection) -> None:
        # Documented, not fixed: RE2 counts runes. Proven directly, so the guard
        # is visibly load-bearing rather than defensive noise.
        row = con.execute("SELECT regexp_matches('café', '^.{5}$')").fetchone()
        assert row is not None
        assert row[0] is False
        assert re.search(b"^.{5}$", "café".encode()) is not None


def seed_case(
    connection: DuckDBPyConnection, case: Case, *, only: frozenset[int] | None = None
) -> None:
    """Materialize one semantics case's packets as pkts rows.

    Every field the expression mentions becomes a column through the real
    #25/#26 path — column_spec for the name/type/codec, add_field_column for the
    ALTER — except the skeleton columns pkts is born with (frame.time is one).

    ``only`` restricts the seeding to those row indices, keeping each row's
    ``frame_number`` — that is what lets :func:`assert_guard_rows_are_exact`
    ask which individual rows trip the portable-text guard.
    """
    specs: dict[str, ColumnSpec] = {}
    for ref in field_refs(case.expr):
        if ref.name not in specs:
            specs[ref.name] = column_spec(ref.name, ref.ftype, ref.multi)
    for spec in specs.values():
        if spec.column_name not in SKELETON_COLUMNS:
            add_field_column(connection, spec.column_name, spec.sql_type)
    columns = ", ".join(f'"{spec.column_name}"' for spec in specs.values())
    placeholders = ", ".join("?" for _ in specs)
    for index, (packet, _expected) in enumerate(case.rows):
        if only is not None and index not in only:
            continue
        row: list[Any] = [index]
        row.extend(spec.encode_raw(packet.get_raw(spec.abbrev)) for spec in specs.values())
        connection.execute(
            f'INSERT INTO main.pkts ("frame_number", {columns}) VALUES (?, {placeholders})',
            row,
        )


@contextmanager
def fresh_connection() -> Iterator[DuckDBPyConnection]:
    """A second in-memory workspace, for seeding one subset of a case's rows."""
    connection: DuckDBPyConnection = duckdb.connect(":memory:")
    create_schema(connection)
    try:
        yield connection
    finally:
        connection.close()


def assert_guard_rows_are_exact(case: Case) -> None:
    """``sql_guard_rows`` names *which* rows trip the guard, so check which.

    Testing the frozenset for truthiness (what this did before issue #102) let
    ``frozenset({99})`` pass while asserting nothing: any listed index at all
    turned the case into "expect a raise". Here each listed row is seeded alone
    and must raise, and every unlisted row is seeded together and must return
    the shared expectation cleanly — so an index that is out of range, points
    at a portable row, or omits an unportable one fails.
    """
    indices = frozenset(range(len(case.rows)))
    assert case.sql_guard_rows <= indices, (
        f"{case.id}: sql_guard_rows {sorted(case.sql_guard_rows - indices)} "
        f"index rows the case does not have"
    )
    for index in sorted(case.sql_guard_rows):
        with fresh_connection() as connection:
            seed_case(connection, case, only=frozenset({index}))
            with pytest.raises(duckdb.Error, match="pure-ASCII"):
                select(connection, case.expr)
    portable = indices - case.sql_guard_rows
    with fresh_connection() as connection:
        seed_case(connection, case, only=portable)
        expected = {index for index in portable if case.rows[index][1]}
        assert select(connection, case.expr) == expected


def _case_id(case: Case) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_sql_backend_matches_the_other_two(con: DuckDBPyConnection, case: Case) -> None:
    """One table, three backends, one row set (issue #36).

    Rows are seeded through the real materialization codecs, so an absent scalar
    lands as NULL and an absent multi-value field as []. A backend is allowed to
    differ from the shared expectation only by refusing to compile
    (``sql_refusal``) or by raising the portable-text guard on the rows
    ``sql_guard_rows`` names — never by returning a different row set.
    """
    if case.sql_refusal is not None:
        with pytest.raises(UnsupportedSqlExprError, match=case.sql_refusal):
            compile_sql(case.expr)
        return
    seed_case(con, case)
    if case.sql_guard_rows:
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, case.expr)
        # ...and the indices are the claim, not just the fact that there are
        # some: which rows trip the guard is asserted row by row (issue #102).
        assert_guard_rows_are_exact(case)
        return
    expected = {index for index, (_packet, hit) in enumerate(case.rows) if hit}
    assert select(con, case.expr) == expected


def test_no_case_carries_both_escape_hatches() -> None:
    """A case is refused, or guarded, or compared — never two of the three."""
    for case in CASES:
        assert not (case.sql_refusal is not None and case.sql_guard_rows), case.id


def test_escape_hatches_are_still_needed() -> None:
    """A hatch that has stopped being needed must be deleted, not kept.

    Otherwise the table would quietly exempt a case that now agrees.
    """
    for case in CASES:
        if case.sql_refusal is not None:
            with pytest.raises(UnsupportedSqlExprError):
                compile_sql(case.expr)
