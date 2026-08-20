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

from collections.abc import Iterator
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


def seed_case(connection: DuckDBPyConnection, case: Case) -> None:
    """Materialize one semantics case's packets as pkts rows.

    Every field the expression mentions becomes a column through the real
    #25/#26 path — column_spec for the name/type/codec, add_field_column for the
    ALTER — except the skeleton columns pkts is born with (frame.time is one).
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
        row: list[Any] = [index]
        row.extend(spec.encode_raw(packet.get_raw(spec.abbrev)) for spec in specs.values())
        connection.execute(
            f'INSERT INTO main.pkts ("frame_number", {columns}) VALUES (?, {placeholders})',
            row,
        )


def _case_id(case: Case) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_sql_backend_matches_the_other_two(con: DuckDBPyConnection, case: Case) -> None:
    """One table, three backends, one row set (issue #36).

    Rows are seeded through the real materialization codecs, so an absent scalar
    lands as NULL and an absent multi-value field as []. A backend is allowed to
    differ from the shared expectation only by refusing to compile
    (``sql_refusal``) or by raising the portable-text guard
    (``sql_guard_rows``) — never by returning a different row set.
    """
    if case.sql_refusal is not None:
        with pytest.raises(UnsupportedSqlExprError, match=case.sql_refusal):
            compile_sql(case.expr)
        return
    seed_case(con, case)
    if case.sql_guard_rows:
        with pytest.raises(duckdb.Error, match="pure-ASCII"):
            select(con, case.expr)
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
