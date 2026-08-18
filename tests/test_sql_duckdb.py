"""SQL backend tests that run against a real DuckDB (issue #29).

Gated on duckdb like tests/test_workspace_types.py: the shape tests in
tests/test_sql.py must keep running without it, but hostile literals, the
FT_IPv6 CAST and the semantics-table equivalence suite only mean anything when
DuckDB actually executes them.

No DDL is written here: tables come from remora.workspace.schema, which is the
single source of the workspace layout.
"""

from __future__ import annotations

import subprocess
import sys
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


class TestImportPurity:
    def test_importing_the_backend_does_not_import_duckdb(self) -> None:
        # The compiler emits plain strings and plain Python values; importing it
        # must not pull the optional dependency in, even where it is installed.
        code = (
            "import sys\n"
            "import remora.compile.sql\n"
            "assert 'duckdb' not in sys.modules, 'duckdb imported by the sql backend'\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], check=False, timeout=60, capture_output=True, text=True
        )
        assert proc.returncode == 0, proc.stderr


#: Cases the SQL backend refuses outright, with the reason it refuses them.
#: Values are regex-safe fragments for pytest.raises(match=...) assertions.
SQL_UNSUPPORTED_CASES: dict[str, str] = {
    "matches-case-insensitive": "RE2",
    "matches-byte-oriented": "RE2",
    "matches-multi-value-any-occurrence": "RE2",
    "not-matches-absent-is-true": "RE2",
    "contains-bytes": "BLOB",
}

#: Cases that compile but select a different row set, because SQL is
#: three-valued and an absent scalar column is NULL. Issue #29 states this
#: behavior and explicitly does not harmonize it; each entry names the rows the
#: SQL backend drops so the divergence is asserted, not waved through.
SQL_NULL_DIVERGENT_CASES: dict[str, set[int]] = {
    # Row 2 has no ip.src, so ("ip_src" = ?) is NULL, NOT (NULL) is NULL and the
    # row is excluded; the predicate backend's `not False` includes it.
    "nested-not-over-or-conjoined": {0},
}


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
def test_sql_backend_matches_the_predicate_backend(con: DuckDBPyConnection, case: Case) -> None:
    """Acceptance criterion 5: identical row sets for every covered operator.

    ONE table, three backends. The rows are seeded through the real
    materialization codecs, so an absent scalar lands as NULL and an absent
    multi-value field as [] — the shapes the SQL backend's semantics are stated
    against.
    """
    reason = SQL_UNSUPPORTED_CASES.get(case.id)
    if reason is not None:
        with pytest.raises(UnsupportedSqlExprError, match=reason):
            compile_sql(case.expr)
        return
    seed_case(con, case)
    expected = {index for index, (_packet, hit) in enumerate(case.rows) if hit}
    divergent = SQL_NULL_DIVERGENT_CASES.get(case.id)
    assert select(con, case.expr) == (expected if divergent is None else divergent)


def test_coverage_maps_name_real_cases() -> None:
    """Neither coverage map may carry an id the shared table no longer has."""
    ids = {case.id for case in CASES}
    assert set(SQL_UNSUPPORTED_CASES) <= ids
    assert set(SQL_NULL_DIVERGENT_CASES) <= ids
    assert not (set(SQL_UNSUPPORTED_CASES) & set(SQL_NULL_DIVERGENT_CASES))


def test_divergent_cases_really_do_diverge() -> None:
    """A divergent entry that has stopped diverging must be deleted, not kept.

    Otherwise the map would quietly assert a wrong row set forever.
    """
    by_id = {case.id: case for case in CASES}
    for case_id, rows in SQL_NULL_DIVERGENT_CASES.items():
        case = by_id[case_id]
        expected = {index for index, (_packet, hit) in enumerate(case.rows) if hit}
        assert rows != expected, f"{case_id} no longer diverges; drop it from the map"
