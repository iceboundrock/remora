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

from remora.compile.sql import compile_sql
from remora.expr import Expr
from remora.fields import FieldRef
from remora.workspace.schema import add_field_column, create_schema
from remora.workspace.types import column_spec

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
        assert select(con, hostile == HOST) == {0}
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
        subprocess.run([sys.executable, "-c", code], check=True, timeout=60)
