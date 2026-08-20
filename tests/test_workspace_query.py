"""Query tests over a hand-seeded workspace (issue #35).

No tshark anywhere here: rows are inserted through the real #25/#26 path
(``column_spec`` for the name/type/codec, ``add_field_column`` for the ALTER,
``register_fields`` for the catalog row), so the columns and the ``meta.fields``
registry are exactly what a materialization would have left behind. The
tshark-driven half — the Capture/Query parity check — lives in
``tests/integration/workspace/``.

Gated on duckdb like the other workspace suites; the import-purity assertions
live in ``tests/test_workspace_import_purity.py``, which deliberately carries no
gate.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import assert_type

import remora.workspace.materialize as materialize_module
import remora.workspace.query as query_module
from remora import IP, TCP
from remora.compile.sql import UnsupportedSqlExprError
from remora.fields import FieldNotProjectedError, FieldRef
from remora.workspace import (
    ColumnSpec,
    FieldDeclarationMismatchError,
    FieldNotMaterializedError,
    FieldRecord,
    Query,
    Row,
    Workspace,
    add_field_column,
    column_spec,
    iter_ddl,
    register_fields,
    to_db_timestamp,
)
from remora.workspace.errors import WorkspaceAliasError
from remora.workspace.naming import SKELETON_ABBREVS, SKELETON_COLUMNS, column_name

pytest.importorskip("duckdb")

HOST = FieldRef[str]("http.host", "FT_STRING", False)
V6SRC = FieldRef[IPv6Address]("ipv6.src", "FT_IPv6", False)
V6ADDR = FieldRef[IPv6Address]("ipv6.addr", "FT_IPv6", True)

# There is no generated FRAME protocol class — "frame" is not in codegen.toml's
# [generate].protocols and no extras package ships it — so the row key is
# referenced with hand-built refs, exactly as a user would have to. The ftypes
# are the two legitimate spellings: tshark -G fields declares frame.number as
# FT_UINT32, while materialize.py's insert-side skeleton spec calls it
# FT_FRAMENUM. Both map to UINTEGER with identity codecs.
FRAME_NUMBER = FieldRef[int]("frame.number", "FT_UINT32", False)
FRAME_NUMBER_ALT = FieldRef[int]("frame.number", "FT_FRAMENUM", False)
FRAME_TIME = FieldRef[datetime]("frame.time", "FT_ABSOLUTE_TIME", False)
FRAME_TIME_EPOCH = FieldRef[datetime]("frame.time_epoch", "FT_ABSOLUTE_TIME", False)

BASE_TIME = datetime(2023, 11, 14, 22, 15, tzinfo=timezone.utc)

#: tcp_mixed.pcap's five frames, as raw tshark occurrences. Frame 5 is ARP (no
#: ip.*, no tcp.*), so it exercises absent scalar and absent multi at once.
PACKETS: tuple[dict[str, tuple[str, ...]], ...] = (
    {"ip.src": ("10.0.0.1",), "tcp.port": ("51234", "443")},
    {"ip.src": ("10.0.0.2",), "tcp.port": ("443", "51234")},
    {"ip.src": ("10.0.0.3",), "tcp.port": ("52000", "8080")},
    {"ip.src": ("10.0.0.1",)},
    {},
)


def seed(
    workspace: Workspace,
    fields: Sequence[FieldRef[Any]],
    rows: Sequence[Mapping[str, tuple[str, ...]]],
) -> None:
    """Materialize ``fields`` by hand and insert one pkts row per occurrence map."""
    specs = [column_spec(ref.name, ref.ftype, ref.multi) for ref in fields]
    columns = ", ".join(f'"{spec.column_name}"' for spec in specs)
    placeholders = ", ".join("?" for _ in specs)
    with workspace.write() as con:
        for spec in specs:
            add_field_column(con, spec.column_name, spec.sql_type)
        register_fields(
            con,
            [
                FieldRecord(
                    abbrev=spec.abbrev,
                    column_name=spec.column_name,
                    ftype=spec.ftype,
                    multi=spec.multi,
                    column_type=spec.sql_type,
                    materialized_at=BASE_TIME,
                )
                for spec in specs
            ],
        )
        for index, raw in enumerate(rows, start=1):
            values: list[Any] = [index, to_db_timestamp(BASE_TIME + timedelta(seconds=index))]
            values.extend(spec.encode_raw(raw.get(spec.abbrev, ())) for spec in specs)
            con.execute(
                f'INSERT INTO main.pkts ("frame_number", "frame_time"{"," if specs else ""}'
                f"{columns}) VALUES (?, ?{',' if specs else ''}{placeholders})",
                values,
            )


@pytest.fixture
def ws(tmp_path: Path) -> Iterator[Workspace]:
    """An rw workspace holding tcp_mixed's packets under ip.src / tcp.port."""
    with Workspace(tmp_path / "ws.duckdb", mode="rw") as workspace:
        seed(workspace, (IP.src, TCP.port), PACKETS)
        yield workspace


def frames(query: Query) -> list[int | None]:
    """Frame numbers a query selects, in row order."""
    return [row.frame_number for row in query]


def ddl_column_types(table: str) -> dict[str, str]:
    """Column name -> declared SQL type, parsed out of ``schema.iter_ddl()``.

    Reads the layout rather than restating it, so schema.py's statement stays
    the one authority for the skeleton's column types. Deliberately keyed on the
    table name and the opening parenthesis rather than on the statement head:
    ``tests/test_workspace_schema.py`` asserts that no file outside schema.py
    contains a DDL head at all, and a literal here would break that invariant
    for a string this function never needs.
    """
    marker = f" {table} ("
    statement = next(text for text in iter_ddl() if marker in text)
    body = statement.split(marker, 1)[1].rsplit(")", 1)[0]
    columns: dict[str, str] = {}
    for line in body.splitlines():
        parts = line.strip().rstrip(",").split(maxsplit=1)
        if len(parts) == 2:
            columns[parts[0]] = parts[1].strip()
    return columns


def materialize_skeleton_specs() -> tuple[ColumnSpec, ...]:
    """The row-key specs the *write* path inserts through (#31)."""
    return (materialize_module._FRAME_NUMBER_SPEC, materialize_module._FRAME_TIME_SPEC)


class TestConstruction:
    def test_workspace_query_returns_a_query(self, ws: Workspace) -> None:
        query = ws.query()
        assert isinstance(query, Query)

    def test_filter_and_select_are_immutable(self, ws: Workspace) -> None:
        base = ws.query()
        narrowed = base.filter(TCP.port == 443)
        projected = narrowed.select(IP.src)
        assert narrowed is not base
        assert projected is not narrowed
        # The original still selects every row and projects every field.
        assert frames(base) == [1, 2, 3, 4, 5]
        assert frames(narrowed) == [1, 2]

    def test_repeated_filters_are_anded(self, ws: Workspace) -> None:
        query = ws.query().filter(TCP.port == 443).filter(IP.src == "10.0.0.1")
        assert frames(query) == [1]

    def test_multiple_terms_in_one_call_are_anded(self, ws: Workspace) -> None:
        query = ws.query().filter(TCP.port == 443, IP.src == "10.0.0.2")
        assert frames(query) == [2]


class TestFieldValidation:
    def test_unmaterialized_filter_field_raises_before_any_sql(self, ws: Workspace) -> None:
        expected = "field http.host is not materialized — re-materialize including it"
        with pytest.raises(FieldNotMaterializedError, match=re.escape(expected)):
            list(ws.query().filter(HOST == "example.com"))

    def test_unmaterialized_select_field_raises(self, ws: Workspace) -> None:
        expected = "field http.host is not materialized — re-materialize including it"
        with pytest.raises(FieldNotMaterializedError, match=re.escape(expected)):
            list(ws.query().select(HOST))

    def test_every_missing_field_is_named(self, ws: Workspace) -> None:
        other = FieldRef[str]("dns.qry.name", "FT_STRING", True)
        with pytest.raises(FieldNotMaterializedError) as info:
            list(ws.query().filter(HOST == "example.com").select(other))
        message = str(info.value)
        assert "http.host" in message
        assert "dns.qry.name" in message
        assert "are not materialized" in message

    def test_message_never_mentions_a_missing_column(self, ws: Workspace) -> None:
        # The whole point of the check: never a raw DuckDB "column not found".
        with pytest.raises(FieldNotMaterializedError) as info:
            list(ws.query().filter(HOST == "example.com"))
        assert "column" not in str(info.value).lower()

    def test_validation_runs_before_the_expression_is_compiled(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Ordering, pinned directly: a compiler that is never called cannot have
        # produced SQL for DuckDB to reject.
        def explode(expr: object) -> None:
            raise AssertionError("compile_sql must not run before field validation")

        monkeypatch.setattr("remora.compile.sql.compile_sql", explode)
        with pytest.raises(FieldNotMaterializedError):
            list(ws.query().filter(HOST == "example.com"))

    def test_arrow_validates_too(self, ws: Workspace) -> None:
        pytest.importorskip("pyarrow")
        with pytest.raises(FieldNotMaterializedError):
            ws.query().select(HOST).arrow()

    def test_sql_validates_too(self, ws: Workspace) -> None:
        with pytest.raises(FieldNotMaterializedError):
            ws.query().filter(HOST == "example.com").sql()

    def test_skeleton_fields_are_never_missing(self, ws: Workspace) -> None:
        # frame.number / frame.time are the pkts row key: materializing them is
        # a no-op, so referencing them must not look unmaterialized.
        assert frames(ws.query().filter(FRAME_NUMBER >= 4)) == [4, 5]
        assert frames(ws.query().select(FRAME_NUMBER)) == [1, 2, 3, 4, 5]
        assert frames(ws.query().filter(FRAME_TIME >= BASE_TIME)) == [1, 2, 3, 4, 5]

    def test_frame_time_epoch_is_not_a_skeleton_abbrev(self, ws: Workspace) -> None:
        # Only frame.number / frame.time name the row key. frame.time_epoch is
        # the abbrev #31 asks *tshark* for; a caller requesting it gets an
        # ordinary frame_time_epoch column, so unmaterialized it is missing like
        # any other field rather than silently resolving to the row key.
        expected = "field frame.time_epoch is not materialized — re-materialize including it"
        with pytest.raises(FieldNotMaterializedError, match=re.escape(expected)):
            list(ws.query().select(FRAME_TIME_EPOCH))


class TestFilterExecution:
    def test_scalar_equality(self, ws: Workspace) -> None:
        assert frames(ws.query().filter(IP.src == "10.0.0.1")) == [1, 4]

    def test_multi_value_any_occurrence(self, ws: Workspace) -> None:
        assert frames(ws.query().filter(TCP.port == 443)) == [1, 2]

    def test_membership_range_is_the_subnet_predicate(self, ws: Workspace) -> None:
        query = ws.query().filter(IP.src.in_([(IPv4Address("10.0.0.1"), IPv4Address("10.0.0.2"))]))
        assert frames(query) == [1, 2, 4]

    def test_presence(self, ws: Workspace) -> None:
        assert frames(ws.query().filter(IP.src.present())) == [1, 2, 3, 4]

    def test_no_filter_returns_every_row_in_frame_order(self, ws: Workspace) -> None:
        assert frames(ws.query()) == [1, 2, 3, 4, 5]

    def test_hostile_literal_is_bound_not_interpolated(self, tmp_path: Path) -> None:
        with Workspace(tmp_path / "hostile.duckdb", mode="rw") as workspace:
            seed(
                workspace,
                (HOST,),
                ({"http.host": ("'; DROP TABLE pkts; --",)}, {"http.host": ("example.com",)}),
            )
            assert frames(workspace.query().filter(HOST == "'; DROP TABLE pkts; --")) == [1]
            assert frames(workspace.query()) == [1, 2]

    def test_unsupported_expression_propagates_unchanged(self, tmp_path: Path) -> None:
        # Documented refusal of the SQL backend (#29/#36), not a Query concern:
        # `matches` itself compiles now, but a lookaround is a pattern DuckDB's
        # RE2 engine has no operator for.
        with Workspace(tmp_path / "re2.duckdb", mode="rw") as workspace:
            seed(workspace, (HOST,), ({"http.host": ("example.com",)},))
            with pytest.raises(UnsupportedSqlExprError, match="RE2"):
                list(workspace.query().filter(HOST.matches("a(?=b)")))

    def test_matches_runs_through_the_query_path(self, tmp_path: Path) -> None:
        # The other half of #36: a portable pattern on ASCII text compiles and
        # executes, so a workspace query answers `matches` at all.
        with Workspace(tmp_path / "matches.duckdb", mode="rw") as workspace:
            seed(
                workspace,
                (HOST,),
                ({"http.host": ("EXAMPLE.COM",)}, {"http.host": ("other.org",)}, {}),
            )
            assert frames(workspace.query().filter(HOST.matches("^ex.*com$"))) == [1]
            assert frames(workspace.query().filter(~HOST.matches("com"))) == [2, 3]


class TestSql:
    def test_sql_is_inspectable_and_parameterized(self, ws: Workspace) -> None:
        sql, params = ws.query().filter(TCP.port == 443).sql()
        assert "FROM main.pkts" in sql
        assert "ORDER BY" in sql
        assert params == (443,)
        assert "443" not in sql

    def test_select_narrows_the_projection(self, ws: Workspace) -> None:
        sql, _params = ws.query().select(IP.src).sql()
        assert '"ip_src"' in sql
        assert '"tcp_port"' not in sql
        # The row key is always projected: it is what a Row is identified by.
        assert '"frame_number"' in sql
        assert '"frame_time"' in sql

    def test_default_projection_covers_every_materialized_field(self, ws: Workspace) -> None:
        sql, _params = ws.query().sql()
        assert '"ip_src"' in sql
        assert '"tcp_port"' in sql

    def test_select_accumulates(self, ws: Workspace) -> None:
        sql, _params = ws.query().select(IP.src).select(TCP.port).sql()
        assert '"ip_src"' in sql
        assert '"tcp_port"' in sql


class TestRowAccess:
    def test_typed_scalar_and_multi_access(self, ws: Workspace) -> None:
        row = next(iter(ws.query().filter(IP.src == "10.0.0.1")))
        src = row.get(IP.src)
        ports = row.get_all(TCP.port)
        # assert_type before the runtime asserts: an equality assert narrows.
        assert_type(src, IPv4Address | None)
        assert_type(ports, tuple[int, ...])
        assert src == IPv4Address("10.0.0.1")
        assert ports == (51234, 443)

    def test_absent_scalar_is_none_and_absent_multi_is_empty(self, ws: Workspace) -> None:
        rows = list(ws.query())
        arp = rows[4]
        assert arp.get(IP.src) is None
        assert arp.get_all(TCP.port) == ()

    def test_row_key_is_typed_and_utc(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        number = row.frame_number
        stamp = row.frame_time
        assert_type(number, int | None)
        assert_type(stamp, datetime | None)
        assert number == 1
        assert stamp == BASE_TIME + timedelta(seconds=1)
        assert stamp is not None
        assert stamp.tzinfo is timezone.utc

    def test_scalar_accessor_refuses_a_multi_field(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        with pytest.raises(ValueError, match=r"get_all"):
            row.get(TCP.port)

    def test_multi_accessor_refuses_a_scalar_field(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        with pytest.raises(ValueError, match=r"\bget\b"):
            row.get_all(IP.src)

    def test_field_outside_the_projection_raises(self, ws: Workspace) -> None:
        row = next(iter(ws.query().select(IP.src)))
        with pytest.raises(FieldNotProjectedError, match=re.escape("tcp.port")):
            row.get_all(TCP.port)

    def test_repr_names_the_frame(self, ws: Workspace) -> None:
        assert "1" in repr(next(iter(ws.query())))

    def test_rows_are_row_instances(self, ws: Workspace) -> None:
        assert all(isinstance(row, Row) for row in ws.query())


class TestRowKeyIsReachableByReference:
    """The row key is always projected, so Row.get() must reach it.

    Regression: it used to be stripped from the projection *and* exempted from
    validation, so it never entered Row._specs and `row.get(<frame.number ref>)`
    raised FieldNotProjectedError — advising a `.select()` that failed the same
    way.
    """

    def test_frame_number_by_reference(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        number = row.get(FRAME_NUMBER)
        assert_type(number, int | None)
        assert number == 1
        assert number == row.frame_number

    def test_frame_time_by_reference(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        stamp = row.get(FRAME_TIME)
        assert_type(stamp, datetime | None)
        assert stamp == BASE_TIME + timedelta(seconds=1)
        assert stamp is not None
        assert stamp.tzinfo is timezone.utc
        assert stamp == row.frame_time

    def test_either_ftype_spelling_of_frame_number_works(self, ws: Workspace) -> None:
        # FT_UINT32 (tshark's own declaration) and FT_FRAMENUM (#31's insert-side
        # spec) both map to UINTEGER with identity codecs, so neither can decode
        # wrongly and the declaration check accepts both for the row key — on
        # the compile path and the row-access path alike.
        row = next(iter(ws.query()))
        assert row.get(FRAME_NUMBER_ALT) == 1
        assert row.get(FRAME_NUMBER) == 1
        assert frames(ws.query().filter(FRAME_NUMBER_ALT >= 4)) == [4, 5]
        assert frames(ws.query().select(FRAME_NUMBER_ALT)) == [1, 2, 3, 4, 5]

    def test_reachable_under_a_narrowed_select(self, ws: Workspace) -> None:
        row = next(iter(ws.query().select(IP.src)))
        assert row.get(FRAME_NUMBER) == 1
        assert row.get(FRAME_TIME) is not None

    def test_selecting_the_row_key_explicitly_works(self, ws: Workspace) -> None:
        row = next(iter(ws.query().select(FRAME_NUMBER, FRAME_TIME)))
        assert row.get(FRAME_NUMBER) == 1
        assert row.get(FRAME_TIME) is not None
        # Selected explicitly it must not become a second column.
        sql, _params = ws.query().select(FRAME_NUMBER, FRAME_TIME).sql()
        assert sql.count('"frame_number"') == 1
        assert sql.count('"frame_time"') == 1

    def test_the_row_key_is_scalar(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        with pytest.raises(ValueError, match=r"scalar field; read it with get\(\)"):
            row.get_all(FRAME_NUMBER)
        with pytest.raises(ValueError, match=r"scalar field; read it with get\(\)"):
            row.get_all(FRAME_TIME)

    def test_a_multi_declared_row_key_reference_is_refused(self, ws: Workspace) -> None:
        # It would compile to list_contains("frame_number", ?) against BIGINT
        # and reach DuckDB as a binder error.
        bogus = FieldRef[int]("frame.number", "FT_UINT32", True)
        with pytest.raises(FieldDeclarationMismatchError, match="row key"):
            list(ws.query().filter(bogus == 1))

    def test_arrow_still_names_the_row_key_columns_once(self, ws: Workspace) -> None:
        pytest.importorskip("pyarrow")
        table = ws.query().select(FRAME_NUMBER, IP.src).arrow()
        assert table.column_names == ["frame_number", "frame_time", "ip_src"]

    def test_the_skeleton_tables_agree_with_the_naming_policy(self) -> None:
        # Three module-level tables describe the row key; a field added to one
        # and forgotten in another would silently lose its check or its column.
        assert set(query_module._ROW_KEY_SPECS_BY_ABBREV) == SKELETON_ABBREVS
        assert set(query_module._ROW_KEY_FTYPES) == SKELETON_ABBREVS
        for spec in query_module._ROW_KEY_SPECS:
            assert spec.column_name == column_name(spec.abbrev)
            assert spec.column_name in SKELETON_COLUMNS
            # The declared ftype must itself be an accepted spelling.
            assert spec.ftype in query_module._ROW_KEY_FTYPES[spec.abbrev]

    def test_row_key_column_types_come_from_the_ddl(self) -> None:
        """schema.py's layout is the authority for the skeleton column types.

        They are the one thing types.py cannot supply — frame_number is BIGINT,
        not the UINTEGER its ftype maps to — so query.py and materialize.py both
        state them, with a comment pointing here. Rather than trust the comments,
        this parses the live statement out of ``iter_ddl()`` and holds all three
        to it, so a change to the pkts skeleton fails loudly instead of silently
        disagreeing with the read and write paths.
        """
        declared = ddl_column_types("main.pkts")
        assert declared == {"frame_number": "BIGINT", "frame_time": "TIMESTAMP"}
        assert set(declared) == SKELETON_COLUMNS
        for spec in (*query_module._ROW_KEY_SPECS, *materialize_skeleton_specs()):
            assert spec.sql_type == declared[spec.column_name], spec.abbrev


class TestRowKeyDeclarationIsChecked:
    """The row key's ftype is checked, not only its multiplicity.

    Regression: the skeleton carve-out used to accept *any* scalar ftype, so a
    `frame.number` reference declared FT_IPv4 coerced "10.0.0.1" to 167772161
    and silently matched nothing, and a `frame.time` reference declared
    FT_UINT32 leaked a raw DuckDB ConversionException.
    """

    @pytest.mark.parametrize(
        ("ftype", "literal"),
        [("FT_STRING", "1"), ("FT_IPv4", "10.0.0.1"), ("FT_ABSOLUTE_TIME", BASE_TIME)],
    )
    def test_frame_number_rejects_other_ftypes(
        self, ws: Workspace, ftype: str, literal: object
    ) -> None:
        bogus = FieldRef[Any]("frame.number", ftype, False)
        with pytest.raises(FieldDeclarationMismatchError) as info:
            list(ws.query().filter(bogus == literal))
        message = str(info.value)
        assert "frame.number is the pkts row key" in message
        assert "FT_FRAMENUM or FT_UINT32" in message
        assert ftype in message

    @pytest.mark.parametrize(
        ("ftype", "literal"),
        [("FT_UINT32", 5), ("FT_RELATIVE_TIME", timedelta(seconds=5)), ("FT_STRING", "x")],
    )
    def test_frame_time_rejects_other_ftypes(
        self, ws: Workspace, ftype: str, literal: object
    ) -> None:
        bogus = FieldRef[Any]("frame.time", ftype, False)
        with pytest.raises(FieldDeclarationMismatchError) as info:
            list(ws.query().filter(bogus == literal))
        message = str(info.value)
        assert "frame.time is the pkts row key" in message
        assert "FT_ABSOLUTE_TIME" in message

    def test_frame_number_rejects_a_merely_compatible_ftype(self, ws: Workspace) -> None:
        # FT_UINT24 also maps to UINTEGER with identity codecs, but nothing in
        # this tree declares the row key that way: the accepted set is closed,
        # not derived from the column type.
        bogus = FieldRef[int]("frame.number", "FT_UINT24", False)
        with pytest.raises(FieldDeclarationMismatchError, match="FT_UINT24"):
            list(ws.query().filter(bogus == 1))

    def test_wrong_row_key_ftype_is_refused_on_select_too(self, ws: Workspace) -> None:
        bogus = FieldRef[str]("frame.number", "FT_STRING", False)
        with pytest.raises(FieldDeclarationMismatchError, match="row key"):
            list(ws.query().select(bogus))

    def test_wrong_row_key_ftype_is_refused_by_row_access(self, ws: Workspace) -> None:
        row = next(iter(ws.query()))
        with pytest.raises(FieldDeclarationMismatchError, match="row key"):
            row.get(FieldRef[str]("frame.number", "FT_STRING", False))
        with pytest.raises(FieldDeclarationMismatchError, match="row key"):
            row.get(FieldRef[int]("frame.time", "FT_UINT32", False))


class TestRowAccessChecksTheDeclaration:
    """Row.get / get_all validate the whole reference, not just its name.

    Regression: `_spec()` looked up by `field.name` alone, so a same-name
    reference with a different ftype returned a value through an accessor mypy
    had typed for a different one, and a multiplicity disagreement was reported
    as the caller's *accessor* being wrong rather than their declaration.
    """

    def test_same_name_wrong_ftype_is_refused(self, ws: Workspace) -> None:
        # Statically this accessor promises `str | None`; it used to hand back
        # an IPv4Address.
        stale = FieldRef[str]("ip.src", "FT_STRING", False)
        row = next(iter(ws.query()))
        with pytest.raises(FieldDeclarationMismatchError) as info:
            row.get(stale)
        message = str(info.value)
        assert "ip.src is materialized as FT_IPv4 scalar" in message
        assert "the reference declares FT_STRING scalar" in message

    def test_same_name_wrong_multiplicity_via_get(self, ws: Workspace) -> None:
        stale = FieldRef[int]("tcp.port", "FT_UINT16", False)
        row = next(iter(ws.query()))
        with pytest.raises(FieldDeclarationMismatchError, match="multi-valued"):
            row.get(stale)

    def test_same_name_wrong_multiplicity_via_get_all(self, ws: Workspace) -> None:
        # Previously reported as "ip.src is a scalar field; read it with get()",
        # which contradicts the caller's declaration instead of naming it.
        stale = FieldRef[IPv4Address]("ip.src", "FT_IPv4", True)
        row = next(iter(ws.query()))
        with pytest.raises(FieldDeclarationMismatchError) as info:
            row.get_all(stale)
        assert "the reference declares FT_IPv4 multi-valued" in str(info.value)

    def test_a_correct_reference_with_the_wrong_accessor_still_says_so(self, ws: Workspace) -> None:
        # The two failures stay distinct: this reference agrees with storage,
        # so the accessor is what is wrong, and ValueError says which to use.
        row = next(iter(ws.query()))
        with pytest.raises(ValueError, match=r"read it with get_all\(\)"):
            row.get(TCP.port)
        with pytest.raises(ValueError, match=r"read it with get\(\)"):
            row.get_all(IP.src)

    def test_projection_check_still_precedes_the_declaration_check(self, ws: Workspace) -> None:
        # A field left out of the projection is not in _specs at all, so there
        # is nothing to compare a declaration against.
        row = next(iter(ws.query().select(IP.src)))
        with pytest.raises(FieldNotProjectedError, match=re.escape("tcp.port")):
            row.get_all(FieldRef[int]("tcp.port", "FT_STRING", True))


class TestDeclarationConsistency:
    """A reference whose declaration disagrees with the catalog is refused.

    Without the check these reach DuckDB and come back as raw
    ConversionException / BinderException — the driver-error leak the missing
    field check exists to prevent, in a different guise.
    """

    def test_scalar_reference_to_a_multi_column(self, ws: Workspace) -> None:
        stale = FieldRef[int]("tcp.port", "FT_UINT16", False)
        with pytest.raises(FieldDeclarationMismatchError) as info:
            list(ws.query().filter(stale == 443))
        message = str(info.value)
        assert "tcp.port is materialized as FT_UINT16 multi-valued" in message
        assert "the reference declares FT_UINT16 scalar" in message

    def test_multi_reference_to_a_scalar_column(self, ws: Workspace) -> None:
        stale = FieldRef[IPv4Address]("ip.src", "FT_IPv4", True)
        with pytest.raises(FieldDeclarationMismatchError, match="multi-valued"):
            list(ws.query().filter(stale == "10.0.0.1"))

    def test_wrong_ftype(self, ws: Workspace) -> None:
        stale = FieldRef[str]("ip.src", "FT_STRING", False)
        with pytest.raises(FieldDeclarationMismatchError, match="FT_STRING"):
            list(ws.query().select(stale))

    def test_every_mismatch_is_named(self, ws: Workspace) -> None:
        stale_src = FieldRef[str]("ip.src", "FT_STRING", False)
        stale_port = FieldRef[int]("tcp.port", "FT_UINT16", False)
        with pytest.raises(FieldDeclarationMismatchError) as info:
            list(ws.query().filter(stale_src == "x").select(stale_port))
        message = str(info.value)
        assert "ip.src" in message
        assert "tcp.port" in message

    def test_two_declarations_of_one_field_in_one_query_are_both_seen(self, ws: Workspace) -> None:
        # Dedup is by (name, ftype, multi), not by name, so a good reference
        # earlier in the query cannot mask a stale one later.
        stale = FieldRef[int]("tcp.port", "FT_UINT16", False)
        with pytest.raises(FieldDeclarationMismatchError, match=re.escape("tcp.port")):
            list(ws.query().filter(TCP.port == 443).filter(stale == 8080))

    def test_missing_is_reported_before_mismatch(self, ws: Workspace) -> None:
        # A field with no column at all is the coarser problem; a declaration
        # comparison against a record that does not exist is not actionable.
        stale = FieldRef[str]("ip.src", "FT_STRING", False)
        with pytest.raises(FieldNotMaterializedError, match=re.escape("http.host")):
            list(ws.query().filter((HOST == "example.com") & (stale == "10.0.0.1")))

    def test_matching_references_are_accepted(self, ws: Workspace) -> None:
        # The flow that must not break: the refs a workspace was materialized
        # from are exactly the refs that query it.
        assert frames(ws.query().filter(TCP.port == 443).select(IP.src, TCP.port)) == [1, 2]


class TestArrowOutput:
    @pytest.fixture(autouse=True)
    def _needs_pyarrow(self) -> None:
        pytest.importorskip("pyarrow")

    def test_arrow_table_carries_the_projection(self, ws: Workspace) -> None:
        table = ws.query().filter(TCP.port == 443).arrow()
        assert table.num_rows == 2
        assert table.column_names == ["frame_number", "frame_time", "ip_src", "tcp_port"]
        assert table.column("frame_number").to_pylist() == [1, 2]

    def test_arrow_respects_select(self, ws: Workspace) -> None:
        table = ws.query().select(IP.src).arrow()
        assert table.column_names == ["frame_number", "frame_time", "ip_src"]

    def test_ipv6_columns_are_cast_to_exact_decimal_text(self, tmp_path: Path) -> None:
        # The FT_IPv6 hazard types.py documents: UHUGEINT exports through Arrow
        # as decimal128(38, 0) read as *signed*, so ff02::1 would arrive as a
        # negative integer. Query.arrow() casts UHUGEINT to VARCHAR instead, so
        # the value is exact. Pinned in both scalar and LIST position.
        with Workspace(tmp_path / "v6.duckdb", mode="rw") as workspace:
            seed(
                workspace,
                (V6SRC, V6ADDR),
                (
                    {"ipv6.src": ("ff02::1",), "ipv6.addr": ("::", "ff02::1:2")},
                    {"ipv6.src": ("2001:db8::1",), "ipv6.addr": ("2001:db8::1",)},
                ),
            )
            table = workspace.query().arrow()
            with workspace.read() as con:
                native = con.execute(
                    "SELECT ipv6_src FROM main.pkts ORDER BY frame_number"
                ).fetchall()

        column = table.column("ipv6_src")
        assert str(column.type) == "string"
        assert column.to_pylist() == [
            str(int(IPv6Address("ff02::1"))),
            str(int(IPv6Address("2001:db8::1"))),
        ]
        list_type = table.column("ipv6_addr").type
        assert str(list_type).startswith("list<")
        assert str(list_type.value_type) == "string"
        assert table.column("ipv6_addr").to_pylist()[0] == [
            str(int(IPv6Address("::"))),
            str(int(IPv6Address("ff02::1:2"))),
        ]
        # The stored column type is untouched: the cast is a read-time SELECT
        # expression, not a storage change.
        assert native[0][0] == int(IPv6Address("ff02::1"))

    def test_non_ipv6_columns_keep_their_native_arrow_type(self, ws: Workspace) -> None:
        table = ws.query().arrow()
        assert str(table.column("ip_src").type) == "uint32"
        assert str(table.column("frame_number").type) == "int64"

    def test_missing_pyarrow_names_the_arrow_extra(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `remora[workspace]` installs duckdb without pyarrow (duckdb names it
        # only under duckdb's own "all" extra), so this is the state a plain
        # workspace install is in. A None entry in sys.modules is what an
        # uninstalled extra looks like from inside duckdb's converter — the same
        # technique tests/test_workspace_import_purity.py uses for duckdb.
        monkeypatch.setitem(sys.modules, "pyarrow", None)
        with pytest.raises(ImportError, match=r"remora\[arrow\]"):
            ws.query().arrow()

    def test_everything_but_arrow_works_without_pyarrow(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The extra is optional in the real sense: only arrow() needs it.
        monkeypatch.setitem(sys.modules, "pyarrow", None)
        query = ws.query().filter(TCP.port == 443).select(IP.src)
        assert frames(query) == [1, 2]
        assert query.sql()[1] == (443,)
        assert next(iter(query)).get(IP.src) == IPv4Address("10.0.0.1")

    def test_falls_back_to_fetch_arrow_table_on_older_duckdb(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The duckdb 1.1-1.3 branch, exercised against a connection faking it.

        ``remora[workspace]`` declares ``duckdb>=1.1``, where a connection has
        ``arrow()``/``fetch_arrow_table()`` and no ``to_arrow_table()``; 1.4
        added ``to_arrow_table()``, deprecated ``fetch_arrow_table()`` and
        changed ``arrow()`` to return a ``RecordBatchReader`` rather than a
        table. The locked matrix installs the new API, so the older branch is
        unreachable without a stand-in: this wraps the real connection in a
        proxy that hides ``to_arrow_table`` and routes ``fetch_arrow_table`` to
        it, which is exactly the shape 1.1 presents.
        """
        calls: list[str] = []

        class LegacyConnection:
            """duckdb 1.1's connection surface over a modern one."""

            def __init__(self, con: Any) -> None:
                self._con = con

            def __getattr__(self, name: str) -> Any:
                if name == "to_arrow_table":
                    raise AttributeError(name)
                return getattr(self._con, name)

            def execute(self, sql: str, params: Any = None) -> LegacyConnection:
                # duckdb's execute() returns the connection itself, so the
                # result of a query carries the same (faked) surface.
                self._con.execute(sql) if params is None else self._con.execute(sql, params)
                return self

            def fetch_arrow_table(self) -> Any:
                calls.append("fetch_arrow_table")
                return self._con.to_arrow_table()

        real_read = Workspace.read

        @contextmanager
        def legacy_read(self: Workspace) -> Iterator[Any]:
            with real_read(self) as con:
                yield LegacyConnection(con)

        monkeypatch.setattr(Workspace, "read", legacy_read)
        table = ws.query().filter(TCP.port == 443).arrow()
        assert calls == ["fetch_arrow_table"]
        assert table.column_names == ["frame_number", "frame_time", "ip_src", "tcp_port"]
        assert table.column("frame_number").to_pylist() == [1, 2]


class TestReadPathOnly:
    def test_every_operation_works_in_ro_mode(self, tmp_path: Path) -> None:
        path = tmp_path / "ws.duckdb"
        with Workspace(path, mode="rw") as writable:
            seed(writable, (IP.src, TCP.port), PACKETS)
        with Workspace(path) as reader:
            assert reader.mode == "ro"
            query = reader.query().filter(TCP.port == 443)
            assert frames(query) == [1, 2]
            assert query.sql()[1] == (443,)

    def test_query_never_reaches_write(
        self, ws: Workspace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Seeding is done; from here a Query must not have any path to write().
        def forbidden(self: Workspace) -> Any:
            raise AssertionError("Query must never open a write connection")

        monkeypatch.setattr(Workspace, "write", forbidden)
        query = ws.query().filter(IP.src.present()).select(IP.src)
        assert frames(query) == [1, 2, 3, 4]
        assert query.sql()[0]
        pytest.importorskip("pyarrow")
        assert query.arrow().num_rows == 4

    def test_query_issues_no_ddl_or_dml(self, ws: Workspace) -> None:
        sql, _params = ws.query().filter(IP.src.present()).sql()
        upper = sql.upper()
        for verb in ("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "ATTACH"):
            assert verb not in upper


PEER_PACKETS: tuple[dict[str, tuple[str, ...]], ...] = (
    {"ip.src": ("10.0.0.1",), "ip.dst": ("10.9.9.9",)},
    {"ip.src": ("10.0.0.7",), "ip.dst": ("10.9.9.9",)},
)


@pytest.fixture
def ws_with_peer(tmp_path: Path) -> Iterator[Workspace]:
    """An rw workspace with a second workspace attached as 'peer'.

    The primary holds ip.src + tcp.port; the peer holds ip.src + ip.dst, so
    tcp.port is materialized in the primary and *not* in the peer, and ip.dst
    the other way round.
    """
    peer_path = tmp_path / "peer.duckdb"
    with Workspace(peer_path, mode="rw") as peer:
        seed(peer, (IP.src, IP.dst), PEER_PACKETS)
    with Workspace(tmp_path / "ws.duckdb", mode="rw") as workspace:
        seed(workspace, (IP.src, TCP.port), PACKETS)
        workspace.attach(peer_path, "peer")
        yield workspace


class TestAliasedQuery:
    def test_selects_from_the_attached_pkts(self, ws_with_peer: Workspace) -> None:
        assert frames(ws_with_peer.query(alias="peer")) == [1, 2]
        assert frames(ws_with_peer.query()) == [1, 2, 3, 4, 5]

    def test_sql_names_the_attached_table(self, ws_with_peer: Workspace) -> None:
        sql, _params = ws_with_peer.query(alias="peer").sql()
        assert 'FROM "peer".main.pkts' in sql
        plain, _ = ws_with_peer.query().sql()
        assert "FROM main.pkts" in plain

    def test_filters_run_against_the_attached_rows(self, ws_with_peer: Workspace) -> None:
        assert frames(ws_with_peer.query(alias="peer").filter(IP.src == "10.0.0.7")) == [2]
        # The same filter over the primary picks a different frame set.
        assert frames(ws_with_peer.query().filter(IP.src == "10.0.0.1")) == [1, 4]

    def test_rows_decode_through_the_attached_catalog(self, ws_with_peer: Workspace) -> None:
        rows = list(ws_with_peer.query(alias="peer").select(IP.dst))
        assert [row.get(IP.dst) for row in rows] == [IPv4Address("10.9.9.9")] * 2
        assert rows[0].frame_number == 1

    def test_row_key_is_reachable_on_an_aliased_query(self, ws_with_peer: Workspace) -> None:
        row = next(iter(ws_with_peer.query(alias="peer")))
        assert row.get(FRAME_NUMBER) == 1

    def test_a_field_the_peer_lacks_names_the_alias(self, ws_with_peer: Workspace) -> None:
        # tcp.port IS materialized in the primary and is NOT in the peer.
        assert frames(ws_with_peer.query().filter(TCP.port == 443)) == [1, 2]
        with pytest.raises(FieldNotMaterializedError, match=re.escape("tcp.port")) as excinfo:
            list(ws_with_peer.query(alias="peer").filter(TCP.port == 443))
        message = str(excinfo.value)
        assert "'peer'" in message
        assert "is not materialized" in message

    def test_a_field_the_primary_lacks_still_names_no_alias(self, ws_with_peer: Workspace) -> None:
        with pytest.raises(FieldNotMaterializedError) as excinfo:
            list(ws_with_peer.query().filter(IP.dst == "10.9.9.9"))
        assert "peer" not in str(excinfo.value)

    def test_select_of_a_missing_field_also_names_the_alias(self, ws_with_peer: Workspace) -> None:
        with pytest.raises(FieldNotMaterializedError, match="'peer'"):
            ws_with_peer.query(alias="peer").select(TCP.port).sql()

    def test_unprojected_field_names_the_alias(self, ws_with_peer: Workspace) -> None:
        # ip.src IS materialized in the peer; it is merely outside this
        # projection, which is the other refusal Row._spec can raise — it names
        # the attached workspace the way the declaration mismatch beside it
        # does.
        row = next(iter(ws_with_peer.query(alias="peer").select(IP.dst)))
        with pytest.raises(FieldNotProjectedError) as info:
            row.get(IP.src)
        message = str(info.value)
        assert "ip.src is not in this query's projection" in message
        assert "attached workspace 'peer'" in message

    def test_unprojected_field_on_the_primary_names_no_alias(self, ws_with_peer: Workspace) -> None:
        row = next(iter(ws_with_peer.query().select(TCP.port)))
        with pytest.raises(FieldNotProjectedError) as info:
            row.get(IP.src)
        assert "peer" not in str(info.value)

    def test_unknown_alias_is_refused_at_construction(self, ws_with_peer: Workspace) -> None:
        with pytest.raises(WorkspaceAliasError, match="no workspace is attached as 'nope'"):
            ws_with_peer.query(alias="nope")

    def test_chaining_keeps_the_alias(self, ws_with_peer: Workspace) -> None:
        chained = ws_with_peer.query(alias="peer").filter(IP.src.present()).select(IP.dst)
        sql, _ = chained.sql()
        assert 'FROM "peer".main.pkts' in sql

    def test_repr_names_the_alias(self, ws_with_peer: Workspace) -> None:
        assert "peer" in repr(ws_with_peer.query(alias="peer"))

    def test_aliased_query_issues_no_write(self, ws_with_peer: Workspace) -> None:
        sql, _params = ws_with_peer.query(alias="peer").sql()
        upper = sql.upper()
        for verb in ("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "ATTACH"):
            assert verb not in upper

    def test_arrow_reads_the_attached_rows(self, ws_with_peer: Workspace) -> None:
        pytest.importorskip("pyarrow")
        table = ws_with_peer.query(alias="peer").select(IP.dst).arrow()
        assert table.num_rows == 2
        assert table.column("frame_number").to_pylist() == [1, 2]


class TestAliasedDeclarationMismatch:
    """An alias-scoped mismatch names the workspace whose catalog was read.

    The two workspaces are the same library version here; what diverges is the
    *declaration* of one abbrev, which is the shape version skew takes — a
    reference that is right for the primary is wrong for the peer, and the
    refusal has to say which catalog it consulted or it reads as a contradiction
    of the query that just worked.
    """

    @pytest.fixture
    def ws_with_skewed_peer(self, tmp_path: Path) -> Iterator[Workspace]:
        """A peer whose ``tcp.port`` is a *scalar* where the primary's is multi."""
        peer_path = tmp_path / "peer.duckdb"
        scalar_port = FieldRef[int]("tcp.port", "FT_UINT16", False)
        with Workspace(peer_path, mode="rw") as peer:
            seed(peer, (IP.src, scalar_port), ({"ip.src": ("10.0.0.1",), "tcp.port": ("443",)},))
        with Workspace(tmp_path / "ws.duckdb", mode="rw") as workspace:
            seed(workspace, (IP.src, TCP.port), PACKETS)
            workspace.attach(peer_path, "peer")
            yield workspace

    def test_multiplicity_skew_is_refused_with_the_alias_named(
        self, ws_with_skewed_peer: Workspace
    ) -> None:
        # The very same reference is correct for the primary...
        assert frames(ws_with_skewed_peer.query().filter(TCP.port == 443)) == [1, 2]
        # ...and disagrees with the peer, which stores tcp.port as a scalar.
        with pytest.raises(FieldDeclarationMismatchError) as info:
            list(ws_with_skewed_peer.query(alias="peer").filter(TCP.port == 443))
        message = str(info.value)
        assert "tcp.port is materialized as FT_UINT16 scalar" in message
        assert "the reference declares FT_UINT16 multi-valued" in message
        assert "attached workspace 'peer'" in message
        assert "this workspace" not in message

    def test_select_of_a_skewed_field_names_the_alias(self, ws_with_skewed_peer: Workspace) -> None:
        with pytest.raises(FieldDeclarationMismatchError, match="attached workspace 'peer'"):
            ws_with_skewed_peer.query(alias="peer").select(TCP.port).sql()

    def test_row_access_mismatch_names_the_alias(self, ws_with_peer: Workspace) -> None:
        # The Row.get fire site: the row carries the alias its plan was built
        # with, so a stale reference there points at the peer's catalog too.
        row = next(iter(ws_with_peer.query(alias="peer").select(IP.dst)))
        stale = FieldRef[str]("ip.dst", "FT_STRING", False)
        with pytest.raises(FieldDeclarationMismatchError) as info:
            row.get(stale)
        message = str(info.value)
        assert "ip.dst is materialized as FT_IPv4 scalar" in message
        assert "attached workspace 'peer'" in message

    def test_row_access_get_all_mismatch_names_the_alias(self, ws_with_peer: Workspace) -> None:
        row = next(iter(ws_with_peer.query(alias="peer").select(IP.dst)))
        stale = FieldRef[IPv4Address]("ip.dst", "FT_IPv4", True)
        with pytest.raises(FieldDeclarationMismatchError, match="attached workspace 'peer'"):
            row.get_all(stale)

    def test_the_primary_still_names_no_alias(self, ws_with_peer: Workspace) -> None:
        stale = FieldRef[str]("ip.src", "FT_STRING", False)
        with pytest.raises(FieldDeclarationMismatchError, match="this workspace"):
            list(ws_with_peer.query().filter(stale == "10.0.0.1"))


class TestDetachedAliasIsRefusedAtExecution:
    """A Query is immutable and lazy, so the construction-time check goes stale.

    Without the re-check in ``_build`` the compiled statement reached DuckDB and
    came back as a raw ``BinderException: Catalog "peer" does not exist!`` — the
    driver-error leak the up-front alias check exists to prevent, in the one
    shape that check cannot cover.
    """

    MESSAGE = "no workspace is attached as 'peer'"

    def test_iteration_after_detach(self, ws_with_peer: Workspace) -> None:
        query = ws_with_peer.query(alias="peer")
        assert frames(query) == [1, 2]
        ws_with_peer.detach("peer")
        with pytest.raises(WorkspaceAliasError, match=self.MESSAGE):
            list(query)

    def test_sql_after_detach(self, ws_with_peer: Workspace) -> None:
        query = ws_with_peer.query(alias="peer")
        ws_with_peer.detach("peer")
        with pytest.raises(WorkspaceAliasError, match=self.MESSAGE):
            query.sql()

    def test_arrow_after_detach(self, ws_with_peer: Workspace) -> None:
        pytest.importorskip("pyarrow")
        query = ws_with_peer.query(alias="peer")
        ws_with_peer.detach("peer")
        with pytest.raises(WorkspaceAliasError, match=self.MESSAGE):
            query.arrow()

    def test_the_primary_query_is_unaffected(self, ws_with_peer: Workspace) -> None:
        ws_with_peer.detach("peer")
        assert frames(ws_with_peer.query()) == [1, 2, 3, 4, 5]

    def test_direct_construction_is_validated_too(self, ws_with_peer: Workspace) -> None:
        # Query is exported, so Workspace.query() is not the only way in and
        # cannot be the only place the alias is checked.
        query = Query(ws_with_peer, "nope")
        with pytest.raises(WorkspaceAliasError, match="no workspace is attached as 'nope'"):
            query.sql()
        with pytest.raises(WorkspaceAliasError, match="no workspace is attached as 'nope'"):
            list(query)

    def test_reattaching_makes_the_query_work_again(self, ws_with_peer: Workspace) -> None:
        peer_path = ws_with_peer.attachments["peer"]
        query = ws_with_peer.query(alias="peer")
        ws_with_peer.detach("peer")
        with pytest.raises(WorkspaceAliasError):
            list(query)
        ws_with_peer.attach(peer_path, "peer")
        assert frames(query) == [1, 2]
