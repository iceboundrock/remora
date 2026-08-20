"""Query the materialized workspace: the cache-side half of the query surface.

:class:`remora.Capture` queries the *pcap*; :class:`Query` queries the *cache*.
They are deliberately two classes rather than one polymorphic surface, so the
type of the object in hand says which one a caller is paying for — a tshark
subprocess per iteration, or a DuckDB scan over columns that were dissected
once. The IR is shared: the same ``Expr`` tree drives both, lowered by
:mod:`remora.compile.dfilter` on one side and :mod:`remora.compile.sql` on the
other.

Shape
-----
``Query`` is immutable and chainable like ``Capture``: :meth:`Query.filter`
returns a **new** query with the terms AND-ed onto the existing ones, and
:meth:`Query.select` returns a new query with the fields added to the
projection (both accumulate, so a partially built query can be shared and
extended). Nothing runs until :meth:`Query.__iter__`, :meth:`Query.arrow` or
:meth:`Query.sql` is called. ``Workspace.query()`` is the entry point.

Validation before compilation
-----------------------------
Every field the query mentions — every :class:`~remora.expr.FieldRef` in the
filter tree plus every field handed to :meth:`select` — is checked against
``meta.fields`` **before** the expression is compiled and before any generated
SQL reaches DuckDB, so a field nobody materialized reads as ``field ip.src is
not materialized — re-materialize including it`` rather than as DuckDB's
``column not found``. Every missing field is named, not just the first.
``frame.number`` and ``frame.time`` are exempt from the *catalog* lookup: they
are the ``pkts`` row key, materialized in every workspace and carrying no
``meta.fields`` entry (:data:`remora.workspace.naming.SKELETON_ABBREVS`). They
are **not** exempt from being projected — :data:`_ROW_KEY_SPECS` puts them at
the head of every projection as ordinary column specs, so ``row.get(...)``
reaches them like any other scalar field.

The same pass checks the *declaration*: a reference whose ftype or multiplicity
disagrees with the stored column is refused with
:class:`~remora.workspace.errors.FieldDeclarationMismatchError` naming both
sides. Left alone such a reference compiles a predicate against the wrong column
shape, which surfaces either as a raw duckdb ``ConversionException`` /
``BinderException`` or — when the wrong ftype happens to encode to something the
column *can* hold — as a **silently wrong row set** (a ``frame.number``
reference declared ``FT_IPv4`` coerces ``"10.0.0.1"`` to 167772161 and quietly
matches nothing). So this is the missing-field rule extended to version skew
between a workspace and the protocol modules querying it.

That rule is applied in **two** places from one definition
(:func:`_declaration_mismatch`): here, before compilation, and again in
:meth:`Row.get` / :meth:`Row.get_all`, because a reference is a static type as
well as a column address. ``FieldRef[str]("ip.src", "FT_STRING", False)`` names
the same column as ``IP.src`` but promises ``str``, and a name-only lookup would
hand an :class:`~ipaddress.IPv4Address` back through an accessor mypy has typed
``str | None``. The row key is the one carve-out, and only on ftype:
``frame.number`` accepts ``FT_UINT32`` (what ``tshark -G fields`` declares) or
``FT_FRAMENUM`` (what #31's insert-side spec calls it), since both resolve to
``UINTEGER`` with identity codecs and neither can encode or decode differently;
``frame.time`` accepts ``FT_ABSOLUTE_TIME`` alone, which is the only ftype
mapping to ``TIMESTAMP`` and the only one carrying the
``to_db_timestamp``/``from_db_timestamp`` codec pair the column is written and
read with. Multiplicity is never carved out.

The catalog is also the *source of truth for decoding*: a row's values are
decoded with a :class:`~remora.workspace.types.ColumnSpec` rebuilt from the
stored ``meta.fields`` record (abbrev, ftype, multiplicity, column type), never
from the field reference the caller passed, so what comes back always matches
what was written. The reference's ftype is still what encodes a *literal* in the
filter, which is the compiler's business (:mod:`remora.compile.sql`) — and the
declaration check above is what keeps the two from disagreeing.

Refusals from the SQL backend — :class:`~remora.compile.sql.UnsupportedSqlExprError`
for ``matches`` and for ``contains`` on a BLOB column — propagate unchanged.
They are statements about the backend, not about the workspace.

Where this does *not* match the pcap path
-----------------------------------------
The two surfaces answer the same question for the operators #29 harmonizes, and
``tests/integration/test_query_parity.py`` compares them filter by filter. One
exception is deliberate and inherited, not introduced here: SQL is three-valued,
so a **negated comparison on a scalar column** — ``~(IP.src == v)``, which is
how the DSL spells ``!=`` — compiles to ``NOT ("ip_src" = ?)``, which is
``NULL`` and therefore *false* for a packet that has no ``ip.src`` at all, where
Wireshark and the Python predicate backend both include that packet. Multi-value
columns do **not** diverge: an absent one is stored as ``[]``, not ``NULL``, so
``NOT (list_contains(...))`` is a real boolean. Issue #29 states this policy and
explicitly does not harmonize it; the parity suite pins the divergent case so it
stays visible.

Row access
----------
Iteration yields :class:`Row`, whose typed accessors follow the descriptor
contract exactly: :meth:`Row.get` on a scalar field returns ``T | None`` and
:meth:`Row.get_all` on a multi-value field returns ``tuple[T, ...]`` (``()``
when absent), the same shapes ``pkt[IP].src`` and ``pkt[TCP].port`` return on
the pcap path.

**Deliberate divergence from ``pkt[IP].src``.** The pcap path's protocol views
are defined over *raw tshark text*: :class:`~remora.fields.RawPacket` yields
strings and the descriptor parses them. A workspace row has no raw text — it
holds decoded column values, and re-rendering them as tshark would have printed
them is a lossy round trip nobody needs (``FT_ETHER`` is stored as bytes,
``FT_ABSOLUTE_TIME`` as a timestamp). So a ``Row`` is **not** a ``RawPacket``
and does not support ``row[IP].src``; access is by field reference, which keeps
the static types identical while being honest that the value came from a column
rather than from a dissector. Multiplicity is checked at access time — calling
:meth:`Row.get` on a multi-value field raises rather than silently dropping
occurrences, exactly as :class:`remora.fields.Field` refuses a multi ref.

A field that was materialized but left out of the projection raises
:class:`~remora.fields.FieldNotProjectedError`, reusing the pcap path's error
for the pcap path's meaning.

Arrow output and the ``FT_IPv6`` hazard
---------------------------------------
:meth:`Query.arrow` returns the result as a ``pyarrow.Table``, and needs pyarrow
installed: ``pip install 'remora[arrow]'``. That is a **separate extra from**
``workspace``, deliberately. duckdb names pyarrow only under duckdb's *own*
``all`` extra, so ``remora[workspace]`` installs duckdb without it — and a
workspace user who never calls :meth:`~Query.arrow` should not carry a ~35 MB
wheel for it. ``remora[all]`` includes both. Absent pyarrow, :meth:`Query.arrow`
raises an :class:`ImportError` naming the extra, exactly as
:mod:`remora.proto` does for a missing protocol distribution; every other part
of ``Query`` works without it.

:mod:`remora.workspace.types` documents the export hazard this method has to
respect: DuckDB exports ``UHUGEINT`` through Arrow as ``decimal128(38, 0)``
**read as signed**, so every ``FT_IPv6`` address with the high bit set — all of
``fe80::/10`` and ``ff00::/8``, i.e. essentially every real capture — would come
back as a two's-complement negative number. Silent numeric corruption is the
worst possible outcome for an analytics export, so :meth:`Query.arrow` casts
``UHUGEINT`` columns (scalar and ``LIST`` alike) to ``VARCHAR`` in the SELECT
list: the value arrives as exact decimal text, which ``IPv6Address(int(text))``
turns back into an address. The **stored** column type is untouched — the cast
is a read-time projection, not a storage change, and the DuckDB-native path
(:meth:`Query.__iter__`) still decodes straight to :class:`ipaddress.IPv6Address`.
Nothing else is cast: every other column keeps its natural Arrow type.

Attached workspaces
-------------------
``Workspace.query(alias=...)`` binds the query to a workspace attached with
``Workspace.attach`` instead of to this one: the statement selects
``FROM "alias".main.pkts``, and every field is validated and decoded against
*that* workspace's ``"alias".meta.fields``. So a field materialized here but not
there is refused with the alias named — the catalog that answers the question is
the one the rows come from, and a query that read the primary's registry would
compile a column the attached ``pkts`` may not hold. The row key needs no
catalog either way (:data:`_ROW_KEY_SPECS`), since every workspace's ``pkts``
carries it.

``Query`` stays **single-table**: an alias re-targets the one table it selects
from, and nothing here joins. A cross-capture *join* is ordinary SQL over the
connection ``Workspace.read()`` hands out, which is where an attached workspace
was reachable from all along — :meth:`Query.sql` renders a statement that can be
embedded there as a subquery.

Read path only
--------------
``Query`` executes through ``Workspace.read()``: it never enters the write API
and never writes — no ``Workspace.write()`` call, no DDL, no DML. That is the
guarantee, and it is deliberately phrased about the *API* rather than about the
connection's configuration, because the two are not the same thing: in ``"ro"``
mode ``read()`` yields a genuinely read-only connection, but in ``"rw"`` mode it
opens a read-write-*configured* one, since DuckDB refuses two live same-process
connections to one file with different configurations and a read may nest inside
a ``write()``. That is #28's concession, not this module's doing. What ``Query``
does with either connection is identical: ``SELECT``.

Like every module in this package it is import-pure: duckdb is annotated under
``TYPE_CHECKING`` and no connection is opened here.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, TypeAlias, TypeVar, cast

# The *module*, not the function: remora.compile.sql imports this package's
# naming/types layers, which imports this module, so binding `compile_sql` by
# name at import time would fail whenever remora.compile.sql is the entry point
# (it would still be mid-execution, with the name undefined). Importing the
# submodule object works either way — `from package import submodule` falls back
# to sys.modules during a cycle — and the lookup happens at call time.
from remora.compile import sql as _sql_backend
from remora.expr import Expr, FieldLike, field_refs
from remora.fields import FieldNotProjectedError, FieldRef
from remora.workspace.errors import FieldDeclarationMismatchError, FieldNotMaterializedError
from remora.workspace.naming import SKELETON_ABBREVS, column_name
from remora.workspace.schema import FieldRecord, qualify, read_fields
from remora.workspace.types import ColumnSpec

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

    from remora.workspace.workspace import Workspace

__all__ = ["ArrowTable", "Query", "Row"]

T = TypeVar("T")

ArrowTable: TypeAlias = Any
"""A ``pyarrow.Table``.

Spelled ``Any`` on purpose: pyarrow is not a remora dependency and ships no
``py.typed`` marker, so naming the real class would either add a dependency or
break ``mypy --strict``. duckdb's own stubs make the same choice.
"""

#: The ``pkts`` row key as ordinary column specs, always projected first. They
#: carry no ``meta.fields`` entry (#31 never registers them — the skeleton is
#: already materialized), so the catalog cannot supply them and this module
#: states them instead, pairing
#: :data:`remora.workspace.naming.SKELETON_ABBREVS` with the column types
#: :mod:`remora.workspace.schema`'s layout declares. Being ordinary specs is the
#: point: the row key decodes, projects and is reachable through
#: :meth:`Row.get` exactly like any other scalar field.
#:
#: ``frame.number``'s ftype is ``tshark -G fields``' own declaration
#: (``FT_UINT32``); #31's insert-side spec spells it ``FT_FRAMENUM``. Both map
#: to ``UINTEGER`` with identity codecs, so they decode identically, which is
#: why the declaration check below accepts either for the row key.
#: The column *names* are derived, not restated: `naming.column_name` is the
#: frozen abbrev -> column policy, so the row key cannot drift from it. The
#: column *types* are stated, because they are not derivable — ``frame_number``
#: is ``BIGINT``, which is what ``schema.py``'s layout declares, not the
#: ``UINTEGER`` the ftype map would pick (the same deliberate exception #31's
#: insert-side specs carry). ``tests/test_workspace_query.py`` pins both against
#: the live ``iter_ddl()`` text, so the DDL stays the single authority.
_FRAME_NUMBER_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.number",
    column_name=column_name("frame.number"),
    ftype="FT_UINT32",
    multi=False,
    sql_type="BIGINT",
)
_FRAME_TIME_SPEC: Final[ColumnSpec] = ColumnSpec(
    abbrev="frame.time",
    column_name=column_name("frame.time"),
    ftype="FT_ABSOLUTE_TIME",
    multi=False,
    sql_type="TIMESTAMP",
)
_ROW_KEY_SPECS: Final[tuple[ColumnSpec, ...]] = (_FRAME_NUMBER_SPEC, _FRAME_TIME_SPEC)

#: The same specs by abbrev — the authority a row-key reference is checked
#: against, standing in for the ``meta.fields`` record it does not have. Keyed
#: identically to :data:`remora.workspace.naming.SKELETON_ABBREVS`, which
#: ``tests/test_workspace_query.py`` pins.
_ROW_KEY_SPECS_BY_ABBREV: Final[Mapping[str, ColumnSpec]] = {
    spec.abbrev: spec for spec in _ROW_KEY_SPECS
}

#: FTypes a *row-key* reference may legitimately declare. Every other field
#: accepts exactly the ftype its catalog record stores; the row key needs a set
#: because ``frame.number`` has two spellings in this tree — ``tshark -G
#: fields`` declares it ``FT_UINT32`` and #31's insert-side spec calls it
#: ``FT_FRAMENUM`` — and both resolve to ``UINTEGER`` with identity codecs, so
#: neither can encode a literal or decode a value differently from the other.
#: ``frame.time`` has no such twin: ``FT_ABSOLUTE_TIME`` is the only ftype
#: :data:`remora.workspace.types.COLUMN_TYPES` maps to ``TIMESTAMP``, and it is
#: the only one whose codec is the ``to_db_timestamp``/``from_db_timestamp``
#: pair the column is written and read with, so any other spelling is wrong.
#: These sets are exhaustive on purpose: an ftype that merely *happens* to share
#: a column type (``FT_UINT24`` also maps to ``UINTEGER``) is not accepted,
#: because nothing in this tree declares the row key that way.
_ROW_KEY_FTYPES: Final[Mapping[str, frozenset[str]]] = {
    "frame.number": frozenset({"FT_UINT32", "FT_FRAMENUM"}),
    "frame.time": frozenset({"FT_ABSOLUTE_TIME"}),
}

#: Stored column types whose Arrow export is wrong (see the module docstring):
#: ``UHUGEINT`` reads back signed, so it is cast to text on the way out.
_ARROW_UNSAFE_TYPES: Final[frozenset[str]] = frozenset({"UHUGEINT", "UHUGEINT[]"})


def _quote(name: str) -> str:
    """Double-quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


class Row:
    """One workspace row: the ``pkts`` row key plus the projected field values.

    Values are already decoded — :meth:`get` and :meth:`get_all` hand back the
    Python types :mod:`remora.values` parses to, in the shapes the descriptor
    contract defines (``T | None`` for a scalar field, ``tuple[T, ...]`` for a
    multi-value one).
    """

    __slots__ = ("_alias", "_specs", "_values")

    def __init__(
        self,
        values: Mapping[str, Any],
        specs: Mapping[str, ColumnSpec],
        alias: str | None = None,
    ) -> None:
        self._values = values
        self._specs = specs
        self._alias = alias

    @property
    def frame_number(self) -> int | None:
        """Capture-order row key, or ``None`` in a workspace that stored none.

        A convenience spelling of ``row.get(<a frame.number ref>)``: the row key
        is an ordinary projected column here, reachable both ways.
        """
        return cast("int | None", self._values[_FRAME_NUMBER_SPEC.abbrev])

    @property
    def frame_time(self) -> datetime | None:
        """Packet timestamp, aware UTC — ``None`` when the column is NULL.

        DuckDB stores a timezone-naive ``TIMESTAMP`` (#26), which
        :func:`~remora.workspace.types.from_db_timestamp` re-tags as UTC here.
        Raw SQL over ``pkts`` sees the naive form; a ``Row`` never does. Like
        :attr:`frame_number`, also reachable as ``row.get(<a frame.time ref>)``.
        """
        return cast("datetime | None", self._values[_FRAME_TIME_SPEC.abbrev])

    def _spec(self, field: FieldRef[Any]) -> ColumnSpec:
        """Resolve a reference to its column, checking the *whole* declaration.

        Name alone is not enough. A reference is a static type as much as a
        column address — ``FieldRef[str]("ip.src", "FT_STRING", False)`` names
        the same column as ``IP.src`` but promises ``str`` — so matching on the
        name would hand an :class:`~ipaddress.IPv4Address` back through an
        accessor mypy has typed ``str | None``, and let a scalar/multi
        disagreement be reported as the caller's accessor being wrong rather
        than their declaration. Both are the same mismatch
        :meth:`Query._validate` refuses at compile time, so the row-access path
        applies the identical rule.
        """
        spec = self._specs.get(field.name)
        if spec is None:
            raise FieldNotProjectedError(
                f"{field.name} is not in this query's projection; add it with "
                f".select({field.name!r}) or drop the .select() call to project "
                f"every materialized field"
            )
        problem = _declaration_mismatch(field, spec)
        if problem is not None:
            raise FieldDeclarationMismatchError(_mismatch_message([problem], self._alias))
        return spec

    def get(self, field: FieldRef[T]) -> T | None:
        """Value of a scalar field, or ``None`` when it is absent from the packet.

        Args:
            field: Class-access field reference, e.g. ``IP.src``.

        Returns:
            The decoded value, or ``None`` when the packet had no occurrence.

        Raises:
            FieldNotProjectedError: If the field is outside this query's
                projection.
            FieldDeclarationMismatchError: If the reference's ftype or
                multiplicity disagrees with the stored column — the same check
                :meth:`Query.filter` applies, so a stale reference cannot return
                a value through an accessor typed for a different one.
            ValueError: If the field is *correctly* declared multi-value — use
                :meth:`get_all`. Returning one occurrence of many would silently
                drop data, exactly as :class:`remora.fields.Field` refuses a
                multi ref. Distinct from the mismatch above: here the reference
                agrees with storage and the accessor is the wrong one.
        """
        spec = self._spec(field)
        if spec.multi:
            raise ValueError(
                f"{field.name} is multi-valued; read it with get_all() "
                f"(get() would silently drop occurrences)"
            )
        return cast("T | None", self._values[field.name])

    def get_all(self, field: FieldRef[T]) -> tuple[T, ...]:
        """Every occurrence of a multi-value field, in wire order.

        Args:
            field: Class-access field reference, e.g. ``TCP.port``.

        Returns:
            The decoded occurrences; ``()`` when the field is absent, so
            iteration and ``in`` need no ``None`` guard.

        Raises:
            FieldNotProjectedError: If the field is outside this query's
                projection.
            FieldDeclarationMismatchError: If the reference's ftype or
                multiplicity disagrees with the stored column.
            ValueError: If the field is *correctly* declared scalar — use
                :meth:`get`.
        """
        spec = self._spec(field)
        if not spec.multi:
            raise ValueError(f"{field.name} is a scalar field; read it with get()")
        return cast("tuple[T, ...]", self._values[field.name])

    def __repr__(self) -> str:
        return f"<Row frame_number={self.frame_number} fields={len(self._values)}>"


@dataclass(frozen=True)
class _Plan:
    """One compiled query: the SQL, its parameters, and how to decode a row."""

    sql: str
    params: tuple[Any, ...]
    specs: tuple[ColumnSpec, ...]
    #: The attached workspace this plan reads, or ``None`` for the primary one.
    #: Carried so a :class:`Row` built from it can name the alias in a refusal.
    alias: str | None = None


class Query:
    """A lazily-executed, immutable query over one workspace's materialized rows.

    Build it with ``Workspace.query()``. ``filter()`` and ``select()`` each
    return a NEW query with the terms or fields appended, so a partially built
    query can be shared; nothing touches the database until the query is
    iterated, exported with :meth:`arrow`, or rendered with :meth:`sql`.

    Execution is **not streaming**: every result path materializes the whole
    result set while the connection is held, rather than paging with the
    connection open across the caller's loop. :meth:`__iter__` documents why —
    in rw mode paging would hold DuckDB's exclusive lock for the consumer's
    whole iteration, and in ro mode the result rides the single held
    connection, so a nested query would clobber a paged one.

    Args:
        workspace: The open workspace to read. Every execution goes through
            ``Workspace.read()``; a ``Query`` never enters the write API and
            never writes.
        alias: A workspace attached to ``workspace`` under this alias, to query
            instead of ``workspace`` itself. The statement then selects from
            ``alias.main.pkts`` and validates against ``alias.meta.fields`` —
            see the module docstring. ``Workspace.query()`` is what checks the
            alias against the recorded attachments; nothing here does.
    """

    __slots__ = ("_alias", "_select", "_terms", "_workspace")

    def __init__(self, workspace: Workspace, alias: str | None = None) -> None:
        self._workspace = workspace
        self._alias = alias
        self._terms: tuple[Expr, ...] = ()
        self._select: tuple[FieldRef[Any], ...] = ()

    def _clone(self, terms: tuple[Expr, ...], select: tuple[FieldRef[Any], ...]) -> Query:
        clone = Query(self._workspace, self._alias)
        clone._terms = terms
        clone._select = select
        return clone

    def filter(self, *terms: Expr) -> Query:
        """A new query with ``terms`` AND-ed onto the existing ones.

        Args:
            terms: Expression trees, e.g. ``TCP.port == 443``. Unlike
                ``Capture.filter`` there is no opaque-callable form: the whole
                point of the cache path is that the predicate runs inside
                DuckDB, and a Python lambda cannot.

        Returns:
            A new :class:`Query`; this one is unchanged.
        """
        return self._clone(self._terms + terms, self._select)

    def select(self, *fields: FieldRef[Any]) -> Query:
        """A new query projecting ``fields`` in addition to those already chosen.

        With no ``select()`` at all the projection is every field in
        ``meta.fields``. The ``pkts`` row key (``frame_number`` /
        ``frame_time``) is always projected, so ``frame.number`` and
        ``frame.time`` need not be asked for and add no second column when they
        are — they are reachable through :meth:`Row.get` either way.

        Args:
            fields: Class-access field references, e.g. ``IP.src``. Duplicates
                of one abbrev collapse, and the projection keeps the order
                fields were first named in.

        Returns:
            A new :class:`Query`; this one is unchanged.
        """
        return self._clone(self._terms, self._select + fields)

    def sql(self) -> tuple[str, tuple[Any, ...]]:
        """The SQL this query would execute, with its bound parameters.

        Inspectable and side-effect free apart from reading ``meta.fields`` —
        the catalog is what turns a field reference into a column, so validation
        happens here too. Handy for debugging, and for handing the predicate to
        the DuckDB connection directly (raw SQL passthrough is deliberately not
        a ``Query`` feature: ``Workspace.read()`` already gives you the
        connection).

        Returns:
            The SQL text with ``?`` placeholders, and the values to bind.

        Raises:
            FieldNotMaterializedError: If a referenced field has no column.
            FieldDeclarationMismatchError: If a reference's ftype or
                multiplicity disagrees with the stored catalog record.
            UnsupportedSqlExprError: If the SQL backend refuses the filter.
        """
        with self._workspace.read() as con:
            plan = self._build(con, arrow=False)
        return plan.sql, plan.params

    def __iter__(self) -> Iterator[Row]:
        """Execute the query and iterate the matching rows in frame order.

        **This is not streaming, deliberately.** The whole result set is fetched
        with one ``fetchall()`` inside a single ``Workspace.read()`` block, and
        only the decoding into :class:`Row` objects is lazy — so peak memory is
        the raw tuples of every matching row. The trade-off is stated rather
        than hidden, because the streaming alternative (holding the connection
        open and paging with ``fetchmany``) is worse in both workspace modes:

        - In ``"rw"`` mode ``read()`` holds the exclusive DuckDB lock for as
          long as the connection is open, so paging would keep every other
          process locked out for the duration of the *consumer's* loop — an
          arbitrarily long, caller-controlled window, on a query that only
          reads.
        - In ``"ro"`` mode the workspace holds one long-lived connection, and
          ``con.execute()`` returns that connection rather than an independent
          cursor. A second query started while a paged iteration was in flight
          would replace the pending result, so nested or interleaved queries
          would silently return the wrong rows.

        Fetching inside the ``read()`` block and decoding outside it costs
        memory on huge result sets and buys correctness on both counts. Filter
        harder, or reach for :meth:`arrow` (which streams into columnar memory)
        or the connection ``Workspace.read()`` already hands out, when the
        result set is too large to sit in memory as tuples.

        Returns:
            An iterator of :class:`Row`, ascending by ``frame_number``.

        Raises:
            FieldNotMaterializedError: If a referenced field has no column.
            FieldDeclarationMismatchError: If a reference's ftype or
                multiplicity disagrees with the stored catalog record.
            UnsupportedSqlExprError: If the SQL backend refuses the filter.
        """
        with self._workspace.read() as con:
            plan = self._build(con, arrow=False)
            rows = con.execute(plan.sql, list(plan.params)).fetchall()
        index = {spec.abbrev: spec for spec in plan.specs}
        return (_decode_row(raw, plan.specs, index, plan.alias) for raw in rows)

    def arrow(self) -> ArrowTable:
        """Execute the query and return the result as a ``pyarrow.Table``.

        Requires pyarrow, which is the ``arrow`` extra: ``pip install
        'remora[arrow]'`` (or ``remora[all]``). It is separate from
        ``workspace`` because duckdb does not pull pyarrow in — see the module
        docstring — so every other ``Query`` operation works without it.

        ``FT_IPv6`` columns are cast to ``VARCHAR`` — exact decimal text —
        because DuckDB's Arrow export reads ``UHUGEINT`` as a *signed*
        ``decimal128(38, 0)`` and would otherwise hand back link-local and
        multicast addresses as negative numbers. See the module docstring; the
        stored column type is unchanged, and ``IPv6Address(int(text))`` recovers
        the address. No other column type is cast.

        Returns:
            The result table, columns in projection order with the ``pkts`` row
            key first.

        Raises:
            FieldNotMaterializedError: If a referenced field has no column.
            FieldDeclarationMismatchError: If a reference's ftype or
                multiplicity disagrees with the stored catalog record.
            UnsupportedSqlExprError: If the SQL backend refuses the filter.
            ImportError: If pyarrow is not installed, naming the ``arrow``
                extra that provides it.
        """
        with self._workspace.read() as con:
            plan = self._build(con, arrow=True)
            result = con.execute(plan.sql, list(plan.params))
            # duckdb >= 1.4 renamed fetch_arrow_table() to to_arrow_table() and
            # changed arrow() to return a RecordBatchReader; the old name still
            # works there but warns. Prefer the new one, fall back for 1.1-1.3.
            to_arrow_table = getattr(result, "to_arrow_table", None)
            try:
                table: ArrowTable = (
                    result.fetch_arrow_table() if to_arrow_table is None else to_arrow_table()
                )
            except ImportError as exc:
                raise ImportError(
                    "Query.arrow() builds a pyarrow.Table through duckdb, which needs "
                    "pyarrow; install it with pip install 'remora[arrow]'"
                ) from exc
        return table

    def _build(self, con: DuckDBPyConnection, *, arrow: bool) -> _Plan:
        """Validate every referenced field, then compile the statement."""
        # The catalog read follows the alias: an aliased query's fields are the
        # attached workspace's, never this one's.
        records = {record.abbrev: record for record in read_fields(con, database=self._alias)}
        self._validate(records)
        # The row key leads every projection, as ordinary specs: it is always
        # selected, so it always decodes and is always reachable via Row.get().
        specs = _ROW_KEY_SPECS + tuple(
            _spec_of(records[abbrev]) for abbrev in self._projection(records)
        )
        projection = [_arrow_column(spec) if arrow else _quote(spec.column_name) for spec in specs]
        sql = f"SELECT {', '.join(projection)} FROM {qualify(self._alias, 'main.pkts')}"
        params: tuple[Any, ...] = ()
        if self._terms:
            predicate = _sql_backend.compile_sql(_conjoin(self._terms))
            sql += f" WHERE {predicate.sql}"
            params = predicate.params
        return _Plan(
            sql=f"{sql} ORDER BY frame_number",
            params=params,
            specs=specs,
            alias=self._alias,
        )

    def _references(self) -> tuple[FieldLike, ...]:
        """Every field reference this query mentions, in first-use order.

        Filter references come first (depth-first through the tree), then the
        selected fields. ``FieldRef`` is unhashable by design — ``__eq__``
        builds an ``Expr`` — so the dedup key is the ``(name, ftype, multi)``
        triple, never the ref. Keying on the whole declaration rather than on
        the name alone is what lets :meth:`_validate` see *both* declarations
        when one query names one field two ways.
        """
        seen: dict[tuple[str, str, bool], FieldLike] = {}
        for term in self._terms:
            for ref in field_refs(term):
                seen.setdefault((ref.name, ref.ftype, ref.multi), ref)
        for field in self._select:
            seen.setdefault((field.name, field.ftype, field.multi), field)
        return tuple(seen.values())

    def _validate(self, records: Mapping[str, FieldRecord]) -> None:
        """Refuse unmaterialized and mis-declared fields, before anything runs.

        Two checks, both naming every offender rather than the first, and both
        ahead of :func:`~remora.compile.sql.compile_sql` so nothing derived from
        a bad reference is ever handed to DuckDB. On an aliased query both name
        the attached workspace, because that is the catalog ``records`` came
        from and a field missing *there* says nothing about this workspace.
        """
        missing: list[str] = []
        mismatched: list[str] = []
        for ref in self._references():
            spec = _authority(ref.name, records)
            if spec is None:
                if ref.name not in missing:
                    missing.append(ref.name)
                continue
            problem = _declaration_mismatch(ref, spec)
            if problem is not None:
                mismatched.append(problem)
        # Missing first: a field with no column at all is the coarser problem,
        # and a declaration comparison against a record that does not exist is
        # not a thing anyone can act on.
        scope = "" if self._alias is None else f" in attached workspace {self._alias!r}"
        if len(missing) == 1:
            raise FieldNotMaterializedError(
                f"field {missing[0]} is not materialized{scope} — re-materialize including it"
            )
        if missing:
            raise FieldNotMaterializedError(
                f"fields {', '.join(missing)} are not materialized{scope} — "
                f"re-materialize including them"
            )
        if mismatched:
            raise FieldDeclarationMismatchError(_mismatch_message(mismatched, self._alias))

    def _projection(self, records: Mapping[str, FieldRecord]) -> tuple[str, ...]:
        """Abbrevs to project: the selected fields, or every materialized one.

        Skeleton abbrevs are dropped *here* because :data:`_ROW_KEY_SPECS`
        already carries them at the head of every projection: selecting
        ``frame.number`` must not duplicate the column, and must not be needed
        for :meth:`Row.get` to reach it either.
        """
        if not self._select:
            return tuple(records)
        chosen: dict[str, None] = {}
        for field in self._select:
            if field.name not in SKELETON_ABBREVS:
                chosen.setdefault(field.name, None)
        return tuple(chosen)

    def __repr__(self) -> str:
        projection = "*" if not self._select else ",".join(f.name for f in self._select)
        target = "" if self._alias is None else f" alias={self._alias!r}"
        return (
            f"<Query {str(self._workspace.path)!r}{target} "
            f"terms={len(self._terms)} select={projection}>"
        )


def _conjoin(terms: Sequence[Expr]) -> Expr:
    """AND a query's terms into one expression, left to right."""
    combined = terms[0]
    for term in terms[1:]:
        combined = combined & term
    return combined


def _declaration(ftype: str, multi: bool) -> str:
    """Render one field declaration for a mismatch message."""
    return f"{ftype} {'multi-valued' if multi else 'scalar'}"


def _authority(abbrev: str, records: Mapping[str, FieldRecord]) -> ColumnSpec | None:
    """The column spec a reference to ``abbrev`` must agree with, if there is one.

    The ``meta.fields`` record for an ordinary field, the fixed skeleton spec for
    the row key (which has no record), and ``None`` for a field this workspace
    holds no column for at all.
    """
    row_key = _ROW_KEY_SPECS_BY_ABBREV.get(abbrev)
    if row_key is not None:
        return row_key
    record = records.get(abbrev)
    return None if record is None else _spec_of(record)


def _declaration_mismatch(ref: FieldLike, spec: ColumnSpec) -> str | None:
    """How ``ref``'s declaration disagrees with the stored column, or ``None``.

    The single rule both the compile path (:meth:`Query._validate`) and the
    row-access path (:meth:`Row._spec`) apply, so a reference that a filter
    would refuse cannot slip in through ``row.get`` instead.

    Multiplicity must match exactly. FType must be one of
    :func:`_accepted_ftypes` — normally the stored ftype alone, and for the row
    key the documented equivalence set. Neither is cosmetic: ftype is what
    :mod:`remora.compile.sql` encodes a literal with, so a wrong one compiles a
    predicate against the wrong column shape, and multiplicity is what decides
    ``"col" = ?`` versus ``list_contains("col", ?)``.
    """
    if ref.multi == spec.multi and ref.ftype in _accepted_ftypes(spec):
        return None
    if spec.abbrev in _ROW_KEY_SPECS_BY_ABBREV:
        accepted = " or ".join(sorted(_accepted_ftypes(spec)))
        return (
            f"{ref.name} is the pkts row key, a scalar {spec.sql_type} column "
            f"declared {accepted}, but the reference declares "
            f"{_declaration(ref.ftype, ref.multi)}"
        )
    return (
        f"{ref.name} is materialized as {_declaration(spec.ftype, spec.multi)} "
        f"but the reference declares {_declaration(ref.ftype, ref.multi)}"
    )


def _accepted_ftypes(spec: ColumnSpec) -> frozenset[str]:
    """FTypes a reference to this column may declare.

    Exactly the stored ftype, except for the row key, whose accepted spellings
    are enumerated in :data:`_ROW_KEY_FTYPES` — see there for why the set is
    closed rather than derived from the column type.
    """
    return _ROW_KEY_FTYPES.get(spec.abbrev, frozenset({spec.ftype}))


def _mismatch_message(problems: Sequence[str], alias: str | None = None) -> str:
    """Assemble the refusal for one or more declaration mismatches.

    Args:
        problems: One rendering of each disagreement, from
            :func:`_declaration_mismatch`.
        alias: The attached workspace whose catalog was consulted, or ``None``
            for this one — named so a mismatch points at the workspace that
            actually stores the column.

    Returns:
        The refusal text.
    """
    scope = "this workspace" if alias is None else f"attached workspace {alias!r}"
    return (
        f"{'; '.join(problems)}. The stored declaration in {scope} is what the "
        f"column holds, so re-materialize the workspace, or query it with the "
        f"field references it was materialized from"
    )


def _spec_of(record: FieldRecord) -> ColumnSpec:
    """Rebuild a column's codec from its stored catalog row.

    The catalog, not the caller's field reference, is what decoding follows: it
    records the ftype, multiplicity and column type the data was actually
    written with.
    """
    return ColumnSpec(
        abbrev=record.abbrev,
        column_name=record.column_name,
        ftype=record.ftype,
        multi=record.multi,
        sql_type=record.column_type,
    )


def _arrow_column(spec: ColumnSpec) -> str:
    """Projection expression for the Arrow export, casting what Arrow gets wrong."""
    column = _quote(spec.column_name)
    if spec.sql_type not in _ARROW_UNSAFE_TYPES:
        return column
    cast_type = "VARCHAR[]" if spec.multi else "VARCHAR"
    return f"CAST({column} AS {cast_type}) AS {column}"


def _decode_row(
    raw: Sequence[Any],
    order: Sequence[ColumnSpec],
    index: Mapping[str, ColumnSpec],
    alias: str | None = None,
) -> Row:
    """Turn one fetched tuple into a :class:`Row`, decoding through the codecs.

    Uniform over every column, row key included: ``FT_ABSOLUTE_TIME``'s codec is
    :func:`~remora.workspace.types.from_db_timestamp`, so ``frame_time`` is
    re-tagged aware-UTC by the same path a materialized timestamp column takes.
    """
    return Row(
        values={spec.abbrev: spec.decode(value) for spec, value in zip(order, raw, strict=True)},
        specs=index,
        alias=alias,
    )
