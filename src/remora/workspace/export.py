"""Parquet export: the delivery format, never the storage format (issue #34).

Parquet is how a workspace *leaves* remora — delivery, archival, and ingestion
by Spark or Athena downstream — while the live workspace stays in DuckDB
native form, because the workspace is mutable (annotations) and Parquet is not.
Nothing here reads a Parquet file back into a workspace; that is out of scope,
as are partitioned dataset layouts. One call writes one table to one file.

What an export does **not** contain
-----------------------------------
An exported file holds exactly the columns the table has, and no more:

* **No payloads.** ``pkts`` stores projected field values, never packet bytes.
* **No unprojected fields.** A field that was not materialized has no column,
  so it cannot be exported; adding it means re-materializing from the capture.
* **No capture metadata beyond the row key.** Timestamps and frame numbers are
  the skeleton columns; the ``meta`` catalog is not part of a table export.

So an export is a *derivative*, and **the pcap remains the source of truth**.
An analysis that needs a field nobody projected has to go back to the capture.

Type mapping
------------
The exported schema mirrors the stored one. For a schema remora wrote there are
exactly two divergences — ``UHUGEINT`` and ``INTERVAL``, at any list depth —
which this module rewrites because DuckDB's Parquet writer cannot represent them
exactly; every other column type is written straight through. (Signed
``HUGEINT`` is rewritten too, but no ftype maps to it, so it can only appear on
a column some other tool added; see :data:`TEXT_EXPORTED_TYPES`.)

=====================  =========================  ==========================
Workspace column       Parquet / Arrow            Note
=====================  =========================  ==========================
``BIGINT``             ``int64``                  row key
``TIMESTAMP``          ``timestamp[us]``          naive UTC, as stored
``UINTEGER``           ``uint32``                 ``FT_IPv4``, unsigned
``UTINYINT`` …         ``uint8`` … ``uint64``     exact width preserved
``TINYINT`` …          ``int8`` … ``int64``       exact width preserved
``DOUBLE``             ``double``
``BOOLEAN``            ``bool``
``VARCHAR``            ``string``
``BLOB``               ``binary``                 ``FT_ETHER``, ``FT_BYTES``
``UHUGEINT``           ``string``                 **rewritten** — see below
``INTERVAL``           ``string``                 **rewritten** — see below
``T[]``                ``list<T>``                multi-value fields
=====================  =========================  ==========================

A multi-value column keeps its list shape, element type included; the two
rewrites apply inside a list exactly as they do to a scalar, so ``UHUGEINT[]``
exports as ``list<string>``.

The FT_IPv6 caveat
------------------
:mod:`remora.workspace.types` documents that DuckDB exports ``UHUGEINT``
through **Arrow** as ``decimal128(38, 0)`` read as signed, so an address above
2^127 comes back two's-complement negative — wrong, but re-interpretable
mod 2^128. The **Parquet** writer is worse: on duckdb 1.5.5 it writes
``UHUGEINT`` (and ``HUGEINT``) as a ``double``, which has 53 bits of mantissa
against 128 bits of address, so the value is not recoverable at all —
``7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`` and ``8000::`` land on the *same*
double. That is not a corner case: it is every neighbouring pair of addresses.

Shipping that silently is not an option, so an ``UHUGEINT`` column is cast to
``VARCHAR`` and exported as its **exact decimal text** — the same
representation :func:`remora.workspace.types._ipv6_to_decimal_text` already
binds IPv6 with, so decimal text is remora's canonical wire form for an address
rather than a new invention. A reader recovers the address with
``IPv6Address(int(text))``, and DuckDB re-reads the column with
``CAST(col AS UHUGEINT)``.

``INTERVAL`` is rewritten for the same reason: Parquet's own ``INTERVAL``
logical type is millisecond-resolution, so a native write truncates
``FT_RELATIVE_TIME``'s microseconds (1234us becomes 1000us). The text form
(``'00:00:00.001234'``) is exact and casts straight back with
``CAST(col AS INTERVAL)``.

Streaming
---------
The export is exactly one ``COPY … TO … (FORMAT PARQUET)`` statement, executed
by DuckDB end to end: not one row is fetched into Python, so memory stays flat
on a table of any size. The only other statements are two catalog lookups,
neither of which touches the table: the table's column types, which is what the
two rewrites above are decided from, and the file backing the current database,
which is what the destination is checked against below.

Safety
------
Neither a table name nor a file path can be a bound parameter in ``COPY``, so
both are handled by construction: ``table`` is validated against the closed set
:data:`EXPORTABLE_TABLES` and then quoted, and the path is escaped for a
single-quoted SQL string literal. A hostile table name is refused rather than
escaped, which is the only safe treatment for something that has to reach SQL
as an identifier.

The destination is checked too, and for a blunter reason: ``COPY`` overwrites
whatever is at the path, so exporting *onto the workspace* destroys it. All
three spellings do it — the database path itself, a symlink to it, a hard link
to it — and so does the ``.wal`` sidecar, which is the worst of the four
because it fails **silently**: DuckDB replays a write-ahead log on open, and a
log replaced by Parquet bytes is discarded along with every committed row it
still held (measured: 1999 rows down to 1, no error raised). So the destination
is compared against the database file and its ``.wal`` before the ``COPY`` runs
and a match is refused with a :class:`~remora.workspace.errors.WorkspaceError`.
The comparison is by file *identity* — ``(st_dev, st_ino)``, which every
spelling, symlink and hard link of one file shares, the same rule
:mod:`remora.workspace.workspace` keys its coordination registry on — falling
back to a resolved-pathname comparison for a destination that does not exist
yet, which is the normal case for the ``.wal``.

That check alone cannot carry the "under any spelling" guarantee, because it is
check-then-act: ``COPY`` opens the path itself, so between the check and the
open another process could plant a symlink or a hard link to the database at
the destination. The window cannot be closed by checking harder, so the write
does not go to the destination at all. It goes into a private ``0700``
directory created beside the destination, and the finished file is renamed out
of it onto the destination. ``os.replace`` replaces the directory *entry*: it
never follows a symlink and never writes through a hard link, so a link planted
at the destination after the check is simply replaced, and the file it pointed
at — the workspace — is never opened.

The directory is what makes that airtight rather than merely likely. An
unpredictably named temp *file* would not: :func:`tempfile.mkstemp` picks a
name nobody can guess, but the name is in the directory listing as soon as it
exists, and DuckDB opens it afterwards, so it can be swapped for a link in
between — and what survives that today is DuckDB's incidental habit of
unlinking its destination before writing, which is an implementation detail and
not a promise. Inside a ``0700`` directory there is no such window: no other
user can enter it, so the path ``COPY`` opens cannot be tampered with at all.
The rename also makes the destination atomic, which the direct write was not: a
``COPY`` that fails partway used to leave a truncated file where a good export
had been (measured), and now leaves the previous file exactly as it was, with
the temp directory removed.

Two things that leaves, stated rather than implied. **The destination directory
is trusted.** Anyone who can write in it can rename anything onto the
destination name before or after this export, and can do so whether remora
writes there or not; exporting into a directory under someone else's control is
outside what a writer can defend. ``0700`` keeps other *users* out of the temp
directory, and a process running as the exporting user is inside the trust
boundary already — it can open the workspace and the destination directly.
**And an external process moving the actual database file onto the destination
path mid-export is not defended against:** the rename then replaces a directory
entry that is the database, and the database is gone — as it would be for any
writer, because moving a live database out from under one is not a thing a
caller can guard. Both are out of scope here for the same reason they are out
of scope everywhere else in this package.

Connections are supplied by the caller — this module never opens one, because
connection and lock ownership belongs to ``Workspace`` (#28) — and it imports
duckdb only for typing, so it stays importable without it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final

from remora.workspace.errors import WorkspaceError

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = ["EXPORTABLE_TABLES", "TEXT_EXPORTED_TYPES", "export_parquet"]

EXPORTABLE_TABLES: Final[tuple[str, ...]] = ("pkts", "streams", "annotations")
"""The closed set of ``main`` tables :func:`export_parquet` will write.

The catalog in ``meta`` is deliberately absent: it describes a *workspace*, not
a dataset, and exporting it would suggest an import path that does not exist.
"""

TEXT_EXPORTED_TYPES: Final[frozenset[str]] = frozenset({"HUGEINT", "UHUGEINT", "INTERVAL"})
"""Column types cast to ``VARCHAR`` on export, because Parquet loses them.

128-bit integers are written as a ``double`` (53 bits of mantissa) and
``INTERVAL`` is written at millisecond resolution; both losses are silent and
neither is recoverable, so these columns ship as exact text instead. The module
docstring holds the reasoning and the reader-side casts.

Three entries, two divergences: ``UHUGEINT`` and ``INTERVAL`` are the only ones
a remora-written schema can produce, because those are what
:data:`remora.workspace.types.COLUMN_TYPES` maps ``FT_IPv6`` and
``FT_RELATIVE_TIME`` to and no ftype maps to signed ``HUGEINT``. ``HUGEINT`` is
here defensively, for a column some other tool added to a workspace file: it is
lossy in exactly the same way, and the cost of covering it is one set entry.
"""


_WAL_SUFFIX: Final[str] = ".wal"

# Name of the export inside its private temp directory. A constant is safe
# there — the directory is fresh and only this process can enter it — and it
# keeps a destination whose own basename is awkward (``..``, say) out of a path
# that gets built by concatenation.
_TEMP_FILE_NAME: Final[str] = "export.parquet"


def _quote_ident(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


def _quote_literal(value: str) -> str:
    """Escape a string for interpolation into a single-quoted SQL literal."""
    return value.replace("'", "''")


def _split_list_suffix(data_type: str) -> tuple[str, int]:
    """Split a DuckDB type into its element type and its ``LIST`` nesting depth.

    Args:
        data_type: A type as ``duckdb_columns()`` renders it, e.g.
            ``"UHUGEINT"`` or ``"UHUGEINT[]"``.

    Returns:
        The innermost type and how many ``[]`` suffixes were stripped.
    """
    depth = 0
    while data_type.endswith("[]"):
        data_type = data_type[:-2]
        depth += 1
    return data_type, depth


def _select_item(column: str, data_type: str) -> str:
    """Render one column's item in the export projection.

    A column DuckDB can write exactly is selected as it stands; one of
    :data:`TEXT_EXPORTED_TYPES` is cast to text at the same list depth, so a
    ``UHUGEINT[]`` becomes a ``VARCHAR[]`` rather than being flattened.

    Args:
        column: The column name.
        data_type: Its DuckDB type.

    Returns:
        A SQL select item, aliased back to the column's own name.
    """
    quoted = _quote_ident(column)
    element, depth = _split_list_suffix(data_type)
    if element.upper() not in TEXT_EXPORTED_TYPES:
        return quoted
    return f"CAST({quoted} AS VARCHAR{'[]' * depth}) AS {quoted}"


def _database_file(con: DuckDBPyConnection) -> Path | None:
    """The file backing the current database, or ``None`` for an in-memory one.

    Read from the catalog rather than from a caller-supplied path, so the guard
    below protects a connection handed to :func:`export_parquet` directly just
    as well as one owned by a ``Workspace``.

    Args:
        con: An open connection.

    Returns:
        The database file, or ``None`` when there is none to protect.
    """
    row = con.execute(
        "SELECT path FROM duckdb_databases() WHERE database_name = current_database()"
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return Path(str(row[0]))


def _is_same_file(left: Path, right: Path) -> bool:
    """Whether two paths name one file, by identity where possible.

    ``(st_dev, st_ino)`` is the same for every spelling, symlink and hard link
    of one file, which a pathname comparison gets wrong; but a destination that
    does not exist yet cannot be stat'ed, and the ``.wal`` sidecar usually does
    not, so that case falls back to comparing resolved pathnames.

    Args:
        left: One path.
        right: The other.

    Returns:
        Whether both name the same file.
    """
    try:
        left_stat = os.stat(left)
        right_stat = os.stat(right)
    except OSError:
        return os.path.realpath(left) == os.path.realpath(right)
    return (left_stat.st_dev, left_stat.st_ino) == (right_stat.st_dev, right_stat.st_ino)


def _check_destination(target: Path, database: Path | None) -> None:
    """Refuse a destination that is the workspace database or its ``.wal``.

    ``COPY`` overwrites its destination, so this is the difference between an
    export and a deletion. Both the path DuckDB reports and its resolved form
    are checked, so a workspace addressed through a symlink is protected under
    either spelling.

    Args:
        target: Where the export is headed.
        database: The file backing the workspace, or ``None`` for in-memory.

    Raises:
        WorkspaceError: If ``target`` is that file or its write-ahead log.
    """
    if database is None:
        return
    resolved = Path(os.path.realpath(database))
    for candidate in (database, resolved):
        if _is_same_file(target, candidate):
            raise WorkspaceError(
                f"refusing to export to {target}: that is the workspace database "
                f"file itself ({candidate}), and COPY would overwrite it with "
                f"Parquet, destroying the workspace"
            )
        wal = candidate.with_name(candidate.name + _WAL_SUFFIX)
        if _is_same_file(target, wal):
            raise WorkspaceError(
                f"refusing to export to {target}: that is the workspace's "
                f"write-ahead log ({wal}), and overwriting it discards every "
                f"committed row it still holds — silently, since DuckDB opens "
                f"the database afterwards without complaint"
            )


def _make_temp_dir(target: Path) -> Path:
    """Create a private ``0700`` directory to export into, beside ``target``.

    A directory rather than a temporary *file*, because a file's name is no
    protection: :func:`tempfile.mkstemp` picks an unpredictable name, but the
    moment it exists anyone who can list the directory can read that name, and
    DuckDB opens the path by name afterwards — so the name could be swapped for
    a link in between, and only DuckDB's incidental habit of unlinking its
    destination first keeps that from mattering. :func:`tempfile.mkdtemp`
    creates the directory with mode ``0700`` regardless of umask, so no other
    user can enter it, and the path ``COPY`` opens cannot be tampered with at
    all.

    Beside ``target``, so the rename out of it stays on one filesystem and is
    therefore atomic.

    Args:
        target: The eventual destination.

    Returns:
        The private directory, which the caller must remove.

    Raises:
        OSError: If the destination's directory cannot hold it.
    """
    return Path(tempfile.mkdtemp(dir=target.parent or Path(), prefix=f".{target.name}."))


def export_parquet(con: DuckDBPyConnection, table: str, path: str | os.PathLike[str]) -> Path:
    """Write one workspace table to a single Parquet file.

    The whole export is one ``COPY`` statement DuckDB streams to disk, so no
    row is ever materialized in Python. The file holds the table's columns and
    nothing else — no payloads, no unprojected fields, no catalog — so the
    capture remains the source of truth; see the module docstring for the full
    contract and for the ``UHUGEINT``/``INTERVAL`` text rewrites.

    Args:
        con: An open connection to the workspace. Reading only, so a read-only
            connection is fine.
        table: One of :data:`EXPORTABLE_TABLES`. A table name cannot be bound
            as a parameter, so anything else is refused rather than quoted and
            hoped for.
        path: Destination file, replaced if it exists. It must not be the
            workspace database or its ``.wal`` — under any spelling, symlink or
            hard link — since that would destroy the workspace. The file is
            written inside a private ``0700`` directory beside it and renamed
            into place, so the destination is replaced atomically and a failed
            export leaves whatever was there untouched. The destination's own
            directory is trusted; see the module docstring.

    Returns:
        The path written.

    Raises:
        ValueError: If ``table`` is not one of :data:`EXPORTABLE_TABLES`.
        WorkspaceError: If ``path`` is the workspace database file or its
            write-ahead log, checked before anything is written; or if the
            table is missing from the database, which means this is not a
            workspace.
        OSError: If the destination's directory cannot hold the temporary
            directory, or the rename out of it fails.
    """
    if table not in EXPORTABLE_TABLES:
        raise ValueError(
            f"cannot export {table!r}: exportable tables are {', '.join(EXPORTABLE_TABLES)}"
        )
    target = Path(os.fspath(path))
    # Before anything else: COPY overwrites its destination, so a destination
    # that is the workspace itself turns an export into a deletion.
    _check_destination(target, _database_file(con))
    # duckdb_columns() spans attached databases, so pin the probe to the
    # current one exactly like every other catalog probe in this package.
    columns = con.execute(
        "SELECT column_name, data_type FROM duckdb_columns() "
        "WHERE database_name = current_database() AND schema_name = 'main' "
        "AND table_name = ? ORDER BY column_index",
        [table],
    ).fetchall()
    if not columns:
        raise WorkspaceError(f"no main.{table} table in this database; is it a workspace?")
    projection = ", ".join(_select_item(name, data_type) for name, data_type in columns)
    # Export into a private directory and rename the result over the
    # destination. The check above cannot be atomic — COPY opens the path
    # itself, so another process could swap a link in behind it — and
    # os.replace is what closes that window: it replaces the directory *entry*,
    # never following a symlink and never writing through a hard link, so a
    # link swapped in after the check is simply replaced and whatever it
    # pointed at is untouched. It also makes the destination atomic: a failed
    # COPY leaves the previous file exactly as it was instead of a half-written
    # one. The 0700 directory is what makes the path COPY opens untamperable;
    # a bare temp *file* would only have an unpredictable name, which stops
    # protecting the moment the name exists (see _make_temp_dir).
    tmp_dir = _make_temp_dir(target)
    try:
        tmp = tmp_dir / _TEMP_FILE_NAME
        con.execute(
            f"COPY (SELECT {projection} FROM main.{_quote_ident(table)}) "
            f"TO '{_quote_literal(str(tmp))}' (FORMAT PARQUET)"
        )
        # os.replace, not os.rename: on Windows the latter refuses an existing
        # destination. The temp directory is in the destination's own
        # directory, so the rename never crosses a filesystem.
        os.replace(tmp, target)
    finally:
        # Empty after a successful rename; holds the partial export otherwise.
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return target
