"""Attaching other workspace files read-only (issue #37).

Cross-capture correlation — the same host seen from two vantage points, or in
two captures taken at different times — is why the workspace is DuckDB-native
rather than a pile of Parquet: DuckDB can ``ATTACH`` a second database file and
join across it in one query. This module owns the policy around that; the
connection it runs on is always supplied by the caller, because connection and
lock ownership belongs to :class:`~remora.workspace.workspace.Workspace`.

Read-only, always
-----------------
Every statement issued here carries ``(READ_ONLY)``, in either workspace mode.
DuckDB enforces it: ``INSERT``/``UPDATE``/``DELETE``/``CREATE``/``ALTER``
against a read-only attachment raise ``Cannot execute statement of type ... on
database "peer" which is attached in read-only mode``. Cross-workspace writes
are out of scope for #37 and this is what keeps them impossible rather than
merely unattempted.

Instance scope, not connection scope
------------------------------------
A DuckDB ``ATTACH`` belongs to the *database instance*, not the connection: a
second same-process connection to the same file sees an attach made on the
first, and the attach disappears only when the last connection to that path
closes. ``Workspace`` in ``"rw"`` mode holds no connection between operations,
so an attach made on one short-lived connection is gone by the next — which is
why :func:`apply_attachments` exists and why ``Workspace`` replays its recorded
attachments onto every connection it opens. Replay is verified rather than
blind: an alias the instance already holds is left alone when it points at the
same file read-only, and refused when it does not.

What an attachment costs
------------------------
A read-only attachment takes a **shared read lock** on the peer file for as
long as it is attached — that is, for as long as a connection carrying it is
open. Three consequences, all measured rather than assumed:

* Another *process* cannot write to an attached file (DuckDB's
  ``Could not set lock on file ...`` ``IOException``), and conversely attaching
  a file another process holds read-write fails the same way.
* Within *this* process the reach of that depends on the attaching workspace's
  mode. In ``"ro"`` mode, where the connection is held continuously, a
  ro-attached file cannot be opened read-write at all — ``Unique file handle
  conflict`` — so ``Workspace(peer, mode="rw")`` operations (``materialize``,
  ``build_streams``, ``compact``, any ``write()``) fail while the peer is
  attached. In ``"rw"`` mode the attachment — and its lock — exists only for
  the duration of each ``read()``/``write()`` body, so between operations the
  peer opens read-write fine. ``Workspace(peer, mode="ro")`` is unaffected
  either way.
* Compaction of the *primary* is unaffected: ``compact()`` opens its own
  connection and replays nothing, and ``COPY FROM DATABASE`` names the current
  database explicitly, so no attachment is ever copied into a compacted file.

Compatibility
-------------
An attached file has to clear the same bar as the primary, or
``alias.meta.fields`` and ``alias.main.pkts`` fail later as raw DuckDB binder
errors far from the cause. :func:`attach_database` therefore runs
:func:`remora.workspace.schema.check_compatible` against the alias and detaches
again on refusal, so a failed attach leaves nothing behind.

Like every module here but ``workspace.py`` this one is import-pure: duckdb is
annotated under ``TYPE_CHECKING`` and no connection is opened.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from remora.workspace.errors import WorkspaceAliasError
from remora.workspace.schema import check_compatible

if TYPE_CHECKING:
    from duckdb import DuckDBPyConnection

__all__ = [
    "RESERVED_ALIASES",
    "Attachment",
    "apply_attachments",
    "attach_database",
    "attached_databases",
    "detach_database",
    "validate_alias",
]

RESERVED_ALIASES: Final[frozenset[str]] = frozenset({"main", "temp", "system"})
"""Database names DuckDB reserves; an ATTACH naming one is a binder error."""

_ALIAS_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Attachment:
    """One workspace attached under an alias.

    Attributes:
        alias: The database name the workspace is reachable as, e.g. ``"peer"``
            for ``peer.main.pkts``. Validated by :func:`validate_alias`.
        path: The attached file, always resolved with :func:`os.path.realpath`
            so it compares equal to the path DuckDB reports back in
            ``duckdb_databases()``.
    """

    alias: str
    path: Path


def validate_alias(alias: str) -> None:
    """Refuse an alias DuckDB cannot use or remora will not quote.

    Args:
        alias: Candidate database alias.

    Raises:
        WorkspaceAliasError: If the alias is not a bare SQL identifier
            (``[A-Za-z_][A-Za-z0-9_]*``) or is one of :data:`RESERVED_ALIASES`.
    """
    if not _ALIAS_RE.fullmatch(alias):
        raise WorkspaceAliasError(
            f"{alias!r} is not a valid workspace alias; use letters, digits and "
            f"underscores, starting with a letter or an underscore"
        )
    if alias.lower() in RESERVED_ALIASES:
        raise WorkspaceAliasError(
            f"{alias!r} is a reserved DuckDB database name "
            f"({', '.join(sorted(RESERVED_ALIASES))}); choose another alias"
        )


def _quote_ident(name: str) -> str:
    """Quote a SQL identifier, escaping embedded double quotes."""
    return '"' + name.replace('"', '""') + '"'


def _quote_path(path: str) -> str:
    """Escape a path for interpolation into a single-quoted SQL literal."""
    return path.replace("'", "''")


def attached_databases(con: DuckDBPyConnection) -> dict[str, tuple[str, bool]]:
    """Every file-backed database attached alongside the current one.

    Args:
        con: An open connection.

    Returns:
        Alias to ``(resolved path, read_only)``. DuckDB's internal ``system``
        and ``temp`` databases carry a ``NULL`` path and are excluded, as is
        the current database itself — this reports what is attached *beside*
        the workspace, which is what the caller records.
    """
    rows = con.execute(
        "SELECT database_name, path, readonly FROM duckdb_databases() "
        "WHERE path IS NOT NULL AND database_name <> current_database()"
    ).fetchall()
    return {
        str(name): (os.path.realpath(str(path)), bool(readonly)) for name, path, readonly in rows
    }


def attach_database(con: DuckDBPyConnection, attachment: Attachment) -> None:
    """Attach one workspace read-only and verify it is one this library reads.

    Args:
        con: An open connection to the primary workspace.
        attachment: The alias and resolved path to attach.

    Raises:
        WorkspaceAliasError: If the alias is not valid.
        SchemaVersionError: If the file is not a remora workspace, or its layout
            version is not this library's. The alias is detached again first, so
            a refused attach leaves nothing behind.
        duckdb.Error: If DuckDB refuses the ATTACH itself — a missing or corrupt
            file, an alias already in use, or a lock held by another writer.
            ``Workspace.attach`` translates these; a caller holding its own
            connection sees them as themselves.
    """
    validate_alias(attachment.alias)
    con.execute(
        f"ATTACH '{_quote_path(str(attachment.path))}' "
        f"AS {_quote_ident(attachment.alias)} (READ_ONLY)"
    )
    try:
        check_compatible(con, database=attachment.alias)
    except BaseException:
        detach_database(con, attachment.alias)
        raise


def detach_database(con: DuckDBPyConnection, alias: str) -> None:
    """Detach ``alias`` if it is attached; do nothing if it is not.

    DuckDB has no ``DETACH IF EXISTS``, so the alias is looked up first. That
    keeps this usable as cleanup on a failed attach, where whether the ATTACH
    landed is exactly what the caller does not know.

    Args:
        con: An open connection.
        alias: The alias to detach.
    """
    if alias in attached_databases(con):
        con.execute(f"DETACH {_quote_ident(alias)}")


def apply_attachments(con: DuckDBPyConnection, attachments: Iterable[Attachment]) -> None:
    """Replay recorded attachments onto a freshly opened connection.

    Idempotent by design: an ATTACH lives on the database *instance*, so a
    connection may already carry an alias that another connection to the same
    file attached. Such an alias is left alone when it names the same file
    read-only, and refused when it does not — silently re-pointing an alias, or
    quietly accepting a writable one, is the failure this verification exists
    to prevent.

    No compatibility check runs here: :func:`attach_database` did it when the
    attachment was recorded, and re-running it on every connection would put a
    catalog read on the hot path of every query.

    Args:
        con: A freshly opened connection to the primary workspace.
        attachments: The recorded attachments, in the order they were made.

    Raises:
        WorkspaceAliasError: If an alias is already attached to a different file
            or is attached writable.
        duckdb.Error: If DuckDB refuses an ATTACH — most often a lock held by
            another process's writer.
    """
    live = attached_databases(con)
    for attachment in attachments:
        current = live.get(attachment.alias)
        if current is None:
            validate_alias(attachment.alias)
            con.execute(
                f"ATTACH '{_quote_path(str(attachment.path))}' "
                f"AS {_quote_ident(attachment.alias)} (READ_ONLY)"
            )
            continue
        path, read_only = current
        if path != os.path.realpath(attachment.path) or not read_only:
            raise WorkspaceAliasError(
                f"alias {attachment.alias!r} is already attached to {path} "
                f"({'read-only' if read_only else 'read-write'}) rather than to "
                f"{attachment.path} read-only; detach it before reusing the alias"
            )
