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
blind, in both directions: an alias the instance already holds is left alone
when it points at the same file read-only, and refused when it does not, while
one it does not hold is attached through :func:`attach_database` — which
validates it — exactly as the first attach was (see *Compatibility* below).

"Gone by the next" is a statement about the *last* connection closing, not
about one operation ending: any other live connection to the same file — an
enclosing ``read()``/``write()`` body, or one a caller opened themselves — keeps
the instance and its attachments alive. ``Workspace.detach`` documents what
that costs a record-only rw-mode detach; the shared read lock below is held for
exactly the same span.

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

That check is a statement about the *file*, and a replay attaches a file later,
so :func:`apply_attachments` re-runs it on **every** ATTACH it issues rather
than trying to decide in advance that it need not. In ``"rw"`` mode nothing is
attached and nothing is locked between operations, so the file at a recorded
path can be replaced in between; a replay that skipped the check would adopt
the replacement and reopen exactly the raw-binder gap the refusal above exists
to prevent.

Validating **after** the ATTACH rather than before is what makes that airtight,
and it is the whole reason this is not a check-then-act gate. A pre-ATTACH test
— of a stamp, a digest, anything — is a statement about whatever was at the
path when it ran, and DuckDB then opens the path *again*: no amount of checking
harder binds those two operations together, because there is no "attach this
inode" to ask for, and the private-temp-then-rename trick ``export.py`` closes
its own window with has no analogue when the file to open is the caller's
rather than ours. After the ATTACH the peer is open and read-locked, so
``check_compatible`` against the alias reads the file that was *actually*
attached, whatever raced in to become it.

An earlier revision of this module tried to skip the check when a recorded
``(st_dev, st_ino, st_mtime_ns)`` stamp still matched. It was withdrawn as
unsound on both halves — the stat/ATTACH window above, and an in-place rewrite
that restores the mtime, which no stamp can see — and the measurement it was
justifying does not support it either: replay happens once per *connection
open*, and the ATTACH it accompanies already opens the peer file, so the
catalog read is a fraction of a cost that is being paid anyway (measured on
duckdb 1.5.5: ``connect+ATTACH+close`` 6.5 ms, the added validation 1.7 ms,
the ``stat`` it would have replaced 2 µs). Buying 2 µs with a soundness hole is
not a trade this module makes; ``"ro"`` mode, where the connection is held and
the alias stays live, pays nothing either way.

Like every module here but ``workspace.py`` this one is import-pure: duckdb is
annotated under ``TYPE_CHECKING`` and no connection is opened. That is also why
:func:`is_duplicate_database_error` classifies by message text rather than by
exception class — the class is not importable here.
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
    "is_duplicate_database_error",
    "validate_alias",
]

RESERVED_ALIASES: Final[frozenset[str]] = frozenset({"main", "temp", "system"})
"""Database names DuckDB reserves; an ATTACH naming one is a binder error."""

_ALIAS_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_DUPLICATE_DATABASE_RE: Final[re.Pattern[str]] = re.compile(
    r"""database with name ["'`][^"'`\n]*["'`] already exists""", re.IGNORECASE
)
"""What DuckDB says when an ATTACH reuses a live database name.

Measured on duckdb 1.5.5: ``Binder Error: Failed to attach database: database
with name "peer" already exists``. Matched as text because this module never
imports duckdb (it is annotated under ``TYPE_CHECKING`` only), so the exception
*class* is not available to test against.

Two failure directions, guarded from both sides. A *rewording* would silently
degrade the refusal to a generic :class:`WorkspaceError`, which
``tests/test_workspace_attach.py::TestCrossObjectAliasCollision::test_duckdbs_duplicate_message_is_pinned``
catches by asserting the live message from a real duplicate ATTACH. A *false
positive* would misreport some unrelated ATTACH failure as an alias collision,
which is why the database name must appear quote-delimited and newline-free
rather than as a bare ``.*``: the loose form matched anything that merely
mentioned a database and an existing something ("Cannot open database with name
resolution failure; the lock file already exists" is the shape), where this one
needs DuckDB's actual phrasing. The three common quoting styles are all accepted
so a quote-style change is not mistaken for a different error; a deeper rewording
is meant to fail the pin test loudly instead.
"""


def is_duplicate_database_error(exc: BaseException) -> bool:
    """Is ``exc`` DuckDB refusing an ATTACH because the alias is already live?

    An alias collision is a :class:`WorkspaceAliasError` by #37's decision D7,
    but one shape of it reaches DuckDB before remora can see it: same-process
    connections to one file share a database instance, so an alias attached
    through *another* ``Workspace`` object on the same file is live for this one
    while its own record says nothing is attached. ``Workspace.attach`` uses
    this to classify that failure rather than reporting it as a generic
    workspace error.
    """
    return _DUPLICATE_DATABASE_RE.search(str(exc)) is not None


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

    Every ATTACH this issues goes through :func:`attach_database`, so every
    file it attaches is validated **after** it is open and read-locked. There
    is deliberately no cheaper path for a peer believed unchanged: any such
    test would run before the ATTACH, and the ATTACH reopens the path, so the
    file tested and the file attached are two different questions (see the
    module docstring for the withdrawn stamp scheme and the measurement).
    Validating what was actually attached is what makes "a replaced peer is
    never attached blind" true rather than likely.

    **A live alias binds to the file it was attached to, not to the pathname.**
    When the instance already holds the alias, this compares the attached path
    and read-only flag and then leaves it alone — it does not ask whether the
    recorded pathname still resolves to that same file. If a peer is replaced
    at its path while another connection keeps the alias attached, the alias
    goes on serving the old, already-validated file, and ``attachments``
    reports a path whose current contents are not what queries against the
    alias see. That is the contract rather than an oversight, for three
    reasons: the alias belongs to the *instance*, so detaching it to re-attach
    the replacement would yank it out from under every other connection using
    it; the file in use was validated when it was attached, so nothing
    unchecked is being read; and ``"ro"`` mode never re-attaches at all, so
    refusing here would make the guarantee hold in one mode and not the other,
    which is worse than a guarantee stated plainly. The remedy for a caller who
    wants the replacement is
    :meth:`~remora.workspace.workspace.Workspace.detach` and attach again,
    which validates the new file.
    ``tests/test_workspace_attach.py::TestLiveAliasBindsToTheAttachedFile``
    pins it.

    Args:
        con: A freshly opened connection to the primary workspace.
        attachments: The recorded attachments, in the order they were made.

    Raises:
        WorkspaceAliasError: If an alias is already attached to a different file
            or is attached writable, or is not a valid alias.
        SchemaVersionError: If a peer this replay attaches is not a workspace of
            this layout version — whether it changed since the attach was
            recorded or the caller never validated it. The alias is detached
            again, so a refused replay leaves nothing behind.
        duckdb.Error: If DuckDB refuses an ATTACH — a peer that no longer
            exists, or a lock held by another process's writer.
            ``Workspace.read``/``Workspace.write`` translate these; a caller
            holding its own connection sees them as themselves.
    """
    live = attached_databases(con)
    for attachment in attachments:
        current = live.get(attachment.alias)
        if current is None:
            attach_database(con, attachment)
            continue
        path, read_only = current
        if path != os.path.realpath(attachment.path) or not read_only:
            raise WorkspaceAliasError(
                f"alias {attachment.alias!r} is already attached to {path} "
                f"({'read-only' if read_only else 'read-write'}) rather than to "
                f"{attachment.path} read-only; detach it before reusing the alias"
            )
