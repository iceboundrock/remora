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
one it does not hold is re-attached — and revalidated, unless the peer file's
stamp proves it is the same file untouched (see *Compatibility* below).

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

That check is a statement about the *file*, and a replay happens later, so
:func:`apply_attachments` re-runs it whenever the file may have changed —
compared by the ``(st_dev, st_ino, st_mtime_ns)`` stamp :func:`file_stamp`
takes at attach time. The window it closes is narrow but real: while a peer is
attached it holds a shared read lock, but ``"rw"`` mode attaches nothing
between operations, so the file at that path can be replaced in between and
would otherwise be re-attached unvalidated — reopening exactly the raw-binder
gap the refusal above exists to prevent. The cost of closing it is one ``stat``
per attachment per connection, which is why this module does filesystem I/O at
all; it still opens no connection, spawns nothing and reads no capture.

A stamp is a cheap answer rather than a proof, and its two residuals are
accepted and pinned rather than papered over — an in-place rewrite that keeps
the inode and restores the mtime (:func:`file_stamp`), and the check-then-act
window between the ``stat`` and the ``ATTACH`` (:func:`apply_attachments`).
Both are one connection body wide and both are stated where the code that
relies on them lives.

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
    "FileStamp",
    "apply_attachments",
    "attach_database",
    "attached_databases",
    "detach_database",
    "file_stamp",
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

FileStamp = tuple[int, int, int]
"""``(st_dev, st_ino, st_mtime_ns)`` — enough to tell "same file, untouched"."""


def file_stamp(path: str | os.PathLike[str]) -> FileStamp | None:
    """Identity and mtime of ``path``, or ``None`` if it cannot be stat'ed.

    File *identity* rather than pathname, the same ``(st_dev, st_ino)`` rule
    ``workspace.py`` keys its coordination registry on and ``export.py`` guards
    its destination with — a replacement at one path is a new inode, which a
    pathname comparison cannot see. ``st_mtime_ns`` catches the in-place rewrite
    that keeps the inode, and is integer nanoseconds for the reason
    ``cachekey.py`` gives: exact and platform-stable where the float is neither.

    ``None`` means "cannot prove anything about this file", and every caller
    must treat it as changed rather than as unchanged.

    **Accepted blind spot.** A stamp answers "same file, untouched?" cheaply,
    and buys that cheapness the same way ``cachekey.fingerprint_pcap`` buys
    its own: with a named, pinned residual rather than a proof. An in-place
    rewrite that keeps the inode *and* ends with the original ``st_mtime_ns``
    stamps as unchanged — ``os.utime`` restores it outright, an archiver or a
    ``rsync --times`` puts it back, and a coarse-mtime filesystem can hand two
    genuinely different states one timestamp. The consequence for
    :func:`apply_attachments` is one bare ATTACH of an altered peer per such
    rewrite; ``tests/test_workspace_attach.py::TestStampBlindSpot`` constructs
    exactly that and asserts the peer is attached unvalidated, so the
    limitation is executable rather than aspirational, with a companion test
    showing the same rewrite *without* the timestamp restored still
    revalidates. Closing it would need a content digest of the peer on every
    connection open, which is the catalog read this gate exists to avoid, only
    dearer. A caller who cannot rule out a timestamp-preserving rewrite of a
    peer should :meth:`~remora.workspace.workspace.Workspace.detach` and
    attach it again, which revalidates unconditionally.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_mtime_ns)


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
        stamp: What :func:`file_stamp` returned for ``path`` when the attach was
            validated, or ``None`` when it is not known. :func:`apply_attachments`
            revalidates on replay unless the stamp is present and still matches,
            so ``None`` — the default, and what a caller building an
            ``Attachment`` by hand gets — means "revalidate every time", which is
            the safe direction.
    """

    alias: str
    path: Path
    stamp: FileStamp | None = None


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

    A compatibility check runs only when the peer file may have changed since
    the attach was recorded. :func:`attach_database` validated it then, and
    re-running :func:`check_compatible` on every connection would put a catalog
    read on the hot path of every query — but "validated then" is a statement
    about a *file*, and in ``"rw"`` mode, where nothing is attached and nothing
    is locked between operations, the file at that path can be replaced. So each
    replay compares :func:`file_stamp` against the recorded
    :attr:`Attachment.stamp`: equal means the same inode, untouched, and takes
    the bare ATTACH; anything else — a different inode, a newer mtime, a stamp
    that was never recorded, or a file that cannot be stat'ed at all — takes the
    full :func:`attach_database` path and is revalidated. One ``stat`` per
    attachment per connection, versus a catalog read; and never a blind
    re-attach, which is what let a foreign replacement surface as a raw binder
    error from inside ``alias.meta.fields``. A changed peer stays on the
    revalidating path until it is re-attached: the record is the caller's and is
    not rewritten from here.

    Two residuals, both accepted and stated rather than implied. The stamp's own
    blind spot is documented on :func:`file_stamp`: a rewrite that keeps the
    inode and restores the mtime takes the bare ATTACH. And the gate is
    **check-then-act** — the file can be swapped between the ``stat`` and the
    ``ATTACH``, in which case the replacement is attached unvalidated. That
    window is not closable here, for the same reason ``export.py``'s destination
    check was not: DuckDB opens the peer *by path*, there is no "attach this
    inode", and no amount of checking harder removes the gap. ``export.py``
    escaped its own by writing somewhere private and renaming, which has no
    analogue when the file to open is the caller's, not ours. What bounds it is
    scope rather than probability: it is one connection body wide, because the
    ATTACH's shared read lock then holds the peer for as long as the attachment
    lives, and the *next* replay stats the swapped-in file, sees a stamp that no
    longer matches the record, and revalidates.

    Args:
        con: A freshly opened connection to the primary workspace.
        attachments: The recorded attachments, in the order they were made.

    Raises:
        WorkspaceAliasError: If an alias is already attached to a different file
            or is attached writable, or is not a valid alias.
        SchemaVersionError: If a peer that changed since the attach was recorded
            is no longer a workspace of this layout version. The alias is
            detached again, so a refused replay leaves nothing behind.
        duckdb.Error: If DuckDB refuses an ATTACH — a peer that no longer
            exists, or a lock held by another process's writer.
            ``Workspace.read``/``Workspace.write`` translate these; a caller
            holding its own connection sees them as themselves.
    """
    live = attached_databases(con)
    for attachment in attachments:
        current = live.get(attachment.alias)
        if current is None:
            if attachment.stamp is not None and file_stamp(attachment.path) == attachment.stamp:
                validate_alias(attachment.alias)
                con.execute(
                    f"ATTACH '{_quote_path(str(attachment.path))}' "
                    f"AS {_quote_ident(attachment.alias)} (READ_ONLY)"
                )
            else:
                attach_database(con, attachment)
            continue
        path, read_only = current
        if path != os.path.realpath(attachment.path) or not read_only:
            raise WorkspaceAliasError(
                f"alias {attachment.alias!r} is already attached to {path} "
                f"({'read-only' if read_only else 'read-write'}) rather than to "
                f"{attachment.path} read-only; detach it before reusing the alias"
            )
