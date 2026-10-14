"""Event-store error taxonomy.

Imports nothing first-party, so the layering is structural and nothing below
this module can create an import cycle — the same discipline as
``ingest/errors.py`` and ``attack/errors.py``.

Every failure here is fail-closed by intent. An event store that silently
accepts a bad path, an unreadable row, or a schema it does not understand
would produce an analysis built on a partial view of history, and a partial
view presented as complete is the blind spot this layer exists to close.
"""

from __future__ import annotations


class StoreError(Exception):
    """Base class for event-store failures."""


class StorePathError(StoreError):
    """The requested store path is outside the permitted root, or unusable.

    Raised before any file is opened. The store writes under the gitignored
    lab-data root; a path that escapes it (``..``, an absolute path elsewhere,
    a symlink out) is refused rather than normalized, because silently
    relocating a security-evidence database is not a repair.
    """


class SchemaVersionError(StoreError):
    """The database was written by a different schema version.

    There is deliberately no implicit migration. ``NormalizedEvent.from_dict``
    requires an exact key match, so reading rows written under another schema
    would either raise per-row or — worse, if the change were additive in the
    other direction — reconstruct events with silently missing fields. A
    version mismatch is therefore a refusal with both versions named, and
    migration is an explicit, reviewed operation.
    """


class StoreIntegrityError(StoreError):
    """A stored row is not what this store wrote.

    Covers a projection whose content hash does not match its ``event_id``,
    and a row whose JSON will not decode. Both mean the database was modified
    outside this platform. The store surfaces that instead of skipping the
    row, because a query that quietly returns fewer events than history holds
    is indistinguishable to the caller from a quiet period.
    """
