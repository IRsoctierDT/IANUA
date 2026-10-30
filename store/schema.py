# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Physical schema for the event store — DDL, versioning, content addressing.

Separated from :mod:`store.events` so the storage contract is readable on its
own: what the tables are, why each index exists, and what makes a row
identical to another.

Design notes (DESIGN.md §3, §5):

* **SQLite, from the standard library.** Runtime ``dependencies = []`` is a
  deliberate, load-bearing property of this repository, and a driver for a
  networked database would end it for a single-node deployment that does not
  need one. ``sqlite3`` ships with CPython, gives WAL-mode concurrent readers,
  and enforces the append-only constraint below in the engine rather than in
  Python. Moving to a networked store later is a dependency decision
  (AGENTS.md §5.1) with its own review, not a default taken quietly now.
* **Content-addressed rows.** ``event_id`` is the SHA-256 of the canonical
  projection, so appending the same event twice is a no-op. That is not a
  nicety: collection retries, re-reads a rotated file, or replays a queue, and
  a store that counted those as distinct events would inflate every rate,
  every correlation, and every report drawn from it.
* **Append-only in the engine.** A trigger raises on ``UPDATE``. Discipline in
  the Python API is not a control — anything with the file open could rewrite
  history — so the prohibition lives where the writes land. Deletion is
  permitted only through retention pruning, which is explicit and counted.
* **Indexed for the correlator, not for everything.** The indexed columns are
  exactly the pivots entity resolution needs (time, source, user, host, IP,
  observable). Every other field is reachable through the projection, which
  keeps the row narrow and the write cheap.
"""

from __future__ import annotations

import hashlib

# Both defined in ``ingest.schema`` and re-exported here, so the bytes this
# store hashes and the ceiling it refuses past are the very ones ``ingest``
# fits every event under. They were two copies until a projection built
# entirely from bounded fields measured 66,729 bytes against this 65,536-byte
# ceiling and stalled a collector source; ``store`` imports ``ingest`` and
# never the reverse, so the single definition lives on that side.
from ingest.schema import MAX_PROJECTION_BYTES as MAX_PROJECTION_BYTES
from ingest.schema import canonical_json as canonical_json

#: Bumped whenever the tables, the indexes, or the projection contract change.
#: :class:`store.errors.SchemaVersionError` is raised on any mismatch — there
#: is no implicit migration, by design (see that class's docstring).
SCHEMA_VERSION = 1

#: ``meta`` key holding :data:`SCHEMA_VERSION` for the open database.
VERSION_KEY = "schema_version"

#: ``meta`` key holding the highest ``ingested_at`` ever written.
#:
#: Stored rather than derived from ``MAX(ingested_at)`` because retention
#: deletes rows: a derived watermark would reset the moment a window aged out,
#: and a collector could then stamp an event behind a cursor that had already
#: passed it. A **row** in the existing ``meta`` table, not a column — the DDL
#: is unchanged, so this needs no :data:`SCHEMA_VERSION` bump and
#: ``SchemaVersionError`` is never provoked.
HIGH_WATER_KEY = "ingested_high_water"

#: ``MAX_PROJECTION_BYTES``, imported above, is the ceiling on one serialized
#: projection. ``ingest.normalize`` and ``NormalizedEvent.bounded`` fit every
#: event under it, so a projection past it was built by hand without them.
#: Refused rather than stored, so one pathological row cannot dominate the
#: database.

#: Hard ceiling on rows returned by one query, applied even when a caller asks
#: for more. An unbounded read of a security-event store is how a dashboard
#: query turns into an out-of-memory restart during an incident.
MAX_QUERY_LIMIT = 10_000
#: Domain separator in the completeness digest's preimage, so a digest taken
#: over this store's ids can never be confused with a hash of the same bytes
#: computed for any other purpose.
DIGEST_PREFIX = "ianua.store.attest.v1:"
#: Domain separator for the observables digest, distinct from the event digest's
#: so the two preimages cannot be confused for one another. Versioned on its
#: own: the event digest's definition is unchanged and every manifest written
#: against it stays comparable on that field.
OBSERVABLES_DIGEST_PREFIX = "ianua.store.observables.v1:"


def event_id(projection: str) -> str:
    """The content address of a canonical projection.

    Takes the serialized string rather than the dict so the hash is provably
    over the exact bytes stored, with no chance of hashing one rendering and
    writing another.
    """
    return hashlib.sha256(projection.encode("utf-8")).hexdigest()


#: Executed once per fresh database, inside the same transaction that records
#: the schema version — so a store can never exist with tables but no version,
#: which would read as "written by an unknown schema" on the next open.
DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    -- SHA-256 of `projection`; makes a repeated append a no-op.
    event_id     TEXT PRIMARY KEY NOT NULL,
    -- When this platform stored it. Injected by the caller, never read from a
    -- clock in here, so tests are deterministic and the field cannot drift
    -- with the host's time zone.
    ingested_at  REAL NOT NULL,
    -- When it happened, per the source. NULL when the source carried no
    -- usable timestamp: `ingest/` never back-fills "now", and neither does
    -- this table, because fabricated ordering corrupts correlation.
    occurred_at  REAL,
    source_type  TEXT NOT NULL,
    vendor       TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    -- Denormalized correlation pivots. Copies of projection fields, present
    -- so the correlator can filter in the engine instead of decoding every
    -- row in Python.
    user_name    TEXT,
    hostname     TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    -- The full allow-list projection as canonical JSON. The only source of
    -- truth for a rebuilt event; the columns above are derived from it.
    projection   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS events_occurred_at  ON events (occurred_at);
CREATE INDEX IF NOT EXISTS events_ingested_at  ON events (ingested_at);
CREATE INDEX IF NOT EXISTS events_source_type  ON events (source_type);
CREATE INDEX IF NOT EXISTS events_user_name    ON events (user_name);
CREATE INDEX IF NOT EXISTS events_hostname     ON events (hostname);
CREATE INDEX IF NOT EXISTS events_src_ip       ON events (src_ip);
CREATE INDEX IF NOT EXISTS events_dst_ip       ON events (dst_ip);

-- Observables are one-to-many, so they cannot live in a column. Querying
-- "every event mentioning this hash" is the most common intel pivot there is.
CREATE TABLE IF NOT EXISTS observables (
    event_id TEXT NOT NULL REFERENCES events (event_id) ON DELETE CASCADE,
    value    TEXT NOT NULL,
    PRIMARY KEY (event_id, value)
);

CREATE INDEX IF NOT EXISTS observables_value ON observables (value);

-- Append-only, enforced by the engine. The Python API exposes no update, but
-- an API is not a control: anything holding this file open could rewrite an
-- event. These make the prohibition load-bearing where the writes land.
CREATE TRIGGER IF NOT EXISTS events_append_only
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events is append-only: rewriting a stored event is refused');
END;

CREATE TRIGGER IF NOT EXISTS observables_append_only
BEFORE UPDATE ON observables
BEGIN
    SELECT RAISE(ABORT, 'observables is append-only: rewriting a row is refused');
END;
"""
