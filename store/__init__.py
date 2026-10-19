# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Durable, append-only event store — the SOC's memory of what happened.

``ingest/`` turns ten telemetry formats into one :class:`ingest.NormalizedEvent`
but keeps nothing: it is a pure library with no clock, filesystem, network, or
subprocess. This package is the half that persists, so a question like "what
else did this host do in the hour before the alert" has somewhere to be asked.

Typical use::

    import time
    from pathlib import Path

    from ingest import normalize
    from store import EventStore, Query

    with EventStore.open(Path(".")) as events:
        events.append(normalize(record), ingested_at=time.time())

        recent = events.query(Query(hostname="web-01", since=start, until=end))
        for stored in recent:
            print(stored.event.message)

Invariants, each enforced rather than documented:

* **Append-only** — SQLite triggers refuse ``UPDATE``; deletion exists only as
  counted retention pruning via :meth:`EventStore.prune`.
* **Idempotent** — rows are content-addressed, so replaying a batch stores
  nothing new.
* **Tamper-evident** — a projection that does not hash to its ``event_id``
  raises :class:`StoreIntegrityError` on read.
* **No ambient clock** — ``ingested_at`` is injected by the caller.
* **Lab-scoped** — the database lives under gitignored ``data/events/``; a
  filename that escapes it is refused.

See ``store/README.md`` for the storage contract and ``DESIGN.md`` §5
boundary 10 for the trust argument.
"""

from __future__ import annotations

from store.errors import (
    IngestionOrderError,
    SchemaVersionError,
    StoreCorruptionError,
    StoreError,
    StoreFileError,
    StoreIntegrityError,
    StorePathError,
    StoreSidecarError,
)
from store.events import (
    ALL,
    ATTEST_COUNTS_SQL,
    ATTEST_IDS_SQL,
    ATTEST_OBSERVABLES_SQL,
    DEFAULT_FILENAME,
    EVENTS_SUBDIR,
    SIDECAR_SUFFIXES,
    Attestation,
    EventStore,
    Query,
    StoredEvent,
    refuse_unsafe_database,
    refuse_unsafe_sidecars,
)
from store.schema import (
    DIGEST_PREFIX,
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    SCHEMA_VERSION,
    canonical_json,
    event_id,
)

__all__ = [
    "ALL",
    "ATTEST_COUNTS_SQL",
    "ATTEST_IDS_SQL",
    "ATTEST_OBSERVABLES_SQL",
    "DEFAULT_FILENAME",
    "DIGEST_PREFIX",
    "EVENTS_SUBDIR",
    "MAX_PROJECTION_BYTES",
    "MAX_QUERY_LIMIT",
    "SCHEMA_VERSION",
    "SIDECAR_SUFFIXES",
    "Attestation",
    "EventStore",
    "IngestionOrderError",
    "Query",
    "SchemaVersionError",
    "StoreCorruptionError",
    "StoreError",
    "StoreFileError",
    "StoreIntegrityError",
    "StorePathError",
    "StoreSidecarError",
    "StoredEvent",
    "canonical_json",
    "event_id",
    "refuse_unsafe_database",
    "refuse_unsafe_sidecars",
]
