"""Cross-domain correlation — resolve entities, assemble incidents.

The half of XDR that turns normalized events into a story. ``ingest/``
answers *what was this record*, ``store/`` answers *what happened before*,
and this package answers *which of those were the same event in different
telemetry*.

Typical use::

    from pathlib import Path

    from correlation import assemble
    from store import EventStore, Query

    with EventStore.open(Path(".")) as events:
        window = events.query(Query(since=start, until=end, limit=5_000))

    for incident in assemble(window):
        print(incident.score, incident.domains, incident.reasons)

Two properties worth knowing before trusting the output:

* **Entities merge only on declared, exact rules** — no fuzzy matching. A
  value that names a role rather than an actor (POSIX uid ``0``, a well-known
  SID, ``root``, ``administrator``) is kept as an alias but never links
  events, because merging those would put every host's admin account in one
  entity. Addresses are never merged into hosts: DHCP and NAT reuse them.
* **Over-common entities are demoted, not dropped** — an entity appearing in
  more events than the fan-out threshold becomes ``context_entities`` on the
  incidents it touches. Without that, one shared gateway address collapses a
  whole window into a single meaningless "incident".

Scoring is arithmetic from named constants, and every incident carries the
reasons for its number. ATT&CK stamping is deliberately not here — that is P7
and belongs to the mapping engine.

See ``correlation/README.md`` for the resolution rules and ``DESIGN.md`` §5
boundary 11 for the trust argument.
"""

from __future__ import annotations

from correlation.entities import (
    ENTITY_KINDS,
    HOST_LOCAL_PRINCIPALS,
    NEVER_JOIN,
    Entity,
    EntityKind,
    EntityRef,
    references,
    resolve,
)
from correlation.errors import CorrelationError, ThresholdError
from correlation.incidents import (
    DEFAULT_THRESHOLDS,
    MAX_EVENT_SCORE,
    SCORE_PER_EXTRA_DOMAIN,
    SCORE_PER_EXTRA_ENTITY,
    SCORE_PER_EXTRA_EVENT,
    Incident,
    Thresholds,
    assemble,
)

__all__ = [
    "DEFAULT_THRESHOLDS",
    "ENTITY_KINDS",
    "HOST_LOCAL_PRINCIPALS",
    "MAX_EVENT_SCORE",
    "NEVER_JOIN",
    "SCORE_PER_EXTRA_DOMAIN",
    "SCORE_PER_EXTRA_ENTITY",
    "SCORE_PER_EXTRA_EVENT",
    "CorrelationError",
    "Entity",
    "EntityKind",
    "EntityRef",
    "Incident",
    "ThresholdError",
    "Thresholds",
    "assemble",
    "references",
    "resolve",
]
