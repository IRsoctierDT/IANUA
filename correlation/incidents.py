# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Incident assembly — group events that share a resolved entity, and say why.

One event is a signal. A SOC's actual work is noticing that a cloud role
assumption, an identity sign-in from a new address, and a shell spawning on an
endpoint are *the same story*. That is this module: it takes stored events,
resolves their entities (``correlation.entities``), and groups events that
share one into incidents with an explainable score.

Two controls do most of the work, and both exist because the naive version of
this is actively harmful:

* **Fan-out suppression.** Grouping transitively on any shared entity merges
  everything the moment one entity is common — a default gateway address, a
  jump host, a CI service account. One giant "incident" containing the whole
  window is worse than no correlation at all, because it looks like a finding.
  So an entity appearing in more events than
  :attr:`Thresholds.max_entity_fanout` is demoted to *context*: still shown on
  the incidents it touches, never used to join them.
* **Corroboration required.** A component smaller than
  :attr:`Thresholds.min_events` yields no incident. This mirrors the response
  layer's rule that weak signal produces no plan at all — a single
  unattributed event presented as an "incident" is how false positives become
  pages at 3am.

**Scoring is arithmetic, not judgement.** Every contribution is a named
constant below and every incident carries the reasons that produced its
number, so a score is reproducible from the diff and arguable by an analyst.
The detection plan rejected learned confidence scoring as "non-reproducible,
unreviewable in a diff, breaks hermetic CI"; that verdict applies here.

**ATT&CK is deliberately absent.** Stamping techniques onto an incident is P7
in ``docs/DETECTION_INTELLIGENCE_PLAN.md`` and belongs to the mapping engine,
which already resolves against the pinned corpus. Doing it here would be a
second, unreviewed mapping path.

No clock: the window is whatever the caller already selected from the store.
No filesystem, no network, no subprocess.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ingest.schema import NormalizedEvent
from store.events import StoredEvent

from correlation.entities import Entity, references, resolve
from correlation.errors import ThresholdError

#: Each telemetry domain beyond the first. The heaviest weight, because
#: cross-source corroboration is the whole premise of correlating at all: an
#: endpoint alert that an identity log independently supports is a different
#: proposition from two endpoint alerts.
SCORE_PER_EXTRA_DOMAIN = 20

#: Each distinct joining entity beyond the first. More entities means a wider
#: blast radius, which is worth attention but is weaker evidence than crossing
#: a domain boundary — an attacker touching three hosts and an analyst running
#: a script across three hosts look identical on this axis alone.
SCORE_PER_EXTRA_ENTITY = 5

#: Each event beyond the corroboration minimum, capped: volume is a weak
#: signal and an uncapped per-event score would let one chatty source
#: outrank genuine cross-domain evidence.
SCORE_PER_EXTRA_EVENT = 2
MAX_EVENT_SCORE = 20


@dataclass(frozen=True, slots=True)
class Thresholds:
    """The knobs that decide what counts as an incident.

    Gathered into one reviewable object rather than scattered as arguments,
    because together they *are* the policy: changing ``min_events`` changes
    what the platform will call an incident, and that belongs somewhere a
    reviewer can see all of it at once.
    """

    #: Hard ceiling on events considered in one assembly. Correlation is
    #: superlinear in places; an unbounded window is how an interactive query
    #: becomes an outage.
    max_events: int = 10_000
    #: An incident needs at least this much corroboration.
    min_events: int = 2
    #: An entity in more events than this is context, not a join key. The
    #: default is a starting point, not a truth: the right value depends on
    #: window length and estate size, which is why it is a parameter and why
    #: every incident reports the entities that were demoted.
    max_entity_fanout: int = 50
    #: Ceiling on incidents returned, so a pathological window cannot produce
    #: an unreadable result set.
    max_incidents: int = 500

    def validate(self) -> None:
        """Raise :class:`ThresholdError` on a value that cannot mean anything.

        Raised rather than clamped: an analyst reading "2 events" must be able
        to trust that the minimum was the one configured, not a default
        silently substituted for a nonsensical input.
        """
        if self.max_events < 1:
            raise ThresholdError(f"max_events must be >= 1, got {self.max_events}")
        if self.min_events < 1:
            raise ThresholdError(f"min_events must be >= 1, got {self.min_events}")
        if self.max_entity_fanout < 1:
            raise ThresholdError(f"max_entity_fanout must be >= 1, got {self.max_entity_fanout}")
        if self.max_incidents < 1:
            raise ThresholdError(f"max_incidents must be >= 1, got {self.max_incidents}")


DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True, slots=True)
class Incident:
    """A group of events linked by shared entities, with its reasoning."""

    #: Content addresses of the member events, oldest ingestion first.
    event_ids: tuple[str, ...]
    #: The entities that actually linked these events.
    entities: tuple[Entity, ...]
    #: Entities present but too common in this window to join on. Reported
    #: rather than dropped: "these events also all mention the gateway" is
    #: information, and hiding the demotion would make the grouping
    #: inexplicable.
    context_entities: tuple[Entity, ...]
    #: Distinct ``source_type`` values represented, sorted.
    domains: tuple[str, ...]
    #: Distinct vendors represented, sorted.
    vendors: tuple[str, ...]
    #: Earliest and latest source timestamps, or ``None`` when no member event
    #: carried one. Never substituted with an ingestion time: that would
    #: present a storage fact as an observation about the world.
    first_seen: float | None
    last_seen: float | None
    score: int
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def event_count(self) -> int:
        return len(self.event_ids)


def _entity_index(
    events: tuple[NormalizedEvent, ...], entities: tuple[Entity, ...]
) -> tuple[dict[str, set[int]], dict[int, set[str]]]:
    """Map joining entities to the events they appear in, and the inverse.

    An entity's identity is its ``kind:key`` so a username and a hostname that
    happen to share a string cannot link events to each other.
    """
    alias_to_key: dict[tuple[str, str], str] = {}
    for entity in entities:
        if not entity.joinable:
            continue
        for alias in entity.aliases:
            alias_to_key[(entity.kind, alias)] = f"{entity.kind}:{entity.key}"

    key_to_events: dict[str, set[int]] = {}
    event_to_keys: dict[int, set[str]] = {}
    for index, event in enumerate(events):
        for ref in references(event):
            if not ref.joinable:
                continue
            key = alias_to_key.get((ref.kind, ref.value))
            if key is None:  # pragma: no cover - resolve() covers every ref
                continue
            key_to_events.setdefault(key, set()).add(index)
            event_to_keys.setdefault(index, set()).add(key)
    return key_to_events, event_to_keys


def _components(
    count: int, key_to_events: dict[str, set[int]], event_to_keys: dict[int, set[str]]
) -> list[list[int]]:
    """Connected components over "shares a join key", breadth-first.

    Iterative rather than recursive: a long chain of linked events would
    otherwise be bounded by the interpreter's recursion limit, which is not a
    property anyone should have to reason about here.
    """
    seen: set[int] = set()
    found: list[list[int]] = []
    for start in range(count):
        if start in seen:
            continue
        seen.add(start)
        component = [start]
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for key in event_to_keys.get(current, ()):
                for neighbour in key_to_events.get(key, ()):
                    if neighbour not in seen:
                        seen.add(neighbour)
                        component.append(neighbour)
                        queue.append(neighbour)
        found.append(sorted(component))
    return found


def _score(
    domains: tuple[str, ...], entities: tuple[Entity, ...], events: int, minimum: int
) -> tuple[int, tuple[str, ...]]:
    """The arithmetic, with its reasons. No hidden terms."""
    total = 0
    reasons: list[str] = []
    if len(domains) > 1:
        gain = SCORE_PER_EXTRA_DOMAIN * (len(domains) - 1)
        total += gain
        reasons.append(f"+{gain}: spans {len(domains)} telemetry domains ({', '.join(domains)})")
    if len(entities) > 1:
        gain = SCORE_PER_EXTRA_ENTITY * (len(entities) - 1)
        total += gain
        reasons.append(f"+{gain}: {len(entities)} linked entities")
    extra = max(0, events - minimum)
    if extra:
        gain = min(MAX_EVENT_SCORE, SCORE_PER_EXTRA_EVENT * extra)
        total += gain
        reasons.append(f"+{gain}: {events} events (capped at +{MAX_EVENT_SCORE})")
    if not reasons:
        reasons.append("0: corroborated but single-domain, single-entity")
    return total, tuple(reasons)


def assemble(
    stored: tuple[StoredEvent, ...], *, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> tuple[Incident, ...]:
    """Group ``stored`` events into scored incidents, highest score first.

    Returns an empty tuple rather than a degenerate incident when nothing
    corroborates — "no incident" is a real and common answer.
    """
    thresholds.validate()
    window = stored[: thresholds.max_events]
    if not window:
        return ()
    events = tuple(item.event for item in window)
    entities = resolve(events)
    key_to_events, event_to_keys = _entity_index(events, entities)

    # Fan-out suppression: demote over-common entities before grouping.
    common = {
        key for key, members in key_to_events.items() if len(members) > thresholds.max_entity_fanout
    }
    joining = {key: members for key, members in key_to_events.items() if key not in common}
    joining_inverse = {
        index: {key for key in keys if key not in common} for index, keys in event_to_keys.items()
    }

    by_key = {f"{entity.kind}:{entity.key}": entity for entity in entities if entity.joinable}
    incidents: list[Incident] = []
    for component in _components(len(events), joining, joining_inverse):
        if len(component) < thresholds.min_events:
            continue
        # Sorted by ingestion time, then content address: an incident is
        # evidence, so its member order must be reproducible rather than an
        # artefact of the order the caller happened to pass events in.
        members = sorted(
            (window[index] for index in component),
            key=lambda item: (item.ingested_at, item.event_id),
        )
        member_events = [item.event for item in members]
        domains = tuple(sorted({event.source_type for event in member_events}))
        vendors = tuple(sorted({event.vendor for event in member_events}))
        linking = tuple(
            sorted(
                {
                    by_key[key]
                    for index in component
                    for key in joining_inverse.get(index, ())
                    if key in by_key
                },
                key=lambda entity: (entity.kind, entity.key),
            )
        )
        context = tuple(
            sorted(
                {
                    by_key[key]
                    for index in component
                    for key in event_to_keys.get(index, ())
                    if key in common and key in by_key
                },
                key=lambda entity: (entity.kind, entity.key),
            )
        )
        times = [event.timestamp for event in member_events if event.timestamp is not None]
        score, reasons = _score(domains, linking, len(component), thresholds.min_events)
        incidents.append(
            Incident(
                event_ids=tuple(item.event_id for item in members),
                entities=linking,
                context_entities=context,
                domains=domains,
                vendors=vendors,
                first_seen=min(times) if times else None,
                last_seen=max(times) if times else None,
                score=score,
                reasons=reasons,
            )
        )
    # Highest score first; ties broken deterministically by event count then id.
    incidents.sort(key=lambda i: (-i.score, -i.event_count, i.event_ids[0]))
    return tuple(incidents[: thresholds.max_incidents])
