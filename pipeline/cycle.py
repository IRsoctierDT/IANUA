# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One pass of the detection pipeline: read new events, assemble incidents.

``store/`` holds what happened and ``correlation/`` decides which events were
the same story, but nothing ran either of them except a human at a dashboard.
This is the step that makes the platform *continuous*: a bounded, resumable,
idempotent cycle that a scheduler invokes.

**At-least-once, deliberately.** :func:`run_cycle` returns the new cursor; it
does not persist it. The caller advances the cursor only after the cycle
succeeded, so a crash mid-cycle re-reads the same window rather than stepping
over it. The cost is that events can be processed twice; the benefit is that
they cannot be processed zero times. For a security pipeline that trade is not
close — a duplicate incident is noise an analyst dismisses, while a skipped
window is a blind spot nobody is told about. Reprocessing is safe because
:func:`correlation.assemble` is a pure function of its input and this cycle
persists no incidents.

**One cycle, not a loop.** There is no daemon here. A scheduler the operating
system already runs — cron, a systemd timer — invokes the CLI, and the process
exits. That is less code, less state, and one fewer thing to supervise than a
hand-rolled loop; it is also how ``scripts/audit_maintenance.py`` already
works. ``docs/PRODUCTION_SOC_PLAN.md`` records the timer example.

**No clock, at all.** This cycle never reads one: the window is defined by
the cursor, not by a time range, so there is no "last five minutes" that a
slow run could silently widen or a clock skew could silently narrow. Time
enters only at ``scripts/run_pipeline.py``, and only to timestamp the audit
record — which is what keeps every layer below it reproducible in a test and
in CI, the same discipline as ``as_of`` in ``intel/`` and ``ingested_at`` in
``store/``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from correlation import DEFAULT_THRESHOLDS, Incident, Thresholds, assemble
from store import MAX_QUERY_LIMIT, EventStore, Query

from pipeline.cursor import Cursor

#: Events considered in one cycle. Bounded so a backlog is worked through over
#: several scheduled runs rather than in one unbounded read: the store's own
#: query ceiling would clamp a larger ask anyway, and a cycle that tries to
#: hold the whole backlog is how a scheduled job becomes an outage.
DEFAULT_BATCH = 1_000


@dataclass(frozen=True, slots=True)
class CycleResult:
    """What one cycle did, in enough detail to audit it."""

    #: Events read from the store this cycle.
    events_read: int
    #: Incidents assembled from them, highest score first.
    incidents: tuple[Incident, ...] = field(default_factory=tuple)
    #: Where to resume. ``None`` when nothing was read, in which case the
    #: caller must leave the stored cursor untouched rather than clearing it.
    cursor: Cursor | None = None
    #: The cursor this cycle started from, for the audit record.
    started_from: Cursor | None = None

    @property
    def idle(self) -> bool:
        """Whether there was nothing new. A normal, common outcome."""
        return self.events_read == 0


def run_cycle(
    store: EventStore,
    *,
    cursor: Cursor | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    batch: int = DEFAULT_BATCH,
) -> CycleResult:
    """Read the next window after ``cursor`` and assemble incidents from it.

    Reads **oldest first**: a pipeline must advance through history in the
    order it happened, which is the opposite of the newest-first default a
    dashboard wants.

    Raises :class:`ValueError` for a non-positive ``batch`` rather than
    clamping it — a scheduler configured with a batch of zero would otherwise
    appear to run forever while processing nothing, which is worse than a
    refusal at startup.
    """
    if batch < 1:
        raise ValueError(f"batch must be >= 1, got {batch}")
    window = store.query(
        Query(
            ingested_after=cursor.as_keyset() if cursor is not None else None,
            newest_first=False,
            limit=min(batch, MAX_QUERY_LIMIT),
        )
    )
    if not window:
        return CycleResult(events_read=0, started_from=cursor)
    last = window[-1]
    return CycleResult(
        events_read=len(window),
        incidents=assemble(window, thresholds=thresholds),
        cursor=Cursor(ingested_at=last.ingested_at, event_id=last.event_id),
        started_from=cursor,
    )


def reference(incident: Incident) -> str:
    """A stable short digest over the events an incident was built from.

    ``Incident`` deliberately carries no identifier — ``correlation.assemble``
    is a pure function and invents no state. But this pipeline is
    at-least-once, so a re-read window re-emits a byte-identical incident, and
    an operator looking at two alerts needs to be able to tell "the same story,
    seen twice" from "two stories". Hashing the sorted event ids gives exactly
    that: equal for a replay, different for any change in membership.

    It is a correlation reference, **not** a security claim: it is unkeyed and
    derived from data the store already holds, so it proves nothing about
    origin. Attribution comes from the audit chain, which is hashed and
    signed; this is for deduplication.
    """
    digest = hashlib.sha256()
    for event_id in sorted(incident.event_ids):
        digest.update(event_id.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]
