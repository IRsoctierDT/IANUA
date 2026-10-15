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

#: How far back a cycle looks *beyond* the events it is advancing over, in
#: seconds. Fifteen minutes by default: three firings of the documented
#: five-minute timer.
#:
#: **Why any lookback at all.** Without it a cycle correlates exactly the
#: events since the cursor, which partitions the stream — and cross-domain
#: correlation is inherently windowed, not partitioned. An attack whose steps
#: land at 10:02, 10:07 and 10:12 is three one-event cycles, each assembling
#: nothing, and once the cursor passes them no later cycle can recover the
#: story. That was measured, not theorised: the same store correlated in one
#: pass yields a three-domain incident, and through disjoint cycles it yields
#: none, reporting ``exit 0`` and "0 incident(s)" throughout.
#:
#: **What it does not fix.** An incident whose events span longer than the
#: lookback is still cut. That limit is inherent to any stateless window and
#: is the reason persisted, mergeable incidents are the real end state
#: (``docs/PRODUCTION_SOC_PLAN.md`` stage 9). A lookback buys correctness for
#: the common case and states its own boundary rather than hiding it.
DEFAULT_LOOKBACK = 900.0


@dataclass(frozen=True, slots=True)
class CycleResult:
    """What one cycle did, in enough detail to audit it."""

    #: Events read from the store this cycle.
    events_read: int
    #: Incidents assembled over the whole correlation window — the new events
    #: plus the trailing lookback — highest score first. Some of these may have
    #: been reported by an earlier cycle; :attr:`fresh` is the subset that is
    #: not purely historical.
    incidents: tuple[Incident, ...] = field(default_factory=tuple)
    #: Events correlated, which is :attr:`events_read` plus whatever the
    #: lookback pulled in. Reported so an operator can see the window actually
    #: used rather than inferring it.
    events_correlated: int = 0
    #: Where to resume. ``None`` when nothing was read, in which case the
    #: caller must leave the stored cursor untouched rather than clearing it.
    cursor: Cursor | None = None
    #: The cursor this cycle started from, for the audit record.
    started_from: Cursor | None = None
    #: Incidents involving at least one event this cycle had not seen before.
    #: The rest are re-assemblies of history the lookback pulled back in, and
    #: an earlier cycle already reported them.
    #:
    #: Computed from the event ids, so it needs **no persisted state**: an
    #: incident every one of whose events sits at or before the starting cursor
    #: is treated as already reported. That is what keeps a lookback from
    #: turning every cycle into a duplicate alert storm without the cycle having
    #: to remember anything.
    #:
    #: It is a **proxy**, and the one case where it is wrong is worth naming: if
    #: the window *widens* between runs — an operator raising ``lookback`` after
    #: a miss — the wider window can assemble a story entirely from
    #: already-consumed events, and this rule suppresses it even though no cycle
    #: ever reported it. Knowing better would mean persisting the set of
    #: reported references, with its own retention question, so the CLI exposes
    #: ``--include-seen`` instead and leaves that call to the operator who
    #: changed the window. :attr:`incidents` always holds everything assembled.
    fresh: tuple[Incident, ...] = field(default_factory=tuple)

    @property
    def idle(self) -> bool:
        """Whether there was nothing new. A normal, common outcome."""
        return self.events_read == 0

    @property
    def repeats(self) -> int:
        """Incidents the lookback re-assembled that an earlier cycle reported."""
        return len(self.incidents) - len(self.fresh)


def run_cycle(
    store: EventStore,
    *,
    cursor: Cursor | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    batch: int = DEFAULT_BATCH,
    lookback: float = DEFAULT_LOOKBACK,
) -> CycleResult:
    """Read the next window after ``cursor``, correlate it with a trailing
    overlap, and report what to resume from.

    Two windows, and the distinction is the whole design:

    * The **progress window** is the events strictly after ``cursor``. It
      decides how far the cursor moves, and therefore what this cycle has
      consumed.
    * The **correlation window** is that, plus every event ingested within
      ``lookback`` seconds before it. It decides what ``assemble`` is allowed
      to see.

    Keeping them separate is what makes the stage work. A single window would
    have to be either the progress window — which partitions the stream and
    loses any story that straddles a cycle — or the correlation window, which
    would advance the cursor backwards over events already consumed. Reading
    oldest-first within each: a pipeline advances through history forwards,
    which is the opposite of the newest-first default a dashboard wants.

    Raises :class:`ValueError` for a non-positive ``batch`` or a negative
    ``lookback`` rather than clamping — a scheduler configured with a batch of
    zero would otherwise appear to run forever while processing nothing, which
    is worse than a refusal at startup. A ``lookback`` of exactly zero is
    allowed and means "no overlap", which is the old partitioning behaviour and
    is occasionally what a backfill wants.
    """
    if batch < 1:
        raise ValueError(f"batch must be >= 1, got {batch}")
    if lookback < 0:
        raise ValueError(f"lookback must be >= 0 seconds, got {lookback}")

    # Read no more than will actually be correlated. ``assemble`` truncates its
    # input silently (``stored[: thresholds.max_events]``), so a cycle that
    # read past that ceiling would advance the cursor over events nothing ever
    # looked at — a blind spot with no signal, which is the exact failure this
    # stage exists to prevent. Taking the minimum makes the window the cursor
    # advances over a subset of the window ``assemble`` saw.
    #
    # ``MAX_QUERY_LIMIT`` is the store's own ceiling and clamps rather than
    # refuses, because asking for more than the store will serve is a cap, not
    # a caller error.
    ceiling = min(thresholds.max_events, MAX_QUERY_LIMIT)
    progress = store.query(
        Query(
            ingested_after=cursor.as_keyset() if cursor is not None else None,
            newest_first=False,
            limit=min(batch, ceiling),
        )
    )
    if not progress:
        return CycleResult(events_read=0, started_from=cursor)

    last = progress[-1]
    advanced = Cursor(ingested_at=last.ingested_at, event_id=last.event_id)

    # The correlation window starts ``lookback`` before the OLDEST new event,
    # not before the newest: an event that arrived just now needs the context
    # that preceded *it*, and anchoring on the newest would shrink the overlap
    # to nothing whenever a cycle covers a wide span.
    # Context BEHIND the progress window, concatenated rather than filtered.
    #
    # The obvious implementation — read everything from the floor and drop what
    # is newer than the cursor — is wrong, and wrong in the worst direction. A
    # row limit applied newest-first is spent on the rows *above* the boundary,
    # which the filter then discards: on a backlogged store that leaves the
    # correlation window empty while the cursor still advances over everything
    # it consumed. Measured at 200 events read and 0 correlated before this was
    # rewritten — a blind spot worse than the one the lookback exists to close.
    #
    # Bounding the read in SQL instead (``ingested_before``) spends the budget
    # on the newest context actually below the boundary, and building the window
    # by concatenation makes ``progress ⊆ window`` true by construction: no
    # filter can drop an event the cursor is about to cross.
    window = progress
    budget = ceiling - len(progress)
    if lookback > 0 and budget > 0:
        first = progress[0]
        context = store.query(
            Query(
                ingested_from=first.ingested_at - lookback,
                ingested_before=(first.ingested_at, first.event_id),
                newest_first=True,
                limit=budget,
            )
        )
        # Newest-first so the budget buys the most recent context, then reversed
        # so the window stays in ingestion order for ``assemble``.
        window = tuple(reversed(context)) + progress

    incidents = assemble(window, thresholds=thresholds)
    if window is not progress:
        # Also correlate the new events ALONE, and keep anything the wide
        # window missed.
        #
        # Widening is not monotonic. ``assemble`` demotes an entity appearing in
        # more than ``max_entity_fanout`` events to reported context rather than
        # a join key — correctly, since grouping transitively on a shared
        # gateway collapses a window into one false incident. But the extra
        # history the lookback pulls in inflates exactly those counts, so an
        # entity that was a valid join key over the new events can become
        # context over the wider window, and the link is never made. Measured:
        # a score-30 two-domain incident reported at ``lookback=0`` vanished
        # entirely at ``lookback=900`` once the shared principal crossed the
        # fan-out threshold.
        #
        # So the lookback is strictly additive. An incident whose events are a
        # subset of one the wide window already found is dropped as the same
        # story seen with less context; everything else is kept. The cost is one
        # extra assembly over at most ``batch`` events, which is the smaller of
        # the two windows.
        covered = [set(incident.event_ids) for incident in incidents]
        recovered = tuple(
            incident
            for incident in assemble(progress, thresholds=thresholds)
            if not any(set(incident.event_ids) <= seen for seen in covered)
        )
        if recovered:
            # Re-sorted on ``assemble``'s own key so the merged sequence keeps
            # the highest-score-first contract and stays deterministic.
            incidents = tuple(
                sorted(
                    incidents + recovered,
                    key=lambda i: (-i.score, -len(i.event_ids), i.event_ids[0]),
                )
            )
    # An incident is news if it involves any event this cycle had not already
    # consumed. Derived from the ids, so no state is persisted to know it.
    new_ids = {event.event_id for event in progress}
    fresh = tuple(i for i in incidents if new_ids.intersection(i.event_ids))
    return CycleResult(
        events_read=len(progress),
        events_correlated=len(window),
        incidents=incidents,
        cursor=advanced,
        started_from=cursor,
        fresh=fresh,
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
