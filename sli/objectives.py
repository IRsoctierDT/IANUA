# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Service-level objectives: the committed targets, and where each comes from.

An objective is data, not a comparison written at a call site. Each carries
its own ``direction`` and evaluates its own measurement, so there is exactly
one place a target can be compared the wrong way round — the same reason
``ingest/_coerce.py`` applies the field bound in one place rather than in ten
parsers.

Every target states its derivation in :attr:`Objective.rationale`, and the
numbers that have a source in the repository are *imported* from it rather
than retyped: ``DEFAULT_BATCH`` and ``MAX_BYTES_PER_RUN`` move with the code
they bound. A target with no derivable source is not invented here — see
``backup-present``, which asks whether the platform is restorable at all
rather than asserting a backup cadence the repository does not document.

Security considerations: nothing here reads the filesystem, the network or the
clock. It is a table and a comparison.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from collect import MAX_BYTES_PER_RUN
from pipeline import DEFAULT_BATCH

#: The documented scheduler cadence for both the collector and the detection
#: cycle (``*/5 * * * *`` in ``docs/PRODUCTION_SOC_PLAN.md``, ``OnCalendar=*:0/5``
#: for the systemd units). Freshness targets are three consecutive misses of
#: it, so a single slow pass does not breach and a stopped timer does.
SCHEDULED_INTERVAL_SECONDS = 300.0
MISSES_BEFORE_BREACH = 3
STALENESS_BUDGET_SECONDS = SCHEDULED_INTERVAL_SECONDS * MISSES_BEFORE_BREACH


class Status(Enum):
    """Whether an objective is met, breached, or could not be measured.

    ``UNKNOWN`` is **not** a pass. A signal that cannot be read is the shape
    of failure this whole package exists to catch: ``DESIGN.md`` §11 records
    three signals that read healthy while the subsystem behind them was not,
    and the lesson written there is that an SLI computed over a signal which
    fails open measures nothing. So the three states are distinguished for the
    operator and only one of them is healthy.
    """

    MET = "met"
    BREACHED = "breached"
    UNKNOWN = "unknown"

    @property
    def healthy(self) -> bool:
        """Only ``MET`` is healthy; ``UNKNOWN`` fails closed."""
        return self is Status.MET


class Direction(Enum):
    """Which side of the target is acceptable."""

    AT_MOST = "at most"
    AT_LEAST = "at least"


@dataclass(frozen=True, slots=True)
class Objective:
    """One service-level objective: what is measured, and the bar it must clear."""

    id: str
    title: str
    unit: str
    direction: Direction
    target: float
    #: Where the number comes from. Required rather than optional: a threshold
    #: whose provenance nobody recorded is a threshold the next engineer will
    #: either not dare to change or change without knowing what it meant.
    rationale: str

    def evaluate(self, value: float | None) -> Status:
        """Grade one measurement against this target.

        ``None`` means the indicator could not be measured and grades
        ``UNKNOWN`` — never ``MET``. The comparison lives here so it exists
        once, rather than once per indicator with a chance to be inverted.
        """
        if value is None:
            return Status.UNKNOWN
        if self.direction is Direction.AT_MOST:
            return Status.MET if value <= self.target else Status.BREACHED
        return Status.MET if value >= self.target else Status.BREACHED

    def describe(self) -> str:
        """The objective as a sentence, for a report or a compliance detail."""
        return f"{self.title}: {self.direction.value} {self.target:g} {self.unit}"


#: The committed objectives. Order is the order a report presents them, which
#: follows the data's own path: collected, stored, detected, then the controls
#: that keep the evidence trustworthy and recoverable.
OBJECTIVES: tuple[Objective, ...] = (
    Objective(
        id="collection-pending",
        title="Bytes waiting in declared sources",
        unit="bytes",
        direction=Direction.AT_MOST,
        target=float(MAX_BYTES_PER_RUN),
        rationale=(
            "One collector pass reads at most MAX_BYTES_PER_RUN per source "
            "(imported, not retyped), so more than that still pending means "
            "collection cannot catch up in one pass. This is the indicator a "
            "permanently stalled source shows up in: a source whose offset "
            "stops advancing while its file grows."
        ),
    ),
    Objective(
        id="ingest-freshness",
        title="Age of the newest stored event",
        unit="seconds",
        direction=Direction.AT_MOST,
        target=STALENESS_BUDGET_SECONDS,
        rationale=(
            "Three consecutive misses of the documented */5 collector cadence. "
            "One slow pass must not breach; a stopped timer must."
        ),
    ),
    Objective(
        id="detection-lag",
        title="Store time the detection cycle has not reached",
        unit="seconds",
        direction=Direction.AT_MOST,
        target=STALENESS_BUDGET_SECONDS,
        rationale=(
            "The same three-miss budget against the documented */5 cycle. "
            "Measured between the pipeline cursor and the store's high-water "
            "mark, so it is lag in the data rather than time since a run — a "
            "cycle that runs on time and processes nothing still breaches."
        ),
    ),
    Objective(
        id="detection-backlog",
        title="Events stored but not yet processed",
        unit="events",
        direction=Direction.AT_MOST,
        target=float(DEFAULT_BATCH),
        rationale=(
            "One cycle drains at most DEFAULT_BATCH events (imported, not "
            "retyped), so a backlog above it is one a single cycle can no "
            "longer clear. Reported beside detection-lag because the two fail "
            "differently: a quiet SOC has lag and no backlog."
        ),
    ),
    Objective(
        id="store-intact",
        title="The event store's database is structurally sound",
        unit="(1 = yes)",
        direction=Direction.AT_LEAST,
        target=1.0,
        rationale=(
            "A second objective rather than a widening of store-readable, "
            "because the two failures have different runbook branches and one "
            "indicator carrying both would make its detail ambiguous between "
            "them: a damaged file is restored from a backup, an unreadable "
            "projection is pruned. The same argument earned StoreCorruptionError "
            "its own class. Measured need: on a 1200-event store, 116 of 524 "
            "single-page losses left store-readable reading met while "
            "integrity_check raised, because its probe is a fixed 100-row sample "
            "from the two ends; EventStore.verify_integrity refuses 116 of 116. "
            "Priced at 1.1-1.5 ms/MiB, roughly linear."
        ),
    ),
    Objective(
        id="store-readable",
        title="A bounded query of the event store returns",
        unit="(1 = yes)",
        direction=Direction.AT_LEAST,
        target=1.0,
        rationale=(
            "Not a tautology: DESIGN.md §11 records one over-long message "
            "making every subsequent query raise MalformedProjectionError for "
            "the whole result set, which run_cycle does not catch — one record "
            "stopped every later detection cycle on that store. A store that "
            "accepts writes and cannot be read is the failure this measures. "
            "store/ now raises that row as StoreIntegrityError chained from "
            "the reader's error, which is what lets this probe grade it "
            "breached rather than unmeasurable."
        ),
    ),
    Objective(
        id="audit-chains-intact",
        title="Audit chains that verify",
        unit="fraction",
        direction=Direction.AT_LEAST,
        target=1.0,
        rationale=(
            "Every chain present under the lab root must verify. The evidence "
            "this platform produces is tamper-evident only while its chains "
            "do, so a fraction below 1.0 is not a degraded service but an "
            "untrustworthy one."
        ),
    ),
    Objective(
        id="backup-present",
        title="A backup exists to restore from",
        unit="(1 = yes)",
        direction=Direction.AT_LEAST,
        target=1.0,
        rationale=(
            "Deliberately 'does one exist' and not 'is one recent'. "
            "docs/RESTORE.md documents the backup procedure and the recovery "
            "ordering; it documents no cadence, and inventing one here would "
            "be asserting a requirement the repository does not state "
            "(AGENTS.md §9). The age of the newest backup is reported as "
            "detail for an operator to judge, not graded."
        ),
    ),
)

#: Objectives by id, for a caller holding an indicator and wanting its target.
BY_ID: dict[str, Objective] = {objective.id: objective for objective in OBJECTIVES}
