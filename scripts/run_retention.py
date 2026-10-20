#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Apply the event store's retention window: report by default, delete on request.

``EventStore.prune`` has existed since stage 1 and had **no caller**. That is
the gap this closes: a retention mechanism nothing invokes is a retention
policy nobody has.

**Reporting is the default; deleting needs a grant.** The two modes are
deliberately different action classes, because they are different actions:

* a **dry run** deletes nothing, so it is gated ``read_only`` and runs freely;
* ``--apply`` deletes, so it is gated ``destructive`` — which the shipped
  policy sets to ``require_approval``, so it is **refused** until an operator
  adds ``retain_events:apply`` to the ``allow`` list of their policy bundle.

That refusal is the design, not an obstacle to work around. ``05_Governance_Rules.md``
puts "Deleting data" under "Human Approval Required Before", and
``guarded.enforce()`` cannot express a per-invocation prompt — the 2026-08-21
decision established that, and refused to add one. What it *can* express is a
standing grant for one named label in a committed, reviewable file. So the
approval is a deliberate edit an operator makes once and a reviewer can see,
scoped to this one action rather than to every destructive action.

**Deletion here is irreversible in a way the rest of the platform is not.**
The collector's offsets live in their own file (``data/collect/offsets.json``)
and nothing rewinds them. Measured: purge the store, re-run the same collector
invocation against a source that still holds every line, and it reports
"nothing new" and stores zero events. So pruned content cannot be recovered by
re-collection, which is why the default reports instead of acting, and why the
report states what the window covers rather than only how many rows it hits.

**One clock read, and it is the operator's threshold.** Retention is keyed on
``ingested_at`` — the platform's own arrival time — and not on ``occurred_at``,
for the reason ``store/README.md`` already gives: a host with a skewed clock
would otherwise keep its events forever or lose them on arrival.

**Single-instance, like every other scheduled entry point here.**
``AuditLogger`` derives each record's ``seq`` and ``prev_hash`` by reading the
last line and appending, with no lock, so two concurrent appenders fork the
chain and ``verify()`` returns ``False`` for every future reader — a false
positive in a tamper detector. The lock is a correctness control, not an
optimization.

**Exit codes**, which are the whole interface a scheduler sees: ``0`` a pass
ran (including a dry run, and including a skip because another pass held the
lock), ``1`` the store or the audit write failed, ``2`` bad arguments or
the single-instance lock could not be taken, ``3`` blocked by policy — which
is what an ungranted ``--apply`` returns — and ``4`` retryable contention.

``4`` exists because ``1`` used to mean both "the evidence store is damaged"
and "another writer held the lock for five seconds", which an operator must
treat oppositely. ``docs/RETENTION.md`` carried a paragraph warning that
"exit 1 is not always damage" instead of the code distinguishing them; that
paragraph is gone. See ``scripts/_exit_codes.py`` for why this is a new code
rather than ``0`` (nothing observes a pass that never ran) or ``3``
(already "a human must grant this").

**A pass never deletes past the detection cycle, unless an operator says so.**
Retention prunes on ``ingested_at``; the pipeline cursor records how far
detection has got; the two used to be mutually invisible (``grep -ic
'cursor\\|pipeline'`` on this file: 0). Measured, 40 events over 10 days with
only the oldest 5 processed and ``--keep-days 3 --apply``: **24 events
destroyed that the cycle had never looked at**, exit 0, reported as a clean
``events_removed: 29``. ``UPDATE`` is trigger-refused and ``event_id`` is a
sha256 over the projection, so those rows cannot be recovered or
reconstructed — it is evidence destroyed before anything analysed it.

So the threshold is clamped to the cursor, and three states clamp it to
*nothing*: an absent cursor (which is step 3 of ``docs/RESTORE.md``), a cursor
ahead of the newest stored event (the skew that document calls unrecoverable),
and — by refusing with exit 2 rather than guessing — one that will not parse.

**The clamp does not bound the disk, and that is the honest shape of this.**
Measured over a 40-day stall: clamping and refusing grow the store at the same
rate (~+5.0 MB/30 days, +1000 events/10 days); only deleting unprocessed
evidence holds it flat. Nothing bounds the disk during a detection stall except
destroying evidence nobody has looked at, so the trade cannot be engineered
away — it has to be *authorized*. ``--include-unprocessed`` is where, and it is
gated on its own label (:data:`APPLY_UNPROCESSED_LABEL`) so that granting
``retain_events:apply`` does not grant it.

**And a pass refuses when its window reaches past every event in the store.**
That state means nothing has been ingested for a whole retention window, whose
two causes are a forward clock step and collection having been dead that long.
Measured on a caught-up node at the shipped ``--keep-days 90``: a clock jumped
200 days forward removed **29 of 30** events, exit 0, reported as a clean
success. The cursor clamp above bounds that to *processed* events, so no
un-analysed evidence is lost — but the whole analysed evidence base went, on a
clock glitch, at the default setting. ``--keep-days 0`` is exempt because by
the flag's own documentation it means "retain nothing", which is what separates
a deliberate purge from a clock fault without inventing a tolerance.

**And it stops short of the cursor by a margin, because the cycle reads back
into it.** The clamp above bounds a pass to *processed* events; the detection
cycle's lookback exists to re-read *processed* events as correlation context.
Those are the same rows, which took measuring to see: a three-step story
straddling the 90-day boundary — all three steps inside one default 900s
lookback, no concurrency anywhere, every flag defaulted — was reported by the
cycle at **score 52 across three domains** before a documented retention pass
and at **score 30 across two** after it. One event deleted, and what an
analyst reads is still an incident, only smaller and quieter, which is
indistinguishable from a quieter attack. So a pass leaves
``--lookback-margin`` seconds of processed history behind the cursor
(:data:`DEFAULT_LOOKBACK_MARGIN`, which *is* ``pipeline.DEFAULT_LOOKBACK``
rather than a second copy of the number). An operator running the pipeline
with a raised ``--lookback`` must raise this to match; the flag's help says so,
and nothing here can detect it, because the cycle's flag is not recorded
anywhere this pass can read.

That margin is also why there is **no lock between this pass and the cycle**.
The hazard was first written down as a mutual-exclusion problem, and the
measurement refuted it: driving a prune deterministically between the cycle's
two queries gave the *same* degraded score as running the two passes strictly
in sequence, since the row is gone either way. With the margin the two touch
disjoint row ranges by construction, which is stronger than a lock because it
does not depend on every future writer remembering to take one.

One residual, measured and accepted: ``prune`` is ``DELETE ... WHERE
ingested_at < ?`` with no ``event_id`` tie-break, while the cursor is a
``(ingested_at, event_id)`` pair. One ``append_many`` commit stamps every row
with one ``ingested_at``, so the commit the cursor currently sits in is not
deletable until the cursor moves to a later stamp. The error is always
under-deletion, never over-deletion.

**The report must not charge that residual to the detection cycle.** It did:
the withheld figure was ``window_matching - matching - margin_withheld``,
which is every row the bound refused, and it named all of them "not yet
processed by the detection cycle". Measured on one ``append_many`` of 40
events with the cycle demonstrably caught up (``events_read 40``, the next
cycle idle): **40 withheld as not yet processed against a true 0**, and the
same sentence offering ``--include-unprocessed``, which on that store deletes
all 40. Nor is the error the whole commit — with the cursor at the midpoint of
a 40-row commit it was 21, against 19 genuinely unprocessed, so subtracting
the tie group would have under-reported by as much as the old form
over-reported. The unprocessed figure is therefore *counted* in the cursor's
own total order (``count_before(after=...)``), and the already-read part of
its commit is reported as the separate, flagless cause it is.

**And the dry run predicts the delete only if the window is pinned.** The two
passes share one predicate, which is not enough: ``threshold`` is re-derived
from ``time.time()`` per invocation, so whatever aged past the boundary in
between is deleted without having been reported. Measured at one event a
second with six seconds between the two commands: 9 reported, 15 removed, exit
0 both times, the operator's review done against the 9. So a dry run that
matched anything prints the ``--before`` value that pins its own window, and
``--before`` is a *ceiling* — ``min``-ed with the clock-derived threshold and
invisible to the whole-store guard — so a stale, mistyped or hostile value can
never authorize more than ``--keep-days`` already does.

The pin bounds one direction and cannot bound the other, which the report says
rather than implies: if the cursor is **lost** between the two commands — which
``docs/RESTORE.md`` step 3 does by design — the apply clamps to nothing
whatever the pin holds. Measured: 9 reported, 0 removed, ``cursor_state:
absent``, exit 0. A pinned dry run is an upper bound on the delete, never an
equality.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.audit import (  # noqa: E402
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    signer_from_env,
)
from agents.policies.bundle import (  # noqa: E402
    DEFAULT_BUNDLE_PATH,
    PolicyBundleError,
    load_bundle,
)
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from pipeline import (  # noqa: E402
    DEFAULT_LOOKBACK,
    Cursor,
    CursorError,
    cursor_path,
    load_cursor,
)
from scripts._exit_codes import EXIT_RETRYABLE, is_retryable_contention  # noqa: E402
from scripts._locking import LockUnavailableError, prepare_lock, single_instance  # noqa: E402
from store import EventStore, StoreError  # noqa: E402
from store.paths import confine, validated_root  # noqa: E402

#: Default window, in days. A number had to be chosen; this one is the value
#: ``store/README.md`` already used in its illustrative snippet, so the
#: documentation and the default agree rather than offering two numbers.
#: It is not a recommendation — see ``docs/RETENTION.md``, which states the
#: storage cost per day so an operator can pick their own.
DEFAULT_KEEP_DAYS = 90

#: Seconds of already-processed history a pass must leave behind the cursor,
#: because the detection cycle reads back into it.
#:
#: Tied to ``pipeline.DEFAULT_LOOKBACK`` rather than restated, so the two
#: cannot drift apart silently — the number is the cycle's, and retention is
#: the side that has to respect it.
#:
#: **Why this exists.** The cursor clamp bounds a pass to *processed* events;
#: the cycle's lookback exists to re-read *processed* events for correlation
#: context. Those are the same rows, which nobody noticed until it was
#: measured: a story straddling the 90-day boundary, under every shipped
#: default and with no concurrency anywhere, was reported by the cycle at
#: score 52 across three domains before the documented retention pass and at
#: score 30 across two domains after it. One event deleted, and the incident
#: an analyst sees is still an incident — just a quieter, smaller, wrong one.
DEFAULT_LOOKBACK_MARGIN = DEFAULT_LOOKBACK

#: ``--keep-days`` is converted to seconds once, here and in the startup
#: check that the product is finite — see :func:`main`.
_SECONDS_PER_DAY = 86_400.0

#: Where the lock lives: beside the store it guards.
LOCK_SUBDIR = Path("data") / "events"
LOCK_FILE = "retention.lock"
AUDIT_FILE = "audit.log"


ACTION_NAME = "retain_events"
#: Reporting changes nothing; applying deletes. Different actions, so
#: different classes — and the ``destructive`` one is `require_approval` in the
#: shipped bundle, which is the point.
DRY_RUN_CLASS: ActionClass = "read_only"
APPLY_CLASS: ActionClass = "destructive"

#: The label ``--apply --include-unprocessed`` is gated on. **A second,
#: distinct label and not a variant of the first** — that separation is the
#: entire control, and it is measured: a bundle granting only
#: ``retain_events:apply`` answers ``require_approval`` for this one. Folding
#: the two together would let the existing grant self-authorize the wider
#: action, so a security test pins this exact string.
APPLY_UNPROCESSED_LABEL = f"{ACTION_NAME}:apply-unprocessed"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help=(
            "Lab-data root holding data/events/ (default: repo root). Must be an "
            "absolute path that already exists: a typo, or a relative root that is "
            "really the scheduler's working directory, must not build a shadow "
            "tree and report success — still less prune one under --apply."
        ),
    )
    parser.add_argument(
        "--keep-days",
        type=float,
        default=DEFAULT_KEEP_DAYS,
        help=(
            f"Retain events ingested within this many days (default: "
            f"{DEFAULT_KEEP_DAYS}). Keyed on ingestion time, never on the "
            "source's own clock."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Actually delete. Gated as a destructive action, which the shipped "
            "policy sets to require_approval — so this exits 3 until an operator "
            f"adds '{ACTION_NAME}:apply' to the allow list of their policy bundle. "
            "Deletion cannot be undone by re-collection: the collector's offsets "
            "are never rewound."
        ),
    )
    parser.add_argument(
        "--include-unprocessed",
        action="store_true",
        help=(
            "Also delete events the detection cycle has never processed. Gated "
            f"on its own label '{APPLY_UNPROCESSED_LABEL}', separate from "
            f"'{ACTION_NAME}:apply' — granting one does not grant the other. "
            "Without it a pass never deletes past the pipeline cursor, which "
            "means a stalled cycle stops retention reclaiming anything; that is "
            "the trade, and this flag is where an operator accepts it."
        ),
    )
    parser.add_argument(
        "--lookback-margin",
        type=float,
        default=DEFAULT_LOOKBACK_MARGIN,
        help=(
            f"Seconds of processed history to leave behind the cursor for the "
            f"detection cycle to correlate against (default: "
            f"{DEFAULT_LOOKBACK_MARGIN:.0f}, which is the cycle's own default "
            "--lookback). Set this to at least the --lookback the pipeline "
            "runs with: a pass that deletes inside the correlation window "
            "degrades incidents the cycle has not finished assembling, and "
            "reports a smaller one rather than failing. 0 restores the "
            "previous behaviour of pruning right up to the cursor."
        ),
    )
    parser.add_argument(
        "--before",
        type=float,
        default=None,
        help=(
            "Pin the window to this ingestion time (epoch seconds), so an "
            "--apply deletes at most what a dry run reported rather than "
            "re-deriving the boundary from the clock. A dry run prints the "
            "value to pass. It is a ceiling, never a widening: the pass uses "
            "min(this, now - --keep-days), so a stale or mistyped value can "
            "only ever delete less, and the cursor clamp still applies on top. "
            "It cannot bound the other direction: if the cursor is lost in "
            "between, the apply clamps to nothing whatever this holds."
        ),
    )
    parser.add_argument(
        "--caller",
        default=None,
        help="Who this pass is for, recorded in the audit chain. Never inferred.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Policy bundle to enforce (default: the committed bundle).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    return parser.parse_args(argv)


def _report(
    *,
    total: int,
    matching: int,
    threshold: float,
    keep_days: float,
    applied: bool,
    removed: int | None,
    cursor_ingested_at: float | None,
    effective_threshold: float | None,
    withheld: int,
    commit_held: int,
    cursor_state: str,
    lookback_margin: float,
    margin_withheld: int,
    pinned_before: float | None,
) -> dict[str, object]:
    """The pass's outcome, as data.

    The four cursor fields exist because a clamped pass and a quiet one were
    otherwise indistinguishable in this payload, and that is the shape the
    warn-only option was rejected for: a report that does not say it withheld
    anything is a report an operator cannot act on. ``withheld`` is the number
    the retention window matched and the cursor held back — the thing a stalled
    cycle is costing in disk.

    The three withheld figures are **disjoint and complete**: ``withheld`` (the
    cycle has not read them), ``commit_held`` (it has, but they share the
    cursor's own ``ingested_at`` and ``prune`` cannot split a commit) and
    ``margin_withheld`` (it has, and will re-read them as context) sum with
    ``events_matching`` to exactly what the window matched. ``commit_held`` is
    a field rather than prose for that reason alone: without it the payload
    stops accounting for its own window, and ``window_matching`` was never a
    field, so a JSON reader could not reconstruct the total — measured on a
    caught-up single-commit node, the corrected report accounted for 0 of 12
    while the old, wrong one at least showed 12.

    ``pinned_before`` is the ``--before`` value **if it bound the window**, and
    ``None`` otherwise — the fact, not the input. A pin that ``min`` discarded
    is not a cause of anything, and recording the input would put a false one
    into the audit chain, which is append-only and has no amend path: measured,
    a pin ten days in the future produced a record naming a window 100 days
    later than the one the pass actually used.
    """
    return {
        "events_total": total,
        "events_matching": matching,
        "events_retained": total - matching,
        "threshold_ingested_before": threshold,
        "keep_days": keep_days,
        "applied": applied,
        "events_removed": removed,
        "cursor_ingested_at": cursor_ingested_at,
        "cursor_state": cursor_state,
        "effective_threshold": effective_threshold,
        "events_withheld_unprocessed": withheld,
        "events_withheld_at_cursor_stamp": commit_held,
        "lookback_margin": lookback_margin,
        "events_withheld_for_correlation": margin_withheld,
        "window_pinned_before": pinned_before,
    }


def _withheld_line(payload: dict[str, object]) -> str | None:
    """One sentence naming what the cursor held back, or ``None``.

    Printed on every path including the clamped-to-nothing one, because a pass
    that silently reclaims nothing is indistinguishable from a pass with
    nothing to reclaim — and the two call for opposite responses.

    Both figures are folded into *this* sentence rather than given one each,
    because two shares of one number printed by two functions that cannot see
    each other is how "N withheld as not yet processed" came to be printed
    beside a caught-up cycle in the first place.

    Every branch that reports a non-zero figure names
    ``scripts/report_sli.py``'s ``detection-backlog``, and that is not a
    courtesy. Both figures here are **window-scoped** — bounded by
    ``--keep-days`` — and will otherwise be read as the store-wide backlog.
    Measured on one node: this sentence reports 4 while ``detection-backlog``
    on the same root reads 12, with nothing to explain the gap.
    """
    withheld = int(payload["events_withheld_unprocessed"])  # type: ignore[call-overload]
    commit_held = int(payload["events_withheld_at_cursor_stamp"])  # type: ignore[call-overload]
    state = str(payload["cursor_state"])
    if state == "absent":
        return (
            f"{withheld} event(s) matched the window and were withheld: the "
            "detection cycle has recorded no position, so nothing is known to "
            "have been processed. --include-unprocessed overrides this."
        )
    if state == "ahead-of-store":
        return (
            f"{withheld} event(s) matched the window and were withheld: the "
            "cursor is ahead of the newest stored event, so its position cannot "
            "be trusted (docs/RESTORE.md records this skew as unrecoverable)."
        )
    if withheld and commit_held:
        return (
            f"{withheld} event(s) matched the window and were withheld as not "
            f"yet processed by the detection cycle, and {commit_held} more as "
            "already-read rows of the commit the cursor sits inside, which a "
            "threshold cannot split. A stalled cycle stops retention "
            "reclaiming anything; --include-unprocessed overrides it and "
            "would take that whole commit with them. Both figures are bounded "
            "by this window — scripts/report_sli.py's detection-backlog is "
            "the store-wide count."
        )
    if withheld:
        return (
            f"{withheld} event(s) matched the window and were withheld as not "
            "yet processed by the detection cycle. A stalled cycle stops "
            "retention reclaiming anything; --include-unprocessed overrides it. "
            "This figure is bounded by this window — scripts/report_sli.py's "
            "detection-backlog is the store-wide count."
        )
    if commit_held:
        # Deliberately names no flag: these are rows the cycle HAS read, held
        # only because one `append_many` commit carries one `ingested_at` and
        # `prune` has no `event_id` tie-break. On the node that made this
        # sentence necessary the figure was 40 of 40 and
        # `--include-unprocessed` would have deleted every one, so pointing an
        # operator at it here would be the defect this replaces, inverted.
        #
        # And it must not claim the cycle is fine. An earlier draft of this
        # branch said "the detection cycle is not behind, and there is nothing
        # to do — its next tick moves the cursor and the next pass reclaims
        # them". Both halves are false in the state that produces this branch
        # most often: `commit_held > 0` with `withheld == 0` is exactly what a
        # cycle stalled longer than `--keep-days` looks like. Measured on 12
        # events committed 100 days ago with 8 more appended 10 days ago and
        # never read: this branch fires, while `detection-lag` on the same root
        # reads **breached, 7776000s behind** and `detection-backlog` reads 8.
        # The cursor also advances only onto a row keyset-after it, so on a node
        # whose collector has stopped there is no next tick to wait for. The
        # mechanism sentence is gated on `commit_held > 1` because with a tie
        # group of one — what per-event `append` produces — the commit holds a
        # single row and the cause is only `prune`'s strict `<`.
        split = (
            " One append_many commit carries one ingestion stamp, so a "
            "threshold takes all of a commit or none of it."
            if commit_held > 1
            else " prune is a strict `<`, so the row the cursor sits on is never deletable."
        )
        return (
            f"{commit_held} event(s) matched the window and were withheld "
            "because the cursor sits in their commit and the cycle has "
            f"already read them.{split} No flag changes this and "
            "--include-unprocessed is not the remedy: the cursor clears it by "
            "advancing to a later stamp. Whether it is advancing is a separate "
            "question this figure cannot answer — scripts/report_sli.py's "
            "detection-lag and detection-backlog answer it store-wide."
        )
    return None


def _margin_line(payload: dict[str, object]) -> str | None:
    """One sentence naming what the correlation margin held back, or ``None``.

    Separate from :func:`_withheld_line` because the two reasons call for
    opposite responses: events withheld as unprocessed mean the detection
    cycle has stalled and an operator should go and look, while events
    withheld for correlation mean the cycle is working and the margin is doing
    its job. One number covering both would be unactionable.
    """
    held = int(payload["events_withheld_for_correlation"])  # type: ignore[call-overload]
    margin = float(payload["lookback_margin"])  # type: ignore[arg-type]
    if not held:
        return None
    return (
        f"{held} event(s) were processed but withheld anyway: they lie within "
        f"{margin:.0f}s of the cursor, which the detection cycle re-reads as "
        "correlation context. Pruning inside that window degrades incidents "
        "the cycle has not finished assembling — measured at score 52 over "
        "three domains before a pass and 30 over two after it. Lower "
        "--lookback-margin only together with the pipeline's --lookback."
    )


def _notes(payload: dict[str, object]) -> tuple[str, ...]:
    """Every held-back explanation that applies, in a stable order."""
    return tuple(
        line for line in (_withheld_line(payload), _margin_line(payload)) if line is not None
    )


def _window_held(payload: dict[str, object]) -> int:
    """How many rows the window matched and the bound refused, from the payload.

    Asked as a fact rather than inferred from "did any note print", which is
    the proxy :func:`_print_text` used to choose its opening sentence by. The
    proxy is wrong in both directions. One way: the ``absent`` and
    ``ahead-of-store`` branches of :func:`_withheld_line` return a sentence
    unconditionally, *including at zero* — measured on an empty store with no
    cursor at ``--keep-days 0``, nothing was held back and a note still
    printed. The other way: before the cursor's own commit had a sentence of
    its own, a caught-up single-commit node holding 40 matched events printed
    "nothing to remove: no event was ingested more than 0.0 day(s) ago (40
    held)" — no note, and a flat contradiction. Reading the three disjoint
    figures off the payload cannot drift from them, because
    :func:`_report` is where they are computed.
    """
    unprocessed: int = int(payload["events_withheld_unprocessed"])  # type: ignore[call-overload]
    commit: int = int(payload["events_withheld_at_cursor_stamp"])  # type: ignore[call-overload]
    margin: int = int(payload["events_withheld_for_correlation"])  # type: ignore[call-overload]
    return unprocessed + commit + margin


def _print_text(payload: dict[str, object]) -> None:
    matching = int(payload["events_matching"])  # type: ignore[call-overload]
    total = int(payload["events_total"])  # type: ignore[call-overload]
    notes = _notes(payload)
    if payload["applied"]:
        print(f"removed {payload['events_removed']} of {total} event(s)")
        for note in notes:
            print(f"  {note}")
        return
    if matching == 0:
        if _window_held(payload):
            print(f"nothing to remove under the cursor bound ({total} held).")
        elif payload["window_pinned_before"] is not None:
            # The pin emptied the window, and saying "no event was ingested
            # more than N day(s) ago" would be false — measured, 12 events were
            # ingested 100 days ago under a 90-day window pinned 200 days back,
            # and the old text said none were. The chain recorded the pin and
            # the sentence an operator reads did not.
            print(
                f"nothing to remove: --before pinned the window to "
                f"{payload['window_pinned_before']}, which no event precedes "
                f"({total} held)."
            )
        else:
            print(
                f"nothing to remove: no event was ingested more than "
                f"{payload['keep_days']} day(s) ago ({total} held)."
            )
        for note in notes:
            print(f"  {note}")
        return
    print(
        f"would remove {matching} of {total} event(s) ingested before "
        f"{payload['effective_threshold']} "
        f"({payload['keep_days']} day(s) ago); {payload['events_retained']} retained."
    )
    for note in notes:
        print(f"  {note}")
    print(
        f"  nothing was deleted. To remove at most these {matching} and nothing "
        f"else, re-run with --apply --before {payload['effective_threshold']}, "
        f"which requires '{ACTION_NAME}:apply' on the policy bundle's allow "
        "list. Without --before the window is re-derived from the clock when "
        "--apply runs and takes whatever has aged past the boundary since this "
        "report: measured at one event a second, 9 reported and 15 removed six "
        "seconds later. At most, because the pin bounds only that direction — "
        "if the cursor is lost in between, the apply clamps to nothing "
        "(measured: 9 reported, 0 removed). Deletion is final either way: the "
        "collector's offsets are not rewound, so pruned content cannot be "
        "re-collected."
    )


def _pin_clause(pinned_before: float | None) -> str:
    """``, window pinned ...`` when ``--before`` bound the window, else nothing.

    In the chain because the record has to explain its own number: "removed 9
    of 40 before X" reads as a narrower window than ``--keep-days`` asked for,
    and the pin is why. Takes the *resolved* value rather than the flag, so a
    pin ``min`` discarded is never recorded as a cause — the reason string is
    inside the chain's hash and there is no amend path.
    """
    if pinned_before is None:
        return ""
    return f", window pinned to {pinned_before} by --before"


def _margined(bound: float, margin: float) -> float:
    """Pull ``bound`` back by ``margin`` so the correlation window survives.

    Takes a plain ``float``, not ``float | None``: the one caller applies this
    inside the branch where the cursor position is known, and an unknown
    position already clamps the pass to nothing — a margin cannot make
    "nothing" safer. Accepting ``None`` here would have been an unreachable
    branch with a docstring explaining it.

    No floor is applied to the result. A margin reaching below the oldest
    stored event simply matches no rows, which the report states as a withheld
    count; clamping at zero would instead mean an epoch-relative bound quietly
    deleting from a store whose stamps are small, and the test suite uses
    exactly such stamps. ``count_before`` requires only that the bound be
    finite, which :func:`main` validates on the flag.
    """
    return bound - margin


def _processed_bound(root: Path, store: EventStore) -> tuple[Cursor | None, str]:
    """How far the detection cycle is known to have got, and how sure we are.

    Returns ``(cursor, state)``. Its ``ingested_at`` is the newest stamp it is
    safe to delete below; ``None`` means **nothing is known to be processed**,
    which is the fail-closed answer and not an error.

    The whole pair rather than that one stamp, because the clamp and the report
    need different things from it. The clamp needs the stamp: ``prune`` is
    ``ingested_at < ?``. The report needs the ``event_id`` as well, to tell the
    rows of the cursor's own commit the cycle has read from the rows it has
    not — up to one commit's worth of events apart (measured: 40 of 40 on a
    single-commit node), and charging all of them to a stalled cycle is what
    the withheld figure used to do.

    The three states that are not a plain cursor read are each measured, not
    defensive:

    * **absent** — ``docs/RESTORE.md`` step 3 deletes ``cursor.json`` by design
      and step 6 restarts the timers, so this sits on the documented recovery
      path. Treating an absent cursor as "no constraint" gives zero protection
      in precisely the state holding the most unprocessed evidence: measured
      end to end, the documented restore leaves no cursor and the next pass
      destroyed **1500 of 1500** restored events.
    * **ahead of the newest stored event** — the one unrecoverable skew
      ``docs/RESTORE.md`` records. ``sli/indicators.py`` already grades it
      ``UNKNOWN`` for both ``detection-lag`` and ``detection-backlog``;
      retention must not be the single reader that treats it as healthy. A
      clamp would silently bind on nothing there while ``count_before`` still
      reported rows as deletable.
    * **unreadable** — raised, not defaulted, because that is
      ``pipeline/cursor.py``'s own stated posture: "a cursor that will not
      parse raises rather than defaulting", since both available defaults are
      silently wrong.

    Security consideration: this reads one file under the lab-data root and no
    clock. It never writes the cursor — retention must not be able to move the
    pipeline's position, or a destructive pass could authorize its own next one.
    """
    cursor = load_cursor(cursor_path(root))
    if cursor is None:
        return None, "absent"
    mark = store.high_water_mark()
    if mark is not None and cursor.ingested_at > mark:
        return None, "ahead-of-store"
    return cursor, "present"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    started_at = time.monotonic()

    try:
        if not math.isfinite(args.keep_days) or args.keep_days < 0:
            raise ValueError(f"--keep-days must be finite and >= 0, got {args.keep_days!r}")
        # The flag can be finite while the window is not: `1e305 * 86_400.0`
        # overflows to `inf` and the threshold became `-inf`. That was refused
        # — but by `count_before` inside the pass, at exit 1 ("damage, page
        # someone") with the gate decision already in the chain (measured). A
        # bad argument is exit 2 before anything is recorded, so the product
        # is checked where its operand is.
        if not math.isfinite(args.keep_days * _SECONDS_PER_DAY):
            raise ValueError(
                f"--keep-days {args.keep_days!r} is too large to express as a window in seconds"
            )
        if not math.isfinite(args.lookback_margin) or args.lookback_margin < 0:
            raise ValueError(
                f"--lookback-margin must be finite and >= 0, got {args.lookback_margin!r}"
            )
        # Finite only: a `--before` older than the whole store matches nothing,
        # the same harmless direction `_margined` documents for a margin
        # reaching below the oldest event, so there is no lower bound to check.
        #
        # The check is here and not left to `min` because `min` does NOT refuse
        # a NaN — measured, `min(100.0, float("nan")) == 100.0`, so a NaN pin
        # would be silently *discarded* and the pass would run unpinned while
        # the operator believed the window was bounded. That is the opposite of
        # what a non-finite value should do to a destructive pass, and it is
        # why this guard runs before the clock read rather than relying on
        # `count_before`'s own finiteness check further in.
        if args.before is not None and not math.isfinite(args.before):
            raise ValueError(f"--before must be finite, got {args.before!r}")
        # This CLI had **no** root check at all, so `--root ""` reported on a
        # shadow store in the working directory and `--apply` would have
        # pruned it. Shared with every other entry point now.
        args.root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("retention", args.caller)
        lock_path = confine(args.root, LOCK_SUBDIR, LOCK_FILE, error=StoreError, what="lock")
        engine = load_bundle(args.policy)
        # Last in the startup try, deliberately: the only statement here that
        # opens a descriptor, so nothing can fail after it and abandon the handle.
        lock = prepare_lock(lock_path.parent, LOCK_FILE)
    except (PrincipalError, PolicyBundleError, StoreError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Wrapped because the startup `try` has already closed by here, and a
    # lock that fails for a reason that is NOT contention must still be a
    # message and exit 2 rather than a traceback in cron mail. The caught
    # type is deliberately specific: a bare `except OSError` around this
    # block would relabel any failure inside the pass as a lock problem.
    try:
        with single_instance(lock) as acquired:
            if not acquired:
                print(
                    "skipped: another retention pass holds the lock; this invocation did nothing."
                )
                return 0
            return _run(args, principal=principal, engine=engine, started_at=started_at)

    except LockUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _run(
    args: argparse.Namespace,
    *,
    principal: Principal,
    engine: object,
    started_at: float,
) -> int:
    action_class = APPLY_CLASS if args.apply else DRY_RUN_CLASS
    if args.apply and args.include_unprocessed:
        label = APPLY_UNPROCESSED_LABEL
    else:
        label = f"{ACTION_NAME}:{'apply' if args.apply else 'dry-run'}"

    try:
        audit = AuditLogger(args.root / LOCK_SUBDIR / AUDIT_FILE, signer=signer_from_env())
    except (OSError, ValueError) as exc:
        print(f"error: audit log unusable, refusing to run: {exc}", file=sys.stderr)
        return 1

    try:
        enforce(
            action_class=action_class,
            name=label,
            engine=engine,  # type: ignore[arg-type]
            audit=audit,
            actor=principal,
        )
    except ToolBlockedError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        if args.apply:
            print(
                f"hint: --apply is a destructive action. To permit it, add "
                f"'{label}' to the 'allow' list of {args.policy}. That edit is the "
                "human approval this gate requires; it grants exactly this action.",
                file=sys.stderr,
            )
        return 3
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: could not record the gate decision: {exc}", file=sys.stderr)
        return 1

    # The one clock read, and only after the gate permitted the pass.
    clock_threshold = time.time() - args.keep_days * _SECONDS_PER_DAY
    # `min`, so `--before` is a ceiling on the window and never a widening of
    # it: the flag exists to make an --apply delete no more than a dry run
    # reported, and a flag that could reach *past* --keep-days would be a
    # second, ungated way to say "retain nothing".
    threshold = min(clock_threshold, args.before) if args.before is not None else clock_threshold
    # The fact, not the input — see `_report`. A pin `min` discarded explains
    # nothing and must not be recorded as a cause.
    pinned_before = args.before if threshold < clock_threshold else None

    try:
        with EventStore.open(args.root) as store:
            # Before the counts, because both of them lie on a damaged store.
            # Measured: `count()` plans as `SCAN events USING COVERING INDEX
            # events_ingested_at` and `count_before()` as `SEARCH ... COVERING
            # INDEX`, so neither reads a table page. With the events table's
            # row-bearing pages destroyed and its indexes intact, both returned
            # the full pristine count while every route to an actual row raised
            # `database disk image is malformed` — and this pass exited 0 with a
            # report no field of which distinguished that store from a healthy
            # one, then recorded "would remove 200 of 200 event(s)" into a hash
            # chain that verified. Proven causally: damaging
            # `events_ingested_at` as well makes both counts raise.
            #
            # Here and not inside `count()`, because the counts are not wrong —
            # they are answers to a question about the index, and other callers
            # ask it cheaply and often. What is wrong is reporting them, and
            # acting on them, as a census of readable evidence.
            store.verify_integrity()
            total = store.count()
            # What the window alone would take, which is what the report used
            # to call `events_matching`. Kept as a separate figure so a clamped
            # pass can say how much it withheld rather than just reporting a
            # smaller number.
            window_matching = store.count_before(before=threshold)
            mark = store.high_water_mark()
            # The guard tests `clock_threshold`, NOT the pinned `threshold`,
            # and the ordering is deliberate: a forward clock step is exactly
            # what this control detects, so a pin must not be able to silence
            # it. The pin still bounds the damage by itself, which the refusal
            # now says rather than contradicting.
            if mark is not None and clock_threshold > mark and args.keep_days > 0:
                # The window has swallowed the entire store: every event in it
                # is older than the threshold. That happens only when nothing
                # has been ingested for a whole retention window, and the two
                # causes are a forward clock step and collection having been
                # dead that long. Measured on a caught-up node at the shipped
                # default: a clock jumped 200 days forward removed 29 of 30
                # events, exit 0, reported as a clean success. The cursor clamp
                # bounds that to *processed* events — no un-analysed evidence
                # is lost — but the whole analysed evidence base went.
                #
                # `keep_days > 0` is what separates this from a deliberate
                # purge, and it needs no invented magnitude: `--keep-days 0`
                # means "retain nothing" by the flag's own documentation, so an
                # operator who wants everything gone says so and is already
                # gated by `retain_events:apply`. Asserting any particular
                # tolerance in seconds would be inventing a requirement this
                # repository does not state (AGENTS.md §9).
                pinned_note = (
                    f" --before {args.before} would have held this pass to "
                    f"{store.count_before(before=threshold)} event(s), but the "
                    "refusal stands: the clock fault it reports is still there."
                    if pinned_before is not None
                    else ""
                )
                print(
                    f"refused: the {args.keep_days} day window reaches past every "
                    f"event in the store — the newest was ingested at {mark}, which "
                    f"is before the threshold {clock_threshold}. Either the clock has "
                    f"stepped forward or collection has been stopped for longer "
                    f"than the window; an unpinned pass now would delete the whole "
                    f"store.{pinned_note} To purge deliberately, pass --keep-days 0.",
                    file=sys.stderr,
                )
                return 2
            cursor, cursor_state = _processed_bound(args.root, store)
            # The clamp needs only the timestamp; the *report* needs the pair.
            bound = cursor.ingested_at if cursor is not None else None
            if args.include_unprocessed:
                effective: float | None = threshold
                cursor_state = f"{cursor_state} (override)"
            elif bound is None:
                effective = None
            else:
                # `min`, and never `math.nextafter(bound, inf)`. Measured: one
                # `append_many` commit stamps every row with one `ingested_at`
                # — 5000 lines in one collector pass produced exactly one
                # distinct stamp — and `prune` is `DELETE ... WHERE
                # ingested_at < ?`, strict and with no `event_id` tie-break.
                # So a nudge past the cursor's own stamp is all-or-nothing over
                # that whole tie group and destroys the rows the cursor has not
                # passed: 490 of 500 in one measurement. The strict `<` means
                # `min` can only ever under-delete, which is the safe direction.
                #
                # The margin is subtracted from the cursor, not from the
                # threshold: the hazard is not "delete too recently", it is
                # "delete inside the window the detection cycle is about to
                # re-read", and that window is anchored on the cursor.
                effective = min(threshold, _margined(bound, args.lookback_margin))
            if effective is None:
                matching = 0
                removed = 0 if args.apply else None
                # Nothing was deletable anyway: an unknown cursor position
                # already clamps the pass to nothing, so the margin held
                # nothing back of its own and must not claim to have.
                margin_withheld = 0
                # Nor is any of it the cursor's own commit: there is no
                # trustworthy cursor to have one. Both states that reach here
                # (`absent`, `ahead-of-store`) have their own sentence and
                # neither blames the cycle, so the whole window is reported
                # under `withheld` as before — measured unchanged at 30 and 21.
                unprocessed = window_matching
                commit_held = 0
            else:
                matching = store.count_before(before=effective)
                # Attributed separately, with its own count, because folding
                # it into `withheld` would make the report explain these rows
                # as "not yet processed by the detection cycle" — the opposite
                # of true. They are withheld *because* they were processed and
                # the cycle still needs them as context. An operator watching
                # a withheld figure grow has to be able to tell a stalled
                # cycle (act now) from the margin (bounded, working).
                #
                # Counted BEFORE the prune below, deliberately: afterwards the
                # `matching` rows are gone, so `count_before(unmargined)`
                # would already equal the margin's own set and subtracting
                # `matching` a second time would report 0 on every applied
                # pass — the figure wrong in exactly the regime it matters.
                if bound is not None and not args.include_unprocessed and args.lookback_margin > 0:
                    unmargined = store.count_before(before=min(threshold, bound))
                    margin_withheld = max(0, unmargined - matching)
                else:
                    margin_withheld = 0
                if cursor is None or args.include_unprocessed:
                    # `cursor is None` here means --include-unprocessed, the
                    # only way `effective` is not None without one. The
                    # override deletes the window whole, so nothing is
                    # withheld and this subtraction is 0 by construction
                    # (`matching == window_matching`, margin gated off).
                    unprocessed = window_matching - matching - margin_withheld
                    commit_held = 0
                else:
                    # Counted in the cursor's own total order, not derived by
                    # subtracting two timestamp counts. The old expression
                    # `window_matching - matching - margin_withheld` is every
                    # row the bound refused, and it had a third cause nothing
                    # separated: `prune` has no `event_id` tie-break, so the
                    # part of the cursor's own commit the cycle HAS read is
                    # held back too. Charging that to the cycle made the
                    # report say "40 withheld as not yet processed" on a node
                    # whose cycle had just read all 40 (true figure: 0), and
                    # offer `--include-unprocessed`, which there deletes the
                    # whole store.
                    #
                    # Subtracting the tie group instead was measured and
                    # refuted: with the cursor at the midpoint of a 40-row
                    # commit the group is 40 and the inflation is 21, so that
                    # would report 0 where 19 rows are genuinely unread —
                    # trading an over-report for an under-report on the one
                    # figure an operator uses to decide the cycle has stalled.
                    # Only the keyset knows the difference.
                    #
                    # Exactness is structural, not approximate: every row
                    # keyset-after the cursor has `ingested_at >= bound >=
                    # effective`, so that set and `matching` are disjoint.
                    unprocessed = store.count_before(before=threshold, after=cursor.as_keyset())
                    commit_held = max(0, window_matching - matching - margin_withheld - unprocessed)
                removed = store.prune(before=effective) if args.apply else None
    except CursorError as exc:
        # Not a StoreError and not a ValueError — `CursorError` derives from
        # `PipelineError(Exception)`, so it would otherwise reach an unattended
        # scheduler as a traceback. That is a shape this file has already been
        # fixed for twice.
        print(
            f"error: the pipeline cursor is unreadable, refusing to prune: {exc}", file=sys.stderr
        )
        return 2
    except (StoreError, sqlite3.Error, ValueError, OSError) as exc:
        # sqlite3.Error is neither OSError nor StoreError. `store/` maps
        # SQLite's two corruption verdicts to `StoreCorruptionError`, so this
        # clause is defence in depth for the rest — and a locked database
        # (SQLITE_BUSY) arrives here as itself, deliberately, which is what
        # the discrimination below is for. The order matters: contention is
        # tested FIRST, because every contention error is also a
        # `sqlite3.Error` and would otherwise be reported as damage.
        if is_retryable_contention(exc):
            print(f"error: the store is busy, nothing was pruned: {exc}", file=sys.stderr)
            return EXIT_RETRYABLE
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = _report(
        total=total,
        matching=matching,
        threshold=threshold,
        keep_days=args.keep_days,
        applied=bool(args.apply),
        removed=removed,
        cursor_ingested_at=bound,
        effective_threshold=effective,
        # Disjoint, complete, and now *counted* rather than derived. The
        # three figures sum with `matching` to `window_matching`; see
        # `_report`'s docstring for why all three are reported.
        #
        # One expression, read by both this payload and the audit reason
        # below. It used to be written out twice, independently, so a change
        # to one would have left the JSON report and the hash-chained record
        # disagreeing about the same pass — and the chain has no amend path.
        withheld=unprocessed,
        commit_held=commit_held,
        cursor_state=cursor_state,
        lookback_margin=args.lookback_margin,
        margin_withheld=margin_withheld,
        pinned_before=pinned_before,
    )

    # Audited before the report, as elsewhere here: the deletion has already
    # happened by this point, so a failed report must not leave the chain
    # silent about it.
    try:
        audit.record(
            actor=principal.render(),
            action=f"{ACTION_NAME}:{removed if args.apply else matching}",
            action_class=action_class,
            decision="allow",
            reason=escape_delimiter(
                f"{'removed' if args.apply else 'would remove'} "
                f"{removed if args.apply else matching} of {total} event(s) ingested "
                f"before {effective} ({args.keep_days} day(s)"
                f"{_pin_clause(pinned_before)}, cursor "
                f"{cursor_state}, {unprocessed} "
                f"withheld as unprocessed, {commit_held} withheld in the cursor's "
                f"own commit, {margin_withheld} withheld within the "
                f"{args.lookback_margin:.0f}s correlation margin); "
                f"{'applied' if args.apply else 'dry run, nothing deleted'}"
            ),
        )
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: pass ran but could not be recorded: {exc}", file=sys.stderr)
        return 1

    try:
        if args.json:
            payload["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
            print(json.dumps(payload, sort_keys=True))
        else:
            _print_text(payload)
    except OSError as exc:
        print(f"error: pass ran but its report could not be written: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
