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
lock), ``1`` the store or the audit write failed, ``2`` bad arguments, ``3``
blocked by policy — which is what an ungranted ``--apply`` returns.

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
under-deletion, never over-deletion, and ``count_before`` uses the identical
predicate so the dry run and the delete always agree.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import math
import sqlite3
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.audit import (  # noqa: E402
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    signing_key_from_env,
)
from agents.policies.bundle import (  # noqa: E402
    DEFAULT_BUNDLE_PATH,
    PolicyBundleError,
    load_bundle,
)
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from pipeline import (  # noqa: E402
    DEFAULT_LOOKBACK,
    CursorError,
    cursor_path,
    load_cursor,
)
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

#: Where the lock lives: beside the store it guards.
LOCK_SUBDIR = Path("data") / "events"
LOCK_FILE = "retention.lock"
AUDIT_FILE = "audit.log"

_DIR_MODE = 0o700
_FILE_MODE = 0o600

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


def _prepare_lock(directory: Path) -> TextIO:
    """Create the lock file before any lock is attempted.

    Separated from :func:`_single_instance` so its ``mkdir``/``touch``/``chmod``
    run inside the caller's startup ``try`` and an unwritable directory becomes
    a message and exit 2 rather than a traceback — the same lesson
    ``scripts/run_collector.py`` records.
    """
    directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    path = directory / LOCK_FILE
    path.touch(mode=_FILE_MODE, exist_ok=True)
    path.chmod(_FILE_MODE)
    # The ``open`` belongs here too. Moving only ``mkdir``/``touch``/``chmod``
    # left a lock path that is a *directory* tracebacking with
    # ``IsADirectoryError`` and exit 1, in all three CLIs that had this fix.
    return path.open("a", encoding="utf-8")


@contextlib.contextmanager
def _single_instance(handle: TextIO) -> Iterator[bool]:
    """Hold an exclusive lock for one pass; yield False if another holds it.

    A declined lock is not an error and must not exit non-zero: a scheduled
    retention pass overlapping a slow one is expected, and failing would mail
    the operator until they learned to ignore it.
    """
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
    cursor_state: str,
    lookback_margin: float,
    margin_withheld: int,
) -> dict[str, object]:
    """The pass's outcome, as data.

    The four cursor fields exist because a clamped pass and a quiet one were
    otherwise indistinguishable in this payload, and that is the shape the
    warn-only option was rejected for: a report that does not say it withheld
    anything is a report an operator cannot act on. ``withheld`` is the number
    the retention window matched and the cursor held back — the thing a stalled
    cycle is costing in disk.
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
        "lookback_margin": lookback_margin,
        "events_withheld_for_correlation": margin_withheld,
    }


def _withheld_line(payload: dict[str, object]) -> str | None:
    """One sentence naming what the cursor held back, or ``None``.

    Printed on every path including the clamped-to-nothing one, because a pass
    that silently reclaims nothing is indistinguishable from a pass with
    nothing to reclaim — and the two call for opposite responses.
    """
    withheld = int(payload["events_withheld_unprocessed"])  # type: ignore[call-overload]
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
    if withheld:
        return (
            f"{withheld} event(s) matched the window and were withheld as not "
            "yet processed by the detection cycle. A stalled cycle stops "
            "retention reclaiming anything; --include-unprocessed overrides it."
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
        print(
            f"nothing to remove: no event was ingested more than "
            f"{payload['keep_days']} day(s) ago ({total} held)."
            if not notes
            else f"nothing to remove under the cursor bound ({total} held)."
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
        f"  nothing was deleted. Re-run with --apply, which requires "
        f"'{ACTION_NAME}:apply' on the policy bundle's allow list. Deletion is "
        "final: the collector's offsets are not rewound, so pruned content "
        "cannot be re-collected."
    )


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


def _processed_bound(root: Path, store: EventStore) -> tuple[float | None, str]:
    """How far the detection cycle is known to have got, and how sure we are.

    Returns ``(bound, state)``. ``bound`` is the newest ``ingested_at`` that is
    safe to delete below; ``None`` means **nothing is known to be processed**,
    which is the fail-closed answer and not an error.

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
    return cursor.ingested_at, "present"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    started_at = time.monotonic()

    try:
        if not math.isfinite(args.keep_days) or args.keep_days < 0:
            raise ValueError(f"--keep-days must be finite and >= 0, got {args.keep_days!r}")
        if not math.isfinite(args.lookback_margin) or args.lookback_margin < 0:
            raise ValueError(
                f"--lookback-margin must be finite and >= 0, got {args.lookback_margin!r}"
            )
        # This CLI had **no** root check at all, so `--root ""` reported on a
        # shadow store in the working directory and `--apply` would have
        # pruned it. Shared with every other entry point now.
        args.root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("retention", args.caller)
        lock_path = confine(args.root, LOCK_SUBDIR, LOCK_FILE, error=StoreError, what="lock")
        engine = load_bundle(args.policy)
        # Last in the startup try, deliberately: the only statement here that
        # opens a descriptor, so nothing can fail after it and abandon the handle.
        lock = _prepare_lock(lock_path.parent)
    except (PrincipalError, PolicyBundleError, StoreError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with _single_instance(lock) as acquired:
        if not acquired:
            print("skipped: another retention pass holds the lock; this invocation did nothing.")
            return 0
        return _run(args, principal=principal, engine=engine, started_at=started_at)


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
        audit = AuditLogger(
            args.root / LOCK_SUBDIR / AUDIT_FILE, signing_key=signing_key_from_env()
        )
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
    threshold = time.time() - args.keep_days * 86_400.0

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
            if mark is not None and threshold > mark and args.keep_days > 0:
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
                print(
                    f"refused: the {args.keep_days} day window reaches past every "
                    f"event in the store — the newest was ingested at {mark}, which "
                    f"is before the threshold {threshold}. Either the clock has "
                    f"stepped forward or collection has been stopped for longer "
                    f"than the window; a pass now would delete the whole store. "
                    f"To purge deliberately, pass --keep-days 0.",
                    file=sys.stderr,
                )
                return 2
            bound, cursor_state = _processed_bound(args.root, store)
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
        # sqlite3.Error is neither OSError nor StoreError. `store/` now maps
        # SQLite's two corruption verdicts to `StoreCorruptionError`, so this
        # clause is defence in depth for the rest — a locked database
        # (SQLITE_BUSY) still arrives here as itself, deliberately.
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
        # Disjoint, not overlapping. `window_matching - matching` is every
        # row the window wanted and the bound refused, which now has two
        # causes; attributing all of it to "not yet processed" made the text
        # form say "3 withheld as not yet processed" about events the cycle
        # had demonstrably processed (measured: 3 reported, of which 2 were
        # the margin's). Subtracting here keeps each sentence true and keeps
        # the two figures summing to the total withheld.
        withheld=window_matching - matching - margin_withheld,
        cursor_state=cursor_state,
        lookback_margin=args.lookback_margin,
        margin_withheld=margin_withheld,
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
                f"before {effective} ({args.keep_days} day(s), cursor "
                f"{cursor_state}, {window_matching - matching - margin_withheld} "
                f"withheld as unprocessed, {margin_withheld} withheld within the "
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
