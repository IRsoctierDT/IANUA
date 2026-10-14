#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Run one detection cycle: read new events, assemble incidents, advance.

This is the process a scheduler invokes. It is the only place in the pipeline
that reads a clock, opens a file by an operator-supplied path, or decides that
a cycle is permitted — everything below it is a pure function of its inputs.

**Policy-gated and fail-closed.** The cycle runs through
``agents.tools.guarded.enforce`` as ``read_only``, so a deployment that
re-gates that class (``PolicyEngine``'s classes are configurable) stops the
pipeline rather than having it quietly keep reading. A blocked decision raises
and nothing is read.

**Two records per cycle.** The gate decision and the cycle outcome are
separate facts, so they are separate audit entries: if a run dies mid-cycle
the chain shows a permitted attempt with no outcome, which is the thing an
operator needs to see. A single combined record could only be written after
the work, and so could never describe a run that did not finish.

**Audited before the cursor moves, deliberately.** The audit record is written
first, then the cursor is saved. The reverse order has a bad failure: if the
save succeeded and the audit write then failed, the pipeline would have
consumed a window with no record that it did. In this order a failure between
the two means the window is re-read — which is what at-least-once already
promises, and which the audit record already described.

**No ambient identity.** ``--caller`` is optional and must be passed
explicitly. This program does not read ``$USER``, ``$SUDO_USER`` or any other
environment variable to decide who is asking: an audit record naming whoever
happened to own the cron job is an unauthenticated claim, and the audit chain
is the one place in this repository where that matters most.

Usage::

    python scripts/run_pipeline.py                     # one cycle, default root
    python scripts/run_pipeline.py --batch 500 --json   # machine-readable
    python scripts/run_pipeline.py --dry-run            # report, do not advance
    python scripts/run_pipeline.py --caller ivan        # attribute the run

Schedule examples::

    # crontab: every five minutes, output appended to a log the operator reads
    */5 * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python \\
        scripts/run_pipeline.py --root /srv/ianua --caller soc-timer \\
        >> /srv/ianua/data/pipeline/run.log 2>&1

    # systemd: a oneshot unit plus OnCalendar=*:0/5 timer. Prefer this — it
    # gives you Persistent=true (a missed window runs on boot rather than
    # being lost) and the unit's own sandboxing (ProtectSystem, ReadWritePaths
    # limited to the data root).

**Two windows, not one.** A cycle advances its cursor over the events since
the last one, but *correlates* those alongside a trailing ``--lookback`` of
already-consumed history. Without that overlap the cursor partitions the event
stream, and cross-domain correlation is windowed rather than partitioned: an
attack landing at 10:02, 10:07 and 10:12 becomes three one-event cycles that
each assemble nothing, with no later cycle able to recover the story. Incidents
the lookback re-assembles are reported once, when they are new or when they
grow; see ``pipeline.CycleResult.fresh``.

**One cycle at a time.** An exclusive lock is held for the whole cycle. Two
cycles appending to the hash-chained audit log at once fork the chain and break
``verify()`` permanently, which would put a false positive into a tamper
detector — see :func:`_single_instance`. A declined lock exits ``0``: the timer
outrunning the cycle is expected on a tight schedule, not a failure.

Exit codes:

* ``0`` — a cycle ran (including the idle case), or was skipped because another
  cycle held the lock. The output distinguishes the three.
* ``1`` — the cycle, the audit write, or the cursor save failed. The window was
  not consumed; the next invocation re-reads it.
* ``2`` — bad arguments, an unreadable or unsafe ``--root``, or an unusable
  policy bundle. Nothing ran and nothing was recorded.
* ``3`` — blocked by policy. The gate decision *is* recorded.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import sqlite3
import sys
import time
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import (  # noqa: E402
    ActionClass,
    PolicyEngine,
    Principal,
    PrincipalError,
    escape_delimiter,
)
from agents.policies.audit import (  # noqa: E402
    AuditFieldError,
    AuditLogger,
    signing_key_from_env,
)
from agents.policies.bundle import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle  # noqa: E402
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from correlation import ThresholdError, Thresholds  # noqa: E402
from pipeline import (  # noqa: E402
    DEFAULT_BATCH,
    DEFAULT_LOOKBACK,
    CursorError,
    CycleResult,
    cursor_path,
    load_cursor,
    reference,
    run_cycle,
    save_cursor,
)
from store import EventStore, StoreError  # noqa: E402

#: The pipeline's own audit log, beside its cursor under the lab-data root.
#: Mirrors ``compliance/evidence.py``, which keeps its chain at
#: ``data/compliance/audit.log`` rather than sharing one global file: a
#: per-subsystem chain means a corrupted pipeline log cannot invalidate the
#: compliance evidence chain, or the reverse.
AUDIT_FILE = "audit.log"

#: What the policy engine is asked about. A cycle reads the event store and
#: writes one cursor; it mutates no host, sends no packet, and touches no
#: credential.
ACTION_CLASS: ActionClass = "read_only"
ACTION_NAME = "pipeline_cycle"

#: Single-instance lock, beside the cursor. A correctness control, not an
#: optimization — see :func:`_single_instance`.
LOCK_FILE = "cycle.lock"

#: Owner-only, matching the cursor and the audit log.
_FILE_MODE = 0o600


@contextlib.contextmanager
def _single_instance(directory: Path) -> Iterator[bool]:
    """Hold an exclusive lock for the duration of one cycle.

    **A correctness control, not a performance one.** Two cycles running at
    once corrupt the audit log *permanently*: :class:`AuditLogger` derives each
    record's ``seq`` and ``prev_hash`` by reading the last line of the file and
    then appending — a read-modify-write with no locking. Two appenders
    interleave, produce a duplicate ``seq`` and a forked chain, and
    ``verify()`` returns ``False`` from then on, for every future reader. That
    is worse than losing records: it puts a false positive into a tamper
    detector, so an operator can no longer tell overlapping timer firings from
    someone editing the log. Reproduced with six concurrent invocations before
    this lock existed: twelve records, a duplicate ``seq``, ``verify()``
    ``False``, and every process exiting ``0``.

    Overlap is not hypothetical. ``docs/PRODUCTION_SOC_PLAN.md`` documents a
    ``*/5 * * * *`` schedule, so it happens the first time a cycle takes more
    than five minutes — a backlog, a slow disk, a large batch.

    It also removes a milder race: two cycles reading the same window and the
    slower one writing its older cursor last, losing the newer one.
    At-least-once makes that safe rather than wrong, but there is no reason to
    keep it.

    Yields ``True`` when the lock was taken, ``False`` when another cycle holds
    it. A declined lock is **not an error** — it is the timer outrunning the
    cycle, which a tight schedule is expected to do occasionally — so it must
    not exit non-zero and mail the operator every five minutes. It is still
    printed, because a cycle that silently did nothing is the failure mode this
    whole stage exists to avoid.
    """
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / LOCK_FILE
    # Opened for append so an existing lock file is never truncated: the open
    # file handle carries the lock, not the contents.
    with path.open("a", encoding="utf-8") as handle:
        path.chmod(_FILE_MODE)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # BlockingIOError on Linux; OSError covers the platform variants.
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
            "Lab-data root holding data/events/ and data/pipeline/ (default: repo "
            "root). Must already exist: the pipeline creates data/ beneath it but "
            "never the root itself, so a typo fails loudly instead of building a "
            "shadow tree and reporting idle forever."
        ),
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=DEFAULT_BATCH,
        help=f"Events to read in this cycle (default: {DEFAULT_BATCH}).",
    )
    parser.add_argument(
        "--lookback",
        type=float,
        default=DEFAULT_LOOKBACK,
        help=(
            "Seconds of already-consumed history to correlate alongside the new "
            f"events (default: {DEFAULT_LOOKBACK:.0f}). 0 disables the overlap, which "
            "partitions the stream and loses any incident spanning two cycles."
        ),
    )
    parser.add_argument(
        "--caller",
        default=None,
        help="Who this run is for, recorded in the audit chain. Never inferred.",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=None,
        help="Override the corroboration threshold for an incident.",
    )
    parser.add_argument(
        "--max-entity-fanout",
        type=int,
        default=None,
        help="Override the fan-out above which an entity is context, not a join key.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the cycle and report, but leave the stored cursor untouched.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Declarative policy bundle to gate the cycle against (fail-closed).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    return parser.parse_args(argv)


def _thresholds(args: argparse.Namespace) -> Thresholds:
    """Build thresholds from the defaults plus any explicit override.

    Overrides are applied only when passed, so the committed defaults stay the
    single description of what this platform calls an incident.
    """
    overrides: dict[str, int] = {}
    if args.min_events is not None:
        overrides["min_events"] = args.min_events
    if args.max_entity_fanout is not None:
        overrides["max_entity_fanout"] = args.max_entity_fanout
    thresholds = Thresholds(**overrides)
    thresholds.validate()
    return thresholds


def _report(result: CycleResult, *, elapsed: float, advanced: bool) -> dict[str, object]:
    """The run's outcome as JSON-serializable data, for a machine reader."""
    return {
        "events_read": result.events_read,
        "idle": result.idle,
        "events_correlated": result.events_correlated,
        "repeats": result.repeats,
        # Only the fresh ones: an incident the lookback re-assembled was
        # reported by an earlier cycle, and emitting it again every run would
        # make a log shipper duplicate every alert for the whole lookback.
        "incidents": [
            {
                "reference": reference(incident),
                "score": incident.score,
                "domains": sorted(incident.domains),
                "events": len(incident.event_ids),
                "entities": [entity.key for entity in incident.entities],
            }
            for incident in result.fresh
        ],
        "cursor_advanced": advanced,
        "resumed_from": None if result.started_from is None else result.started_from.event_id,
        "elapsed_seconds": round(elapsed, 3),
    }


def _print_text(result: CycleResult, *, elapsed: float, advanced: bool) -> None:
    """Human-readable summary, one line per new incident.

    Printed from the :class:`CycleResult` rather than from the JSON dictionary,
    so neither form is a reinterpretation of the other. Only *fresh* incidents
    are listed: the lookback re-assembles recent history every cycle by design,
    and printing those again each run would bury the new ones.
    """
    if result.idle:
        print("idle: no new events since the stored cursor.")
        return
    print(
        f"read {result.events_read} event(s), correlated {result.events_correlated} "
        f"in {elapsed:.3f}s; {len(result.fresh)} new incident(s)"
        + (f", {result.repeats} re-seen" if result.repeats else "")
        + f"; cursor {'advanced' if advanced else 'held'}."
    )
    for incident in result.fresh:
        print(
            f"  {reference(incident)}  score={incident.score:>3}  "
            f"events={len(incident.event_ids):>3}  "
            f"domains={','.join(sorted(incident.domains))}  "
            f"entities={','.join(entity.key for entity in incident.entities)}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # The one clock read in the whole pipeline. Used for the duration in the
    # report; the audit record keeps its own timestamp so the chain's notion of
    # time stays the chain's.
    started_at = time.monotonic()

    try:
        # The root must already exist. The pipeline creates its *subdirectories*
        # (``data/events``, ``data/pipeline``) but never the root itself, and the
        # difference is what makes a typo loud. A mistyped ``--root`` in a cron
        # line otherwise builds an entire shadow data tree, finds an empty store,
        # prints "idle: no new events" and exits 0 — forever. Every signal says
        # healthy while the SOC is blind, which is the same class of failure as a
        # cycle that correlates nothing: reproduced before this check existed.
        #
        # An operator deploys to a directory that exists, so a missing root is a
        # misconfiguration rather than a fresh install.
        if not args.root.is_dir():
            raise ValueError(
                f"--root {args.root} is not an existing directory; the pipeline creates "
                "data/ beneath the root but never the root itself, so this is a typo or "
                "an unmounted volume rather than a fresh deployment"
            )
        if args.lookback < 0:
            raise ValueError(f"lookback must be >= 0 seconds, got {args.lookback}")
        if args.batch < 1:
            # Validated here as well as in run_cycle: a scheduler misconfigured
            # with a batch of zero is a bad argument, not a failed cycle, and
            # should exit before the gate records an attempt.
            raise ValueError(f"batch must be >= 1, got {args.batch}")
        principal = Principal("pipeline", args.caller)
        thresholds = _thresholds(args)
        path = cursor_path(args.root)
        # The operator's reviewable policy document, not the in-code default:
        # a missing or malformed bundle stops the pipeline rather than falling
        # back to an implicit allow.
        engine = load_bundle(args.policy)
    except (
        PrincipalError,
        ThresholdError,
        CursorError,
        PolicyBundleError,
        ValueError,
        OSError,
    ) as exc:
        # OSError covers PermissionError from cursor_path's resolve() and from
        # the readlink in its containment check: an unreadable root is a bad
        # argument, not a failed cycle, and must not reach an unattended
        # operator as a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with _single_instance(path.parent) as acquired:
        if not acquired:
            print("skipped: another cycle holds the lock; this invocation did nothing.")
            return 0
        return _run(
            args,
            principal=principal,
            thresholds=thresholds,
            path=path,
            engine=engine,
            started_at=started_at,
        )


def _run(
    args: argparse.Namespace,
    *,
    principal: Principal,
    thresholds: Thresholds,
    path: Path,
    engine: PolicyEngine,
    started_at: float,
) -> int:
    """One cycle, under the lock. Split out so the lock's scope is unmissable."""
    try:
        audit = AuditLogger(path.parent / AUDIT_FILE, signing_key=signing_key_from_env())
    except (OSError, ValueError) as exc:
        print(f"error: audit log unusable, refusing to run: {exc}", file=sys.stderr)
        return 1

    try:
        enforce(
            action_class=ACTION_CLASS,
            name=ACTION_NAME,
            engine=engine,
            audit=audit,
            actor=principal,
        )
    except ToolBlockedError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 3
    except (AuditFieldError, OSError, ValueError) as exc:
        # enforce() writes the gate record itself, so an audit failure surfaces
        # from inside it. Caught because an unattended cycle must fail with an
        # exit code the scheduler can act on, not a traceback in cron mail.
        print(f"error: could not record the gate decision: {exc}", file=sys.stderr)
        return 1

    try:
        cursor = load_cursor(path)
        with EventStore.open(args.root) as store:
            result = run_cycle(
                store,
                cursor=cursor,
                thresholds=thresholds,
                batch=args.batch,
                lookback=args.lookback,
            )
    except (CursorError, StoreError, sqlite3.Error, ValueError, OSError) as exc:
        # sqlite3.Error is neither an OSError nor a StoreError, so a corrupt or
        # externally-locked database would otherwise escape as a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - started_at
    advancing = result.cursor is not None and not args.dry_run

    # Audit first, then advance — see the module docstring. The record states
    # what this cycle DECIDED, in the future tense where the outcome is not yet
    # known: writing "cursor advanced" before the save that decides it would put
    # a claim in a tamper-evident chain that a failed save then falsifies, and a
    # chain whose records can be false is not evidence.
    try:
        audit.record(
            actor=principal.render(),
            action=f"{ACTION_NAME}:{result.events_read}",
            action_class=ACTION_CLASS,
            decision="allow",
            reason=(
                f"read {result.events_read} event(s), correlated "
                f"{result.events_correlated}, assembled "
                f"{len(result.fresh)} new incident(s) "
                f"({result.repeats} re-seen), "
                + (
                    f"advancing cursor to {result.cursor.event_id[:16]}"
                    if advancing and result.cursor is not None
                    else "holding cursor"
                )
                + (" (dry run)" if args.dry_run else "")
            ),
        )
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: cycle ran but could not be recorded: {exc}", file=sys.stderr)
        return 1

    advanced = False
    if advancing and result.cursor is not None:
        try:
            save_cursor(path, result.cursor)
            advanced = True
        except (CursorError, OSError, ValueError) as exc:
            # The window will be re-read, which is what at-least-once promises.
            # Recorded as well as printed, so the chain does not end on a record
            # saying the cursor was advancing when it did not.
            print(f"error: cycle ran but the cursor was not advanced: {exc}", file=sys.stderr)
            with contextlib.suppress(AuditFieldError, OSError, ValueError):
                audit.record(
                    actor=principal.render(),
                    action=f"{ACTION_NAME}:cursor_not_advanced",
                    action_class=ACTION_CLASS,
                    decision="allow",
                    reason=(
                        "cursor save failed, window will be re-read: "
                        + escape_delimiter(str(exc)[:160])
                    ),
                )
            return 1

    if args.json:
        print(json.dumps(_report(result, elapsed=elapsed, advanced=advanced), sort_keys=True))
    else:
        _print_text(result, elapsed=elapsed, advanced=advanced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
