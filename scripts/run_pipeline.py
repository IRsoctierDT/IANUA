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

Exit codes: ``0`` cycle ran (including the idle case) · ``1`` the cycle or a
persisted cursor failed · ``2`` bad arguments · ``3`` blocked by policy.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.audit import AuditLogger, signing_key_from_env  # noqa: E402
from agents.policies.bundle import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle  # noqa: E402
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from correlation import ThresholdError, Thresholds  # noqa: E402
from pipeline import (  # noqa: E402
    DEFAULT_BATCH,
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


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Lab-data root holding data/events/ and data/pipeline/ (default: repo root).",
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=DEFAULT_BATCH,
        help=f"Events to read in this cycle (default: {DEFAULT_BATCH}).",
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
        "incidents": [
            {
                "reference": reference(incident),
                "score": incident.score,
                "domains": sorted(incident.domains),
                "events": len(incident.event_ids),
                "entities": [entity.key for entity in incident.entities],
            }
            for incident in result.incidents
        ],
        "cursor_advanced": advanced,
        "resumed_from": None if result.started_from is None else result.started_from.event_id,
        "elapsed_seconds": round(elapsed, 3),
    }


def _print_text(result: CycleResult, *, elapsed: float, advanced: bool) -> None:
    """Human-readable summary, one line per incident.

    Printed from the :class:`CycleResult` rather than from the JSON dictionary,
    so neither form is a reinterpretation of the other.
    """
    if result.idle:
        print("idle: no new events since the stored cursor.")
        return
    print(
        f"read {result.events_read} events in {elapsed:.3f}s; "
        f"{len(result.incidents)} incident(s); "
        f"cursor {'advanced' if advanced else 'held'}."
    )
    for incident in result.incidents:
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
    except (PrincipalError, ThresholdError, CursorError, PolicyBundleError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    audit = AuditLogger(
        path.parent / AUDIT_FILE,
        signing_key=signing_key_from_env(),
    )

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

    try:
        cursor = load_cursor(path)
        with EventStore.open(args.root) as store:
            result = run_cycle(store, cursor=cursor, thresholds=thresholds, batch=args.batch)
    except (CursorError, StoreError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - started_at
    advanced = result.cursor is not None and not args.dry_run

    # Audit first, then advance — see the module docstring. A dry run says so
    # in the record rather than looking like a cycle that consumed a window.
    try:
        audit.record(
            actor=principal.render(),
            action=f"{ACTION_NAME}:{result.events_read}",
            action_class=ACTION_CLASS,
            decision="allow",
            reason=(
                f"read {result.events_read} event(s), assembled "
                f"{len(result.incidents)} incident(s), cursor "
                f"{'advanced' if advanced else 'held'}"
                f"{' (dry run)' if args.dry_run else ''}"
            ),
        )
        if advanced and result.cursor is not None:
            save_cursor(path, result.cursor)
    except (CursorError, OSError, ValueError) as exc:
        print(f"error: cycle ran but was not committed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(_report(result, elapsed=elapsed, advanced=advanced), sort_keys=True))
    else:
        _print_text(result, elapsed=elapsed, advanced=advanced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
