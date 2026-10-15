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
from store import EventStore, StoreError  # noqa: E402
from store.paths import confine, validated_root  # noqa: E402

#: Default window, in days. A number had to be chosen; this one is the value
#: ``store/README.md`` already used in its illustrative snippet, so the
#: documentation and the default agree rather than offering two numbers.
#: It is not a recommendation — see the runbook, which states the storage cost
#: per day so an operator can pick their own.
DEFAULT_KEEP_DAYS = 90

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
            "Lab-data root holding data/events/ (default: repo root). Must already "
            "exist: a typo must not build a shadow tree and report success."
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
) -> dict[str, object]:
    """The pass's outcome, as data."""
    return {
        "events_total": total,
        "events_matching": matching,
        "events_retained": total - matching,
        "threshold_ingested_before": threshold,
        "keep_days": keep_days,
        "applied": applied,
        "events_removed": removed,
    }


def _print_text(payload: dict[str, object]) -> None:
    matching = int(payload["events_matching"])  # type: ignore[call-overload]
    total = int(payload["events_total"])  # type: ignore[call-overload]
    if payload["applied"]:
        print(f"removed {payload['events_removed']} of {total} event(s)")
        return
    if matching == 0:
        print(
            f"nothing to remove: no event was ingested more than "
            f"{payload['keep_days']} day(s) ago ({total} held)."
        )
        return
    print(
        f"would remove {matching} of {total} event(s) ingested before "
        f"{payload['threshold_ingested_before']} "
        f"({payload['keep_days']} day(s) ago); {payload['events_retained']} retained."
    )
    print(
        f"  nothing was deleted. Re-run with --apply, which requires "
        f"'{ACTION_NAME}:apply' on the policy bundle's allow list. Deletion is "
        "final: the collector's offsets are not rewound, so pruned content "
        "cannot be re-collected."
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    started_at = time.monotonic()

    try:
        if not math.isfinite(args.keep_days) or args.keep_days < 0:
            raise ValueError(f"--keep-days must be finite and >= 0, got {args.keep_days!r}")
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
            total = store.count()
            matching = store.count_before(before=threshold)
            removed = store.prune(before=threshold) if args.apply else None
    except (StoreError, sqlite3.Error, ValueError, OSError) as exc:
        # sqlite3.Error is neither OSError nor StoreError, so a corrupt or
        # locked database would otherwise escape as a traceback in cron mail.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = _report(
        total=total,
        matching=matching,
        threshold=threshold,
        keep_days=args.keep_days,
        applied=bool(args.apply),
        removed=removed,
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
                f"before {threshold} ({args.keep_days} day(s)); "
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
