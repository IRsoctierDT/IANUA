#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Collect this node's own logs into the event store — one pass per invocation.

The process a scheduler invokes. It is the only place in collection that reads
a clock, takes a path from an operator, or decides that collecting is
permitted; everything below it is a pure function of its inputs.

**Gated as ``collection``, which is its own policy class.** Not ``read_only``:
this is the one action in the platform that reaches outside the project's
filesystem, and an operator must be able to stop collection without stopping
detection. ``allow`` by default, so the gate is a kill switch rather than a
restriction — said plainly because the alternative would be to imply a
protection that is not there. What constrains *what* gets read is
``collect.sources``, which refuses a relative path, a symlinked log, a
non-regular file, and anything matching the credential deny-list.

**One pass at a time.** An exclusive lock is held for the whole run, for the
same reason ``run_pipeline.py`` holds one: two processes appending to the
hash-chained audit log at once fork the chain and break ``verify()``
permanently, which would put a false positive into a tamper detector. A
declined lock exits ``0`` — the timer outrunning the run is expected on a tight
schedule, not a failure — and says so.

**Offsets advance only after the events are stored**, and the report is written
before the offsets move. Both orderings are deliberate and both were learned
the hard way in stage 4: a position saved before the events are durable skips a
region nothing will ever re-read, and a report written after the position moves
can be lost while the region stays consumed. At-least-once costs a duplicate
read, which the content-addressed store turns into a no-op.

**Ingestion order is kept monotone, per commit.** Each source's batch is
stamped by ``EventStore.next_stamp(time.time())`` immediately before *its own*
``append_many``, which is one transaction. The store refuses a write behind its
high-water mark, and ``next_stamp`` returns a value strictly after that mark, so
no two commits can share an ``ingested_at``.

That "per commit" is load-bearing and was learned the hard way. The pipeline
pages by a ``(ingested_at, event_id)`` keyset that is *strictly* after the
cursor, and it holds a different lock from this CLI — so a cycle can fire
between two of this pass's commits. With one stamp hoisted across the whole
pass, that cycle saved a cursor *inside* a tie group, and every later-source
event whose content hash sorted below the cursor's id was behind a cursor that
had already passed it: never read, by any cycle. Reproduced at 30 of 60 events
lost with the pipeline reporting ``events_read: 0``. Stamping per commit means a
cursor can only ever land between tie groups, never inside one.

Clamping rather than failing on a backwards clock is the right trade:
``occurred_at`` still carries the source's own time, and ``ingested_at`` is only
ever used for ordering and retention. The cost is stated in
``docs/PRODUCTION_SOC_PLAN.md``: a clock that jumps *forward* raises the mark
permanently, which delays retention for everything after it.

**No ambient identity.** ``--caller`` is optional and must be passed
explicitly. This program does not read ``$USER`` or any other environment
variable to decide who is asking, for the same reason
``agents/policies/principal.py`` does not: an audit record naming whoever
happened to own the cron job is an unauthenticated claim.

Usage::

    python scripts/run_collector.py --source /var/log/auth.log
    python scripts/run_collector.py --source /var/log/auth.log \\
        --source /var/log/syslog --caller soc-timer --json
    python scripts/run_collector.py --source /var/log/auth.log --dry-run

Schedule examples::

    # crontab: every minute, because the tail of a file rotated BETWEEN runs
    # is unreachable by name — running often is what bounds that gap.
    * * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python \\
        scripts/run_collector.py --root /srv/ianua --caller soc-collector \\
        --source /var/log/auth.log >> /srv/ianua/data/collect/run.log 2>&1

    # systemd: a oneshot unit plus OnCalendar=minutely. Prefer it — the unit is
    # where least privilege is actually expressed, since nothing in the Python
    # can stop itself from being run as root. See the plan for a full unit.

Exit codes:

* ``0`` — a pass ran (including the common nothing-new case), or was skipped
  because another pass held the lock. The output distinguishes them.
* ``1`` — a source could not be read, the store refused the write, the audit
  write failed, or offsets could not be persisted. Nothing was consumed; the
  next invocation re-reads.
* ``2`` — bad arguments: an undeclarable source, an unusable ``--root``, or a
  malformed policy bundle. Nothing ran and nothing was recorded.
* ``3`` — blocked by policy. The gate decision *is* recorded.
* ``4`` — retryable contention: every failure in the pass was another writer
  holding the store's write lock. Sources that succeeded kept their events and
  their advanced offsets, so a retry re-reads only what was busy. One damaged
  source alongside a busy one reports ``1``, not this — damage wins. See
  ``scripts/_exit_codes.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sqlite3
import sys
import time
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
from agents.policies.bundle import (  # noqa: E402
    DEFAULT_BUNDLE_PATH,
    PolicyBundleError,
    load_bundle,
)
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from collect import (  # noqa: E402
    MAX_BYTES_PER_RUN,
    CollectError,
    Position,
    Source,
    TailResult,
    declare_all,
    load_offsets,
    offsets_path,
    read_new,
    save_offsets,
)
from ingest import normalize_many  # noqa: E402
from scripts._exit_codes import EXIT_RETRYABLE, is_retryable_contention  # noqa: E402
from scripts._locking import prepare_lock, single_instance  # noqa: E402
from store import EventStore, StoreError  # noqa: E402
from store.paths import validated_root  # noqa: E402

#: The collector's own audit log, beside its offsets. Mirrors the pipeline and
#: the compliance evidence engine: a per-subsystem chain means a corrupted
#: collector log cannot invalidate either of the others.
AUDIT_FILE = "audit.log"

#: Single-instance lock. A correctness control — see :func:`_single_instance`.
LOCK_FILE = "collect.lock"

#: Owner-only, matching the offsets, the cursor and the audit log.

#: Its own class, not ``read_only``. See the module docstring.
ACTION_CLASS: ActionClass = "collection"
ACTION_NAME = "collect_logs"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help=(
            "Lab-data root holding data/events/ and data/collect/ (default: repo "
            "root). Must be an absolute path that already exists: the collector "
            "creates data/ beneath the root but never the root itself, and a "
            "relative root is whatever the scheduler's working directory happens "
            "to be — so a typo or an unset variable fails loudly instead of "
            "building a shadow tree and reporting success forever."
        ),
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Absolute path of a log file to collect. Repeatable. Declared, never "
            "discovered: there is no glob and no directory walk, because a "
            "collector that searches for sources eventually finds one nobody "
            "meant it to read."
        ),
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_BYTES_PER_RUN,
        help=(
            f"Cap on bytes read per source per pass (default: {MAX_BYTES_PER_RUN}). "
            "A backlog is worked through over several passes rather than in one "
            "unbounded read."
        ),
    )
    parser.add_argument(
        "--caller",
        default=None,
        help="Who this pass is for, recorded in the audit chain. Never inferred.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Read and report, but store no events and leave the offsets "
            "untouched. Safe way to see what a source would yield."
        ),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Declarative policy bundle to gate this pass against (fail-closed).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    return parser.parse_args(argv)


def _report(
    results: dict[str, TailResult], *, stored: int, elapsed: float, advancing: bool
) -> dict[str, object]:
    """The pass's outcome as JSON-serializable data, for a machine reader."""
    return {
        "sources": [
            {
                "source": key,
                "lines": result.count,
                "reset": result.reset,
                "truncated": result.truncated,
                "capped": result.capped,
                "offset": None if result.position is None else result.position.offset,
            }
            for key, result in sorted(results.items())
        ],
        "lines_read": sum(result.count for result in results.values()),
        "events_stored": stored,
        "offsets_advancing": advancing,
        "elapsed_seconds": round(elapsed, 3),
    }


def _print_text(
    results: dict[str, TailResult], *, stored: int, elapsed: float, advancing: bool
) -> None:
    """Human-readable summary, one line per source.

    Printed from the results rather than from the JSON dictionary, so neither
    form is a reinterpretation of the other.
    """
    total = sum(result.count for result in results.values())
    if total == 0:
        print("nothing new: no complete lines appended to any source.")
        return
    print(
        f"read {total} line(s) from {len(results)} source(s) in {elapsed:.3f}s; "
        f"{stored} event(s) stored; "
        f"offsets {'advancing' if advancing else 'held'}."
    )
    for key, result in sorted(results.items()):
        notes = []
        if result.reset:
            notes.append(result.reset)
        if result.truncated:
            notes.append(f"{result.truncated} line(s) truncated")
        if result.capped:
            notes.append("more waiting (capped)")
        suffix = f"  [{', '.join(notes)}]" if notes else ""
        print(f"  {result.count:>6} lines  {key}{suffix}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # The report's duration. The ingestion stamps are read separately, one per
    # source immediately before its commit (see the loop in `_run`); the audit
    # record keeps its own timestamp so the chain's notion of time stays the
    # chain's.
    started_at = time.monotonic()

    try:
        if not args.source:
            raise ValueError(
                "no --source given; this collector reads only what an operator "
                "declares, so with nothing declared there is nothing to do"
            )
        if args.max_bytes < 1:
            raise ValueError(f"--max-bytes must be >= 1, got {args.max_bytes}")
        # Shared with every other entry point, because this check had four
        # copies and one hole: `Path("") == Path(".")`, so `--root "$UNSET"`
        # passed `is_dir()` and built a shadow data tree in the cwd.
        args.root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("collector", args.caller)
        sources = declare_all(tuple(args.source))
        path = offsets_path(args.root)
        engine = load_bundle(args.policy)
        # Last in the startup try, deliberately: the only statement here that
        # opens a descriptor, so nothing can fail after it and abandon the handle.
        lock = prepare_lock(path.parent, LOCK_FILE)
    except (PrincipalError, CollectError, PolicyBundleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with single_instance(lock) as acquired:
        if not acquired:
            print("skipped: another pass holds the lock; this invocation did nothing.")
            return 0
        return _run(
            args,
            principal=principal,
            sources=sources,
            path=path,
            engine=engine,
            started_at=started_at,
        )


def _run(
    args: argparse.Namespace,
    *,
    principal: Principal,
    sources: tuple[Source, ...],
    path: Path,
    engine: PolicyEngine,
    started_at: float,
) -> int:
    """One pass, under the lock. Split out so the lock's scope is unmissable."""
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
        # from inside it. Caught because an unattended pass must fail with an
        # exit code the scheduler can act on, not a traceback in cron mail.
        print(f"error: could not record the gate decision: {exc}", file=sys.stderr)
        return 1

    results: dict[str, TailResult] = {}
    advanced: dict[str, Position] = {}
    stored = 0
    failure: str | None = None
    #: ``True`` only while *every* per-source failure so far has been retryable
    #: contention. It starts ``True`` and can only be cleared, so one damaged
    #: source cannot be reported as "retry" because a later source was merely
    #: busy — damage wins, which is the fail-closed direction. ``failure``
    #: itself keeps only the last message, which this does not change.
    only_contention = True
    try:
        positions = load_offsets(path)
    except (CollectError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        with EventStore.open(args.root) as store:
            for source in sources:
                # Per-source, so one unreadable file does not starve the rest.
                # Before this, a single permission error returned 1 before any
                # offset was saved, so every *healthy* source re-read its whole
                # window every run and never advanced — one broken source took
                # the others down with it, silently and forever.
                try:
                    result = read_new(source, positions.get(source.key), max_bytes=args.max_bytes)
                    results[source.key] = result
                    if result.lines and not args.dry_run:
                        # Stamped per source, immediately before its own commit.
                        # ``append_many`` is one transaction per call, so a stamp
                        # hoisted out of this loop gave every source's *separate*
                        # commit the same ``ingested_at`` — and the pipeline holds
                        # a different lock, so a cycle landing between two commits
                        # saves a cursor inside that tie group. The keyset is
                        # strictly after ``(ingested_at, event_id)``, so every
                        # later-source event whose content hash sorts below that
                        # id is behind a cursor that has already passed it and is
                        # never read by any cycle. Reproduced: 30 of 60 collected
                        # events permanently invisible, the pipeline reporting
                        # ``events_read: 0`` while the store held all 60.
                        #
                        # This is exactly the loss ``next_stamp`` exists to
                        # prevent, reintroduced one layer up by hoisting the call.
                        # Per commit, each stamp is strictly after the mark the
                        # previous commit set, so no two commits share a stamp and
                        # a cursor can only ever land *between* tie groups.
                        stored += store.append_many(
                            tuple(normalize_many(result.lines)),
                            ingested_at=store.next_stamp(time.time()),
                        )
                    # Recorded only once this source's events are durable.
                    if result.position is not None:
                        advanced[source.key] = result.position
                except (CollectError, StoreError, sqlite3.Error, ValueError, OSError) as exc:
                    # sqlite3.Error is neither OSError nor StoreError, so a
                    # corrupt or locked database would otherwise escape as a
                    # traceback in cron mail.
                    print(f"error: {source.key}: {exc}", file=sys.stderr)
                    failure = f"{source.name}: {exc}"
                    only_contention = only_contention and is_retryable_contention(exc)
    except (StoreError, sqlite3.Error, ValueError, OSError) as exc:
        # Contention first: it is also a `sqlite3.Error`, so the order is what
        # keeps "another writer holds the store" from reading as damage.
        if is_retryable_contention(exc):
            print(f"error: the store is busy, nothing was collected: {exc}", file=sys.stderr)
            return EXIT_RETRYABLE
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - started_at
    advancing = bool(advanced) and not args.dry_run
    total = sum(result.count for result in results.values())

    # Audit, then report, then advance — the ordering learned in stage 4. The
    # record states what this pass DECIDED, in the future tense where the
    # outcome is not yet known: claiming the offsets moved before the save that
    # decides it would put a falsifiable claim in a tamper-evident chain.
    try:
        audit.record(
            actor=principal.render(),
            action=f"{ACTION_NAME}:{len(sources)}",
            action_class=ACTION_CLASS,
            decision="allow",
            reason=escape_delimiter(
                f"read {total} line(s) from {len(results)} of {len(sources)} "
                f"source(s), stored {stored} event(s), offsets "
                + ("advancing" if advancing else "held")
                + (" (dry run)" if args.dry_run else "")
                + (f"; FAILED {failure[:120]}" if failure else "")
            ),
        )
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: pass ran but could not be recorded: {exc}", file=sys.stderr)
        return 1

    # Report before advancing: the lines are consumed once the offsets move, so
    # a failed write here must leave them where they were.
    try:
        if args.json:
            print(
                json.dumps(
                    _report(results, stored=stored, elapsed=elapsed, advancing=advancing),
                    sort_keys=True,
                )
            )
        else:
            _print_text(results, stored=stored, elapsed=elapsed, advancing=advancing)
    except OSError as exc:
        print(f"error: pass ran but its report could not be written: {exc}", file=sys.stderr)
        return 1

    if advancing:
        try:
            positions.update(advanced)
            save_offsets(path, positions)
        except (CollectError, OSError, ValueError) as exc:
            print(f"error: pass ran but offsets were not advanced: {exc}", file=sys.stderr)
            with contextlib.suppress(AuditFieldError, OSError, ValueError):
                audit.record(
                    actor=principal.render(),
                    action=f"{ACTION_NAME}:offsets_not_advanced",
                    action_class=ACTION_CLASS,
                    decision="allow",
                    reason=(
                        "offset save failed, lines will be re-read: "
                        + escape_delimiter(str(exc)[:160])
                    ),
                )
            return 1
    # A source failed, but every source that succeeded has had its events
    # stored and its offset saved above. Reporting non-zero tells the scheduler
    # something needs attention without discarding the progress that was made.
    #
    # Which non-zero matters here more than at the outer handlers, because this
    # is the partial-progress path: when the only thing that went wrong was
    # contention, the successful sources have already advanced their offsets,
    # so a retry re-reads just the busy one — and collection is idempotent by
    # content hash besides. `EXIT_RETRYABLE` therefore says "retry" about a
    # pass that genuinely did most of its work.
    if failure:
        return EXIT_RETRYABLE if only_contention else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
