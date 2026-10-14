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

**Ingestion order is kept monotone.** ``ingested_at`` is stamped at
``max(now, store.high_water_mark())``. The store now *refuses* a write behind
its high-water mark, because the pipeline pages by a ``(ingested_at,
event_id)`` keyset and an event stamped earlier would sit behind a cursor that
has already passed it — never read, by any cycle. Clamping rather than failing
on a backwards clock is the right trade: ``occurred_at`` still carries the
source's own time, and ``ingested_at`` is only ever used for ordering and
retention. The cost is stated in ``docs/PRODUCTION_SOC_PLAN.md``: a clock that
jumps *forward* raises the mark permanently, which delays retention for
everything after it.

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
from store import EventStore, StoreError  # noqa: E402

from ingest import normalize_many  # noqa: E402

#: The collector's own audit log, beside its offsets. Mirrors the pipeline and
#: the compliance evidence engine: a per-subsystem chain means a corrupted
#: collector log cannot invalidate either of the others.
AUDIT_FILE = "audit.log"

#: Single-instance lock. A correctness control — see :func:`_single_instance`.
LOCK_FILE = "collect.lock"

#: Owner-only, matching the offsets, the cursor and the audit log.
_FILE_MODE = 0o600

#: Its own class, not ``read_only``. See the module docstring.
ACTION_CLASS: ActionClass = "collection"
ACTION_NAME = "collect_logs"


def _prepare_lock(directory: Path) -> Path:
    """Create the lock file and return it, before any lock is attempted.

    Separated from :func:`_single_instance` so that its ``mkdir``, ``touch``
    and ``chmod`` run inside the caller's startup ``try`` and an unwritable
    ``data/collect`` becomes a message and exit 2 like every other startup
    failure in this CLI. Inside the context manager they ran at ``__enter__``,
    outside every ``try``, and reached the terminal as a traceback — and the
    first operator to hit it is the one following the runbook, who runs the
    documented manual pass as themselves after the documented root cron entry
    has already created the directory as root. Found by review.
    """
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / LOCK_FILE
    path.touch(mode=_FILE_MODE, exist_ok=True)
    path.chmod(_FILE_MODE)
    return path


@contextlib.contextmanager
def _single_instance(path: Path) -> Iterator[bool]:
    """Hold an exclusive lock for the duration of one pass.

    A correctness control, not an optimization. :class:`AuditLogger` derives
    each record's ``seq`` and ``prev_hash`` by reading the last line and
    appending — a read-modify-write with no locking — so two concurrent
    appenders fork the chain and ``verify()`` returns ``False`` for every
    future reader. That is worse than losing records: it puts a false positive
    into a tamper detector. Demonstrated against the pipeline's identical
    shape before its lock existed: six concurrent invocations, a duplicate
    ``seq``, and every process exiting ``0``.

    It also serializes offset writes, so two passes cannot each read the same
    region and race to persist different positions.

    Takes a path already created by :func:`_prepare_lock`, so nothing here
    can fail for a reason the caller would have to translate into an exit code.

    Yields ``True`` when the lock was taken, ``False`` when another pass holds
    it. A declined lock is not an error, and must not exit non-zero: a
    minutely schedule is *expected* to overlap occasionally, and failing would
    mail the operator every minute until they learned to ignore it.
    """
    with path.open("a", encoding="utf-8") as handle:
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
            "Lab-data root holding data/events/ and data/collect/ (default: repo "
            "root). Must already exist: the collector creates data/ beneath it but "
            "never the root itself, so a typo fails loudly instead of building a "
            "shadow tree and reporting success forever."
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

    # The one clock read in collection. Used for the duration in the report and
    # for the ingestion stamp; the audit record keeps its own timestamp so the
    # chain's notion of time stays the chain's.
    started_at = time.monotonic()

    try:
        if not args.source:
            raise ValueError(
                "no --source given; this collector reads only what an operator "
                "declares, so with nothing declared there is nothing to do"
            )
        if args.max_bytes < 1:
            raise ValueError(f"--max-bytes must be >= 1, got {args.max_bytes}")
        if not args.root.is_dir():
            raise ValueError(
                f"--root {args.root} is not an existing directory; the collector "
                "creates data/ beneath the root but never the root itself, so this "
                "is a typo or an unmounted volume rather than a fresh deployment"
            )
        principal = Principal("collector", args.caller)
        sources = declare_all(tuple(args.source))
        path = offsets_path(args.root)
        lock = _prepare_lock(path.parent)
        engine = load_bundle(args.policy)
    except (PrincipalError, CollectError, PolicyBundleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    with _single_instance(lock) as acquired:
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
    try:
        positions = load_offsets(path)
    except (CollectError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        with EventStore.open(args.root) as store:
            stamp = store.next_stamp(time.time())
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
                        stored += store.append_many(
                            tuple(normalize_many(result.lines)), ingested_at=stamp
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
    except (StoreError, sqlite3.Error, ValueError, OSError) as exc:
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
    # stored and its offset saved above. Reporting 1 tells the scheduler
    # something needs attention without discarding the progress that was made.
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
