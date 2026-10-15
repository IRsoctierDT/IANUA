# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the retention pass: report by default, delete only on a grant.

``EventStore.prune`` had no caller before this, so a retention *mechanism*
existed and a retention *policy* did not. These hold the two properties that
make the CLI safe to schedule: a dry run changes nothing, and an apply is
refused until an operator has granted that one action in a committed file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from pipeline import Cursor, cursor_path, save_cursor
from store import EventStore, Query

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-deploy" addr=203.0.113.9 res=failed'


def _cli_main() -> Any:
    """Import the CLI's entry point inside the test, as the sibling suites do."""
    from scripts.run_retention import main

    return main


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    return root


def _seed(root: Path, *, old: int, recent: int, processed: int | None = None) -> None:
    """Store ``old`` events well outside any sane window and ``recent`` inside it.

    Also writes a pipeline cursor, which is **not incidental**: retention now
    clamps its threshold to the cursor, and a root with no cursor prunes
    nothing at all — so a fixture without one measures the clamp rather than
    the window. ``processed=None`` means caught up (the cursor on the newest
    seeded event), which is the state these window tests are about. An integer
    puts it on the Nth-oldest instead, for the tests that are about a cycle
    being behind.
    """
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(old):
            store.append(
                normalize(_RECORD.replace("svc-deploy", f"old{index}")),
                ingested_at=store.next_stamp(now - 200 * 86_400 + index),
            )
        for index in range(recent):
            store.append(
                normalize(_RECORD.replace("svc-deploy", f"new{index}")),
                ingested_at=store.next_stamp(now - 3_600 + index),
            )
        held = store.count()
        if not held:
            return
        reached = store.query(
            Query(limit=held if processed is None else processed, newest_first=False)
        )[-1]
    save_cursor(
        cursor_path(root),
        Cursor(ingested_at=reached.ingested_at, event_id=reached.event_id),
    )


def _granted_bundle(tmp_path: Path, *labels: str) -> Path:
    """A policy bundle whose allow list carries exactly ``labels``.

    Built from the committed bundle so the test exercises the real default
    policy with one deliberate grant added — which is how an operator permits
    this action, and the only form of approval ``guarded.enforce`` can express.
    """
    repo_root = Path(__file__).resolve().parents[2]
    bundle = json.loads(
        (repo_root / "agents" / "policies" / "policy.json").read_text(encoding="utf-8")
    )
    bundle["allow"] = list(labels)
    path = tmp_path / f"granted-{'-'.join(labels) or 'none'}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _held(root: Path) -> int:
    with EventStore.open(root) as store:
        return store.count()


# --------------------------------------------------------------------------
# Reporting is the default
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_dry_run_reports_and_deletes_nothing(tmp_path: Path, capsys: Any) -> None:
    """The default must never remove anything, because removal is irreversible."""
    root = _root(tmp_path)
    _seed(root, old=5, recent=3)

    assert _cli_main()(["--root", str(root), "--caller", "test"]) == 0

    assert _held(root) == 8, "a dry run deleted events"
    out = capsys.readouterr().out
    assert "would remove 5 of 8" in out
    assert "nothing was deleted" in out


@pytest.mark.unit
def test_a_dry_run_says_so_when_nothing_is_old_enough(tmp_path: Path, capsys: Any) -> None:
    root = _root(tmp_path)
    _seed(root, old=0, recent=4)

    assert _cli_main()(["--root", str(root), "--caller", "test"]) == 0
    assert "nothing to remove" in capsys.readouterr().out
    assert _held(root) == 4


@pytest.mark.unit
def test_the_json_report_carries_the_counts_and_the_threshold(tmp_path: Path, capsys: Any) -> None:
    root = _root(tmp_path)
    _seed(root, old=2, recent=1)

    assert _cli_main()(["--root", str(root), "--caller", "test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events_total"] == 3
    assert payload["events_matching"] == 2
    assert payload["events_retained"] == 1
    assert payload["applied"] is False
    assert payload["events_removed"] is None
    assert payload["keep_days"] == 90


# --------------------------------------------------------------------------
# Deleting needs a grant
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_apply_is_refused_without_a_grant_and_deletes_nothing(tmp_path: Path, capsys: Any) -> None:
    """``destructive`` is ``require_approval`` in the shipped bundle.

    This is the control, not an obstacle: ``05_Governance_Rules.md`` puts
    "Deleting data" under "Human Approval Required Before", and
    ``guarded.enforce`` cannot express a per-invocation prompt — so the
    available form of approval is a standing grant for one named label in a
    reviewable file, and without it the pass must refuse.
    """
    root = _root(tmp_path)
    _seed(root, old=5, recent=3)

    assert _cli_main()(["--root", str(root), "--caller", "test", "--apply"]) == 3
    assert _held(root) == 8, "a blocked apply deleted events anyway"
    err = capsys.readouterr().err
    assert "blocked" in err
    assert "retain_events:apply" in err, "the refusal does not say what to grant"


@pytest.mark.unit
def test_apply_removes_the_matching_events_once_granted(tmp_path: Path, capsys: Any) -> None:
    root = _root(tmp_path)
    _seed(root, old=5, recent=3)
    bundle = _granted_bundle(tmp_path, "retain_events:apply")

    code = _cli_main()(
        ["--root", str(root), "--caller", "test", "--apply", "--policy", str(bundle)]
    )
    assert code == 0
    assert "removed 5 of 8" in capsys.readouterr().out
    assert _held(root) == 3


@pytest.mark.unit
@pytest.mark.parametrize("granted", ["retain_events", "retain", "retain_events:", "apply"])
def test_a_partial_grant_does_not_permit_applying(tmp_path: Path, granted: str) -> None:
    """The allow list is exact-match, and a partial grant must not widen into it.

    ``retain_events`` is the grant an operator would plausibly write, thinking
    it permits "retention" — and under a prefix or substring match it would
    permit the destructive half too. Found by planting a prefix match, which
    the dry-run-label test below could not catch because neither of those two
    labels is a prefix of the other.
    """
    root = _root(tmp_path)
    _seed(root, old=2, recent=1)
    bundle = _granted_bundle(tmp_path, granted)

    code = _cli_main()(
        ["--root", str(root), "--caller", "test", "--apply", "--policy", str(bundle)]
    )
    assert code == 3, f"a grant of {granted!r} permitted the destructive action"
    assert _held(root) == 3


@pytest.mark.unit
def test_a_grant_for_the_dry_run_label_does_not_permit_applying(tmp_path: Path) -> None:
    """The allow list is exact-match, so the two labels are not interchangeable.

    Worth pinning: granting the harmless label must not widen into the
    destructive one, which a prefix or substring match would do.
    """
    root = _root(tmp_path)
    _seed(root, old=2, recent=1)
    bundle = _granted_bundle(tmp_path, "retain_events:dry-run")

    code = _cli_main()(
        ["--root", str(root), "--caller", "test", "--apply", "--policy", str(bundle)]
    )
    assert code == 3
    assert _held(root) == 3


# --------------------------------------------------------------------------
# The audit chain records both the refusal and the deletion
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_the_chain_records_the_refused_attempt_and_stays_verifiable(tmp_path: Path) -> None:
    """A blocked attempt is the thing an auditor most needs to find."""
    from agents.policies.audit import AuditLogger

    root = _root(tmp_path)
    _seed(root, old=2, recent=1)
    main = _cli_main()
    main(["--root", str(root), "--caller", "test"])
    main(["--root", str(root), "--caller", "test", "--apply"])

    log = root / "data" / "events" / "audit.log"
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert AuditLogger(log).verify() is True, "the retention pass forked the audit chain"

    blocked = [r for r in records if r["decision"] == "require_approval"]
    assert len(blocked) == 1
    assert blocked[0]["action_class"] == "destructive"
    assert "retain_events:apply" in blocked[0]["action"]

    # The dry run is recorded as read_only, because it is.
    assert any(r["action_class"] == "read_only" for r in records)


# --------------------------------------------------------------------------
# Arguments and the lock
# --------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("value", ["-1", "nan", "inf"])
def test_a_bad_window_is_a_bad_argument(tmp_path: Path, value: str) -> None:
    """Exit 2 before the gate records an attempt — a misconfigured scheduler.

    ``nan`` deserves its own case: it compares false against every bound, so a
    threshold derived from it would silently match nothing while looking like a
    successful pass.
    """
    root = _root(tmp_path)
    _seed(root, old=1, recent=1)
    assert _cli_main()(["--root", str(root), "--caller", "test", "--keep-days", value]) == 2
    assert _held(root) == 2


@pytest.mark.unit
def test_a_declined_lock_exits_zero_and_changes_nothing(tmp_path: Path, capsys: Any) -> None:
    """Overlap is expected on a schedule; failing would train the operator to ignore it."""
    from scripts.run_retention import LOCK_FILE, LOCK_SUBDIR, _prepare_lock, _single_instance

    root = _root(tmp_path)
    _seed(root, old=3, recent=1)
    lock = _prepare_lock(root / LOCK_SUBDIR)
    # ``_prepare_lock`` returns the open handle now, not the path, so the
    # ``open`` sits inside the caller's startup ``try`` with the rest of it.
    # The file it holds is still the declared lock.
    assert Path(lock.name).name == LOCK_FILE

    with _single_instance(lock) as held:
        assert held is True
        assert _cli_main()(["--root", str(root), "--caller", "test"]) == 0
    assert "skipped" in capsys.readouterr().out
    assert _held(root) == 4


# --------------------------------------------------------------------------
# The interactions the survey found
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_pruning_everything_leaves_the_high_water_mark_intact(tmp_path: Path) -> None:
    """Which is why the mark is stored rather than derived from MAX(ingested_at).

    If retention reset the mark, the next collector pass could stamp an event
    behind a cursor that had already passed it — the loss the mark exists to
    refuse.
    """
    root = _root(tmp_path)
    _seed(root, old=4, recent=0)
    with EventStore.open(root) as store:
        before = store.high_water_mark()
    # `--include-unprocessed` because "everything" means everything: the clamp
    # holds the commit the cursor sits in — `prune` is `ingested_at < ?` with no
    # `event_id` tie-break — so a caught-up node always retains that one group.
    # The flag lifts the clamp; it is not the default path and the tests below
    # assert what the default does.
    bundle = _granted_bundle(tmp_path, "retain_events:apply", "retain_events:apply-unprocessed")

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--caller",
                "test",
                "--apply",
                "--include-unprocessed",
                "--policy",
                str(bundle),
            ]
        )
        == 0
    )
    with EventStore.open(root) as store:
        assert store.count() == 0
        assert store.high_water_mark() == before, "retention reset the high-water mark"


@pytest.mark.unit
def test_retention_does_not_rewind_the_collectors_offsets(tmp_path: Path) -> None:
    """Pinned as a *property*, because it is the one an operator will be surprised by.

    Offsets live in their own file and nothing rewinds them, so content pruned
    from the store cannot be recovered by re-collecting a source that still
    holds every line. Measured before this CLI existed: purge the store, re-run
    the same collector invocation, and it reports "nothing new" and stores
    zero. The CLI's own output says so; this makes sure the claim stays true.
    """
    from collect import load_offsets, offsets_path

    root = _root(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    source = logs / "auth.log"
    source.write_text(f"{_RECORD}\n", encoding="utf-8")

    from scripts.run_collector import main as collect_main

    assert collect_main(["--root", str(root), "--source", str(source), "--caller", "t"]) == 0
    saved = load_offsets(offsets_path(root))
    advanced = saved[str(source.resolve())].offset
    assert advanced > 0

    # `--include-unprocessed` for the same reason as the high-water test, and
    # here it is unavoidable: this root has one event and no cycle has run, so
    # nothing is known to be processed and the default clamp prunes nothing.
    # The subject of this test is the collector's offsets, not the clamp.
    bundle = _granted_bundle(tmp_path, "retain_events:apply", "retain_events:apply-unprocessed")
    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--caller",
                "test",
                "--keep-days",
                "0",
                "--apply",
                "--include-unprocessed",
                "--policy",
                str(bundle),
            ]
        )
        == 0
    )
    assert _held(root) == 0, "the window of 0 days should have removed everything"

    # The offset is untouched, so the source cannot be re-collected.
    assert load_offsets(offsets_path(root))[str(source.resolve())].offset == advanced
    assert collect_main(["--root", str(root), "--source", str(source), "--caller", "t"]) == 0
    assert _held(root) == 0, (
        "re-collection recovered pruned content; if that is now possible the CLI's "
        "irreversibility warning is wrong and must be corrected"
    )
