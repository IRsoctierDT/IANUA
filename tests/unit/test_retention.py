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
import os
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
def test_a_window_that_overflows_seconds_is_refused_before_the_gate(
    tmp_path: Path, capsys: Any
) -> None:
    """``1e305`` is finite; ``1e305 * 86_400`` is not, and the threshold was ``-inf``.

    Measured on the code this pins: ``count_before`` refused the bound — at exit
    **1**, "damage, page someone", with the gate decision already in the audit
    chain. A bad argument is exit 2 and records nothing; the audit log must not
    exist afterwards because nothing in a refused startup creates it.
    """
    root = _root(tmp_path)
    _seed(root, old=1, recent=1)
    assert _cli_main()(["--root", str(root), "--caller", "test", "--keep-days", "1e305"]) == 2
    assert "too large" in capsys.readouterr().err
    assert not (root / "data" / "events" / "audit.log").exists(), "the gate recorded an attempt"
    assert _held(root) == 2


@pytest.mark.unit
def test_a_declined_lock_exits_zero_and_changes_nothing(tmp_path: Path, capsys: Any) -> None:
    """Overlap is expected on a schedule; failing would train the operator to ignore it."""
    from scripts._locking import prepare_lock, single_instance
    from scripts.run_retention import LOCK_FILE, LOCK_SUBDIR

    root = _root(tmp_path)
    _seed(root, old=3, recent=1)
    lock = prepare_lock(root / LOCK_SUBDIR, LOCK_FILE)
    # ``prepare_lock`` returns the open handle now, not the path, so the
    # ``open`` sits inside the caller's startup ``try`` with the rest of it.
    # The file it holds is still the declared lock — asserted by INODE rather
    # than by name, which is both necessary and better. Necessary because the
    # handle no longer knows its path: ``os.fdopen`` yields a wrapper whose
    # ``.name`` is the integer descriptor, so ``Path(lock.name)`` raises
    # ``TypeError`` (measured, and it is the one test the #58 fix broke).
    # Better because the inode is the property that fix is *about* — the type
    # is checked on the descriptor precisely so that the thing inspected and
    # the thing locked cannot be two different files, and comparing names
    # could not tell the difference.
    assert os.fstat(lock.fileno()).st_ino == (root / LOCK_SUBDIR / LOCK_FILE).stat().st_ino

    with single_instance(lock) as held:
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
    # Two deliberate flags, each for a different guard, and this test is where
    # the difference shows.
    #
    # `--include-unprocessed` because "everything" means everything: the clamp
    # holds the commit the cursor sits in — `prune` is `ingested_at < ?` with no
    # `event_id` tie-break — so a caught-up node always retains that one group.
    #
    # `--keep-days 0` because this fixture seeds only 200-day-old events, which
    # is the shape of a node whose collection has been dead for longer than the
    # window — and a pass whose window reaches past *every* event in the store
    # now refuses, the other cause of that state being a forward clock step that
    # would silently destroy the whole evidence base. `--keep-days 0` is the
    # documented way to say "retain nothing", and is the exemption.
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


# --------------------------------------------------------------------------
# The correlation margin: the cursor clamp and the cycle's lookback aimed at
# the same rows
# --------------------------------------------------------------------------
#
# The clamp bounds a pass to *processed* events. The detection cycle's lookback
# exists to re-read *processed* events as correlation context. Those are the
# same rows, which was measured rather than argued: a story straddling the
# 90-day boundary, under every shipped default and with no concurrency
# anywhere, was reported by the cycle at score 52 over three domains before the
# documented retention pass and at score 30 over two after it. One event
# deleted, and what an analyst sees is still an incident — just a smaller,
# quieter, wrong one.


def _tight(root: Path, *, count: int, spacing: float = 1.0) -> float:
    """Seed ``count`` events ending just before now, and a caught-up cursor.

    Returns the cursor's ``ingested_at``. Spacing is seconds, so the whole run
    sits well inside the default 900s margin — which is the regime these tests
    are about and the one ``_seed`` deliberately does not produce.
    """
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(count):
            store.append(
                normalize(_RECORD.replace("svc-deploy", f"tight{index}")),
                ingested_at=store.next_stamp(now - (count - index) * spacing),
            )
        newest = store.query(Query(limit=store.count(), newest_first=False))[-1]
    save_cursor(cursor_path(root), Cursor(ingested_at=newest.ingested_at, event_id=newest.event_id))
    return newest.ingested_at


@pytest.mark.unit
def test_the_default_margin_leaves_the_correlation_window_intact(tmp_path: Path) -> None:
    """``--keep-days 0`` on a caught-up node must still spare the lookback.

    Nothing about these events is unprocessed — the cursor is on the newest of
    them. Before the margin they were all deletable, which is precisely the
    hazard: the cycle re-reads this window on its next firing.
    """
    root = _root(tmp_path)
    _tight(root, count=10)
    bundle = _granted_bundle(tmp_path, "retain_events:apply")
    assert (
        _cli_main()(["--root", str(root), "--keep-days", "0", "--apply", "--policy", str(bundle)])
        == 0
    )
    assert _held(root) == 10, (
        f"the pass deleted inside the correlation window: {_held(root)} of 10 left"
    )


@pytest.mark.unit
def test_a_zero_margin_restores_pruning_to_the_cursor(tmp_path: Path) -> None:
    """The counter-test. Without it the one above could pass for any reason.

    ``--lookback-margin 0`` is the documented way back to the old behaviour,
    and it must demonstrably delete the rows the default spares — otherwise the
    test above is not measuring the margin.
    """
    root = _root(tmp_path)
    _tight(root, count=10)
    bundle = _granted_bundle(tmp_path, "retain_events:apply")
    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--lookback-margin",
                "0",
                "--apply",
                "--policy",
                str(bundle),
            ]
        )
        == 0
    )
    assert _held(root) == 1, (
        f"a zero margin should prune to the cursor's own stamp, leaving 1; {_held(root)} left"
    )


@pytest.mark.unit
def test_the_margin_does_not_spare_genuinely_old_events(tmp_path: Path) -> None:
    """The margin is 900 seconds, not an amnesty.

    A pass that stopped reclaiming anything would be a worse defect than the
    one being fixed: ``scripts/run_retention.py`` exists because the store
    grows at roughly 1.8 KB an event.
    """
    root = _root(tmp_path)
    _seed(root, old=12, recent=4)
    bundle = _granted_bundle(tmp_path, "retain_events:apply")
    assert _cli_main()(["--root", str(root), "--apply", "--policy", str(bundle)]) == 0
    assert _held(root) == 4, (
        f"the 200-day-old events were not reclaimed: {_held(root)} held, expected the 4 recent"
    )


@pytest.mark.unit
@pytest.mark.parametrize("value", ["-1", "-0.5", "nan", "inf"])
def test_a_margin_that_cannot_mean_anything_is_refused(tmp_path: Path, value: str) -> None:
    """Exit 2, the misconfiguration code, as ``--keep-days`` already does.

    A negative margin would push the bound *forward* of the cursor and delete
    unprocessed evidence, so this is fail-closed and not tidiness.
    """
    root = _root(tmp_path)
    _tight(root, count=4)
    assert _cli_main()(["--root", str(root), "--lookback-margin", value]) == 2


@pytest.mark.unit
def test_include_unprocessed_bypasses_the_margin(tmp_path: Path) -> None:
    """The deliberate purge stays deliberate.

    ``--include-unprocessed`` is where an operator says they mean it, and it
    already overrides the cursor bound the margin is an extension of. Honouring
    the margin there would make the documented "retain nothing" unreachable.
    """
    root = _root(tmp_path)
    _tight(root, count=10)
    bundle = _granted_bundle(tmp_path, "retain_events:apply", "retain_events:apply-unprocessed")
    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--include-unprocessed",
                "--apply",
                "--policy",
                str(bundle),
            ]
        )
        == 0
    )
    assert _held(root) == 0, f"the override did not reach everything: {_held(root)} held"


@pytest.mark.unit
def test_the_two_withheld_figures_are_disjoint_and_both_reported(
    tmp_path: Path, capsys: Any
) -> None:
    """One number covering both causes would be unactionable.

    Events withheld as unprocessed mean the cycle has stalled and an operator
    should go and look; events withheld for correlation mean the cycle is
    working and the margin is doing its job. Measured before they were
    separated: a pass reported "3 withheld as not yet processed" when 2 of the
    3 had demonstrably been processed.
    """
    root = _root(tmp_path)
    _seed(root, old=12, recent=4, processed=6)
    assert _cli_main()(["--root", str(root), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["lookback_margin"] == 900.0
    unprocessed = payload["events_withheld_unprocessed"]
    correlation = payload["events_withheld_for_correlation"]
    assert unprocessed >= 0 and correlation >= 0
    assert payload["effective_threshold"] == (
        payload["cursor_ingested_at"] - payload["lookback_margin"]
    )
    # The window matched more than the pass will take, and every withheld row
    # is attributed to exactly one cause.
    assert payload["events_matching"] + unprocessed + correlation <= payload["events_total"]


# --------------------------------------------------------------------------
# The withheld figure is counted, not derived (#59)
# --------------------------------------------------------------------------


def _one_commit(root: Path, *, count: int, age_days: float, at: int | None = None) -> int:
    """One ``append_many`` commit, cursor inside it, and the keyset truth.

    ``append_many`` stamps one ``ingested_at`` across the whole commit — the
    production shape, since both writers use it — which is the fixture the
    withheld figure used to be wrong on. ``at`` is the 0-based row the cursor
    sits on, counting in the store's own ``(ingested_at, event_id)`` order;
    ``None`` puts it on the newest, i.e. a caught-up cycle. Returns the number
    of in-window events the cycle genuinely has **not** read, computed by that
    same total order rather than by subtracting timestamp counts.
    """
    now = time.time()
    with EventStore.open(root) as store:
        store.append_many(
            tuple(
                normalize(_RECORD.replace("svc-deploy", f"row{index}")) for index in range(count)
            ),
            ingested_at=now - age_days * 86_400,
        )
        rows = store.query(Query(limit=count, newest_first=False))
        reached = rows[-1 if at is None else at]
        truth = sum(
            1
            for row in rows
            if (row.ingested_at, row.event_id) > (reached.ingested_at, reached.event_id)
        )
    save_cursor(
        cursor_path(root),
        Cursor(ingested_at=reached.ingested_at, event_id=reached.event_id),
    )
    return truth


@pytest.mark.unit
def test_a_caught_up_cycle_is_not_blamed_for_its_own_commit(tmp_path: Path, capsys: Any) -> None:
    """The defect: 12 reported as unprocessed where 0 were.

    One commit, the cursor on its newest row, the cycle demonstrably caught
    up. The old figure was ``window_matching - matching - margin_withheld`` —
    every row the bound refused — and it named all of them "not yet processed
    by the detection cycle", then offered ``--include-unprocessed``, which on
    this store deletes the whole thing.
    """
    root = _root(tmp_path)
    truth = _one_commit(root, count=12, age_days=100)
    assert truth == 0, "fixture is not caught up, so it cannot show the defect"

    assert _cli_main()(["--root", str(root), "--keep-days", "0", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["events_withheld_unprocessed"] == 0
    assert payload["events_withheld_at_cursor_stamp"] == 12


@pytest.mark.unit
def test_the_inflation_is_the_read_prefix_and_not_the_whole_commit(
    tmp_path: Path, capsys: Any
) -> None:
    """The counter-test for the fix that was tried and refuted.

    Subtracting the cursor's **tie group** was the obvious repair and it is
    wrong: with the cursor at the midpoint of a 12-row commit the group is 12
    and the already-read prefix is 6, so that repair would report 0 where 6
    rows are genuinely unread — trading an over-report for an under-report on
    the one figure an operator uses to decide the cycle has stalled. Only the
    keyset tells the two apart, which is why the figure is counted.
    """
    root = _root(tmp_path)
    truth = _one_commit(root, count=12, age_days=100, at=5)
    assert truth == 6, "fixture must leave the cursor mid-commit"

    assert _cli_main()(["--root", str(root), "--keep-days", "0", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["events_withheld_unprocessed"] == truth
    # Not zero, which is what subtracting the whole tie group would give.
    assert payload["events_withheld_unprocessed"] != 0
    assert payload["events_withheld_at_cursor_stamp"] == 6


@pytest.mark.unit
def test_the_three_withheld_figures_account_for_the_whole_window(
    tmp_path: Path, capsys: Any
) -> None:
    """The identity, which is what makes the report an account rather than a hint.

    ``matching`` plus the three disjoint withheld figures equals what the
    window matched. Without the third field in the payload this cannot be
    checked from JSON at all — ``window_matching`` was never a field — so a
    reader on a caught-up single-commit node would see a pass that matched
    nothing and withheld nothing while 12 events sat in the window.
    """
    root = _root(tmp_path)
    _one_commit(root, count=12, age_days=100, at=5)

    assert _cli_main()(["--root", str(root), "--keep-days", "0", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    with EventStore.open(root) as store:
        window = store.count_before(before=float(payload["threshold_ingested_before"]))
    assert (
        payload["events_matching"]
        + payload["events_withheld_unprocessed"]
        + payload["events_withheld_at_cursor_stamp"]
        + payload["events_withheld_for_correlation"]
    ) == window


@pytest.mark.unit
def test_the_commit_sentence_offers_no_flag_and_claims_nothing_about_the_cycle(
    tmp_path: Path, capsys: Any
) -> None:
    """It must not recommend the destructive flag, nor say the cycle is fine.

    The first is the defect inverted: on this very store
    ``--include-unprocessed`` deletes every event. The second is a trap an
    earlier draft of this sentence fell into — ``commit_held`` with zero
    unprocessed is also what a cycle stalled longer than ``--keep-days`` looks
    like, so "the cycle is not behind, there is nothing to do" would be false
    exactly where it is most often printed. The figure is window-scoped and
    cannot witness either, so the sentence defers to the indicators that can.
    """
    root = _root(tmp_path)
    _one_commit(root, count=12, age_days=100)

    assert _cli_main()(["--root", str(root), "--keep-days", "0"]) == 0
    out = capsys.readouterr().out

    assert "withheld because the cursor sits in their commit" in out
    # The flag is named, but to refuse it. An operator who learned the old
    # message will look for it, so silence would be worse than a refusal —
    # what must not survive is the old sentence's recommendation.
    assert "--include-unprocessed is not the remedy" in out
    assert "overrides it" not in out
    # And no claim about a cycle this figure cannot see.
    assert "not behind" not in out
    assert "nothing to do" not in out
    assert "detection-backlog" in out


# --------------------------------------------------------------------------
# A dry run can bound the delete it authorizes (#60)
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_future_pin_changes_nothing_because_before_is_a_ceiling(
    tmp_path: Path, capsys: Any
) -> None:
    """``--before`` is ``min``-ed with the clock, so it can only ever narrow.

    The property that keeps it from being a second, ungated way to say "retain
    nothing": a pin past the clock-derived boundary is discarded, and the pass
    reports exactly what it would have unpinned.
    """
    root = _root(tmp_path)
    _seed(root, old=6, recent=4)

    assert _cli_main()(["--root", str(root), "--json"]) == 0
    unpinned = json.loads(capsys.readouterr().out)

    assert _cli_main()(["--root", str(root), "--json", "--before", str(time.time() + 86_400)]) == 0
    pinned = json.loads(capsys.readouterr().out)

    assert pinned["events_matching"] == unpinned["events_matching"]
    assert pinned["threshold_ingested_before"] == pytest.approx(
        unpinned["threshold_ingested_before"], abs=5.0
    )
    # The pin did not bind, so it is not recorded as a cause of anything.
    assert pinned["window_pinned_before"] is None


@pytest.mark.unit
def test_a_pin_that_binds_is_recorded_and_named_in_the_text(tmp_path: Path, capsys: Any) -> None:
    """A pin that emptied the window must say so instead of blaming the window.

    Measured before the fix: 12 events ingested 100 days ago, a 90-day window
    pinned 200 days back, and the report said "no event was ingested more than
    90.0 day(s) ago" — false, and the pin named nowhere in the text while the
    audit chain recorded it.
    """
    root = _root(tmp_path)
    _seed(root, old=6, recent=4)
    pin = time.time() - 300 * 86_400

    assert _cli_main()(["--root", str(root), "--caller", "pinned", "--before", str(pin)]) == 0
    out = capsys.readouterr().out

    assert "--before pinned the window" in out
    assert "no event was ingested more than" not in out
    assert _held(root) == 10


@pytest.mark.unit
def test_an_apply_removes_no_more_than_a_pinned_dry_run_reported(
    tmp_path: Path, capsys: Any
) -> None:
    """The point of the flag: the window the operator reviewed is the ceiling.

    Unpinned, the threshold is re-derived from ``time.time()`` on each
    invocation, so whatever ages past the boundary between the two commands is
    deleted without having been reported — measured at one event a second, 9
    reported and 15 removed six seconds later. The precondition matters: the
    cursor must sit above the threshold plus the margin, or this asserts
    ``0 == 0``.
    """
    root = _root(tmp_path)
    _seed(root, old=6, recent=4)
    bundle = _granted_bundle(tmp_path, "retain_events:apply")

    assert _cli_main()(["--root", str(root), "--json"]) == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["events_matching"] > 0, "nothing was deletable, so the pin is untested"

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--json",
                "--apply",
                "--policy",
                str(bundle),
                "--before",
                str(dry["effective_threshold"]),
            ]
        )
        == 0
    )
    applied = json.loads(capsys.readouterr().out)

    assert applied["events_removed"] <= dry["events_matching"]
    assert applied["window_pinned_before"] == pytest.approx(dry["effective_threshold"])
