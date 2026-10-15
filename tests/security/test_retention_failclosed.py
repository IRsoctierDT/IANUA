# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Retention must not report, or delete, from a store whose rows cannot be read.

This is the one CLI that can destroy evidence, and it was the one CLI in the
repository that failed **open** on a damaged store: exit ``0``, a report no
field of which distinguished a store with every row body destroyed from a
healthy one, and a ``would remove 200 of 200 event(s)`` record written into a
hash chain that then verified.

The mechanism is worth stating because it is not the obvious one. Retention's
``except`` clause already named ``sqlite3.Error``; the problem was that nothing
raised. ``count()`` plans as ``SCAN events USING COVERING INDEX
events_ingested_at`` and ``count_before()`` as ``SEARCH ... COVERING INDEX``,
so neither reads a table page and both answer confidently over rows that cannot
be read. Structurally the same defect as the attestation one before it.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from pipeline import Cursor, cursor_path, load_cursor, save_cursor
from store import MAX_QUERY_LIMIT, EventStore, Query

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-deploy" addr=203.0.113.9 res=failed'


def _cli_main() -> Any:
    from scripts.run_retention import main

    return main


def _seeded(tmp_path: Path, *, events: int = 200) -> Path:
    """A root holding ``events`` distinct events, WAL folded into the main file.

    Distinct because ``event_id`` is content-addressed: identical records
    collapse to one row, a fixture bug this repository has paid for once.
    """
    root = tmp_path / "root"
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    batch = max(1, events // 4)
    with EventStore.open(root) as store:
        # Four commits rather than one, and the reason is load-bearing: one
        # `append_many` stamps every row with a single `ingested_at`, and
        # retention's clamp cannot delete below the cursor's own stamp
        # (`prune` is `ingested_at < ?`). A single-commit fixture with a
        # caught-up cursor therefore prunes nothing, and the healthy leg below
        # would measure the clamp instead of the integrity gate it is about.
        for start in range(0, events, batch):
            store.append_many(
                tuple(
                    normalize(_RECORD.replace("svc-deploy", f"user{index:05d}"))
                    for index in range(start, min(start + batch, events))
                ),
                ingested_at=store.next_stamp(now - (200 - start) * 86_400),
            )
        assert store.count() == events, "the fixture collapsed its records"
        newest = store.query(Query(limit=1))[0]
    # Caught up: the cursor on the newest commit, so the window governs and the
    # clamp binds only on that last group.
    save_cursor(
        cursor_path(root),
        Cursor(ingested_at=newest.ingested_at, event_id=newest.event_id),
    )
    database = root / "data" / "events" / "events.sqlite3"
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
    finally:
        folding.close()
    return root


def _damage_a_row_bearing_page(root: Path) -> int:
    """Zero the first page whose loss makes a row read fail. Returns the page.

    Found by sweeping rather than by assuming a page number: which pages carry
    rows depends on the b-tree layout, and a hard-coded page is a fixture that
    silently stops reaching the condition when the schema changes.
    """
    database = root / "data" / "events" / "events.sqlite3"
    probe = sqlite3.connect(database)
    try:
        page_size = int(probe.execute("PRAGMA page_size").fetchone()[0])
    finally:
        probe.close()
    pristine = database.read_bytes()
    for pageno in range(2, len(pristine) // page_size + 1):
        offset = (pageno - 1) * page_size
        database.write_bytes(pristine[:offset] + bytes(page_size) + pristine[offset + page_size :])
        conn = sqlite3.connect(database)
        try:
            conn.execute("SELECT projection FROM events LIMIT 5").fetchall()
        except sqlite3.DatabaseError:
            return pageno
        finally:
            conn.close()
        database.write_bytes(pristine)
    raise AssertionError("no page's loss broke a row read; the fixture proves nothing")


def _held(root: Path) -> int:
    with EventStore.open(root) as store:
        return store.count()


def _mark(root: Path) -> float:
    with EventStore.open(root) as store:
        mark = store.high_water_mark()
    assert mark is not None, "the fixture stored no events"
    return mark


def _chain_lines(root: Path) -> list[dict[str, Any]]:
    path = root / "data" / "events" / "audit.log"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@pytest.mark.security
def test_a_report_only_pass_refuses_a_store_whose_rows_cannot_be_read(
    tmp_path: Path, capsys: Any
) -> None:
    """Exit non-zero, and name the fault rather than a count.

    The healthy leg is asserted in the same test because "refuses" is worthless
    without it: a gate that refuses everything would satisfy the first half.
    """
    root = _seeded(tmp_path)
    healthy = _cli_main()(["--root", str(root), "--caller", "probe"])
    assert healthy == 0, capsys.readouterr().err
    healthy_out = capsys.readouterr().out
    assert "would remove" in healthy_out

    pageno = _damage_a_row_bearing_page(root)
    with EventStore.open(root) as store:
        # The precondition, asserted: the counts still answer, which is why the
        # CLI believed them. If this ever stops being true the test is no longer
        # measuring the defect it was written for.
        assert store.count() == 200
    assert _cli_main()(["--root", str(root), "--caller", "probe"]) == 1, (
        f"retention accepted a store damaged at page {pageno}"
    )
    captured = capsys.readouterr()
    assert "damaged" in captured.err, captured.err
    assert "would remove" not in captured.out


@pytest.mark.security
def test_the_refused_pass_records_no_claim_about_events_it_could_not_read(
    tmp_path: Path,
) -> None:
    """The chain may record that the pass was permitted; never what it found.

    The fail-open wrote ``retain_events:200`` / ``decision: allow`` / ``would
    remove 200 of 200 event(s)`` onto a store from which zero rows were
    readable, and ``AuditLogger.verify()`` returned ``True`` — a chain-valid
    false record. The repository's own precedent for this is the pipeline's
    "audit intent, not outcome" fix (``scripts/run_pipeline.py``), and the
    charter rule is AGENTS.md §3's auditability requirement.
    """
    root = _seeded(tmp_path)
    _damage_a_row_bearing_page(root)
    assert _cli_main()(["--root", str(root), "--caller", "probe"]) == 1

    records = _chain_lines(root)
    assert records, "the gate decision itself should still be recorded"
    outcomes = [
        record
        for record in records
        if "would remove" in str(record.get("reason", ""))
        or str(record.get("action", "")).startswith("retain_events:")
    ]
    assert not outcomes, f"the refused pass recorded an outcome: {outcomes}"


# ----------------------------------------- the cursor bound on the delete path
#
# None of the 2196 tests at the commit before this one set a cursor before
# running retention (`grep -n cursor tests/unit/test_retention.py` matched one
# prose line; this file matched nothing), so three of the four candidate fixes
# were invisible to the entire suite. Everything below is therefore load-bearing
# rather than confirmatory.

#: The label the override is gated on. Pinned as a literal **here** as well as
#: in the CLI, because the one thing that makes the gate real is that it differs
#: from ``retain_events:apply`` — fold the two together and the grant an
#: operator already has self-authorizes the wider action.
_OVERRIDE_LABEL = "retain_events:apply-unprocessed"
_APPLY_LABEL = "retain_events:apply"


def _bundle(tmp_path: Path, *labels: str) -> Path:
    """The committed bundle with exactly ``labels`` granted."""
    repo_root = Path(__file__).resolve().parents[2]
    bundle = json.loads(
        (repo_root / "agents" / "policies" / "policy.json").read_text(encoding="utf-8")
    )
    bundle["allow"] = list(labels)
    path = tmp_path / f"bundle-{'-'.join(labels) or 'none'}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _behind(root: Path, *, commits_processed: int = 1) -> int:
    """Put the cursor on the ``commits_processed``-th oldest commit.

    Returns how many events are left unprocessed, asserted non-zero so a
    fixture that accidentally catches the cursor up cannot pass silently.
    """
    with EventStore.open(root) as store:
        rows = store.query(Query(limit=MAX_QUERY_LIMIT, newest_first=False))
    stamps = sorted({row.ingested_at for row in rows})
    boundary = stamps[commits_processed - 1]
    reached = [row for row in rows if row.ingested_at == boundary][-1]
    save_cursor(
        cursor_path(root), Cursor(ingested_at=reached.ingested_at, event_id=reached.event_id)
    )
    unprocessed = sum(1 for row in rows if row.ingested_at > boundary)
    assert unprocessed, "the fixture left nothing unprocessed, so it proves nothing"
    return unprocessed


@pytest.mark.security
def test_a_granted_pass_does_not_delete_what_the_cycle_has_not_processed(
    tmp_path: Path,
) -> None:
    """The defect, in the one CLI that can destroy evidence.

    Measured before the clamp: 40 events over 10 days with only the oldest 5
    processed and ``--keep-days 3 --apply`` destroyed **24 events the detection
    cycle had never looked at**, exit 0, reported as a clean
    ``events_removed: 29``. ``UPDATE`` is trigger-refused and ``event_id`` is a
    sha256 over the projection, so those rows cannot be recovered — it is
    evidence destroyed before anything analysed it.
    """
    root = _seeded(tmp_path)
    unprocessed = _behind(root)
    bundle = _bundle(tmp_path, _APPLY_LABEL)

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--apply",
                "--policy",
                str(bundle),
                "--caller",
                "probe",
            ]
        )
        == 0
    )

    with EventStore.open(root) as store:
        rows = store.query(Query(limit=MAX_QUERY_LIMIT))
    cursor = load_cursor(cursor_path(root))
    assert cursor is not None
    survived = sum(1 for row in rows if row.ingested_at > cursor.ingested_at)
    assert survived == unprocessed, (
        f"{unprocessed - survived} never-processed event(s) were destroyed"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    ("state", "prepare"),
    [
        ("absent", lambda root: cursor_path(root).unlink()),
        (
            "ahead-of-store",
            lambda root: save_cursor(
                cursor_path(root),
                Cursor(ingested_at=_mark(root) + 86_400.0, event_id="z" * 64),
            ),
        ),
    ],
)
def test_a_cursor_that_cannot_be_trusted_deletes_nothing(
    tmp_path: Path, state: str, prepare: Any
) -> None:
    """Two states where "nothing is known to be processed" is the only safe answer.

    ``absent`` is not a corner case: ``docs/RESTORE.md`` step 3 deletes
    ``cursor.json`` by design and step 6 restarts the timers, so it sits on the
    documented recovery path. Measured end to end before the clamp, the
    documented restore left no cursor and the next pass destroyed **1500 of
    1500** restored events — treating an absent cursor as "no constraint" gives
    zero protection in exactly the state holding the most unprocessed evidence.

    ``ahead-of-store`` is the skew ``docs/RESTORE.md`` calls unrecoverable.
    ``sli/indicators.py`` already grades it ``UNKNOWN`` for both
    ``detection-lag`` and ``detection-backlog``; retention must not be the one
    reader that treats it as healthy. A clamp would bind on nothing there while
    ``count_before`` still reported rows as deletable.
    """
    root = _seeded(tmp_path)
    before = _held(root)
    prepare(root)
    bundle = _bundle(tmp_path, _APPLY_LABEL)

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--apply",
                "--policy",
                str(bundle),
                "--caller",
                "probe",
                "--json",
            ]
        )
        == 0
    )
    assert _held(root) == before, f"a {state} cursor still permitted a delete"


@pytest.mark.security
def test_an_unreadable_cursor_refuses_the_pass(tmp_path: Path) -> None:
    """Raised, not defaulted — ``pipeline/cursor.py``'s own stated posture.

    ``CursorError`` derives from ``PipelineError(Exception)``, not from
    ``StoreError`` or ``ValueError``, so without its own clause it would reach
    an unattended scheduler as a traceback rather than an exit code. That is a
    shape this file has already been fixed for twice.
    """
    root = _seeded(tmp_path)
    _behind(root)
    cursor_path(root).write_text("{ not json", encoding="utf-8")
    bundle = _bundle(tmp_path, _APPLY_LABEL)
    before = _held(root)

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--apply",
                "--policy",
                str(bundle),
                "--caller",
                "probe",
            ]
        )
        == 2
    )
    assert _held(root) == before


@pytest.mark.security
def test_the_override_needs_its_own_grant_and_the_apply_grant_is_not_enough(
    tmp_path: Path,
) -> None:
    """The separation of the two labels IS the control, so it is asserted directly.

    An operator who has already granted ``retain_events:apply`` must not thereby
    have granted "also destroy evidence nothing has looked at". Both directions
    are checked, because "the override is blocked" is satisfied by an override
    that never works at all.
    """
    denied = _seeded(tmp_path / "denied")
    _behind(denied)
    held_before = _held(denied)
    assert (
        _cli_main()(
            [
                "--root",
                str(denied),
                "--keep-days",
                "0",
                "--apply",
                "--include-unprocessed",
                "--policy",
                str(_bundle(tmp_path, _APPLY_LABEL)),
                "--caller",
                "probe",
            ]
        )
        == 3
    ), "the apply grant alone authorized the override"
    assert _held(denied) == held_before

    allowed = _seeded(tmp_path / "allowed")
    unprocessed = _behind(allowed)
    assert (
        _cli_main()(
            [
                "--root",
                str(allowed),
                "--keep-days",
                "0",
                "--apply",
                "--include-unprocessed",
                "--policy",
                str(_bundle(tmp_path, _APPLY_LABEL, _OVERRIDE_LABEL)),
                "--caller",
                "probe",
            ]
        )
        == 0
    ), "the override does not work even when granted, so the test above is vacuous"
    with EventStore.open(allowed) as store:
        rows = store.query(Query(limit=MAX_QUERY_LIMIT))
    cursor = load_cursor(cursor_path(allowed))
    assert cursor is not None
    assert sum(1 for row in rows if row.ingested_at > cursor.ingested_at) < unprocessed, (
        "the granted override deleted nothing unprocessed, so it is not the override"
    )


@pytest.mark.security
def test_the_clamp_is_free_on_a_caught_up_node(tmp_path: Path) -> None:
    """The other direction: the fix must not cost a healthy SOC anything.

    A clamp that quietly retains more than the operator asked for, on a node
    that is keeping up, would be a disk regression disguised as a safety
    feature. Measured across a grid, the clamp binds only when detection lag
    exceeds the entire retention window — and the one group it always holds is
    the commit the cursor sits in, which this asserts rather than hides.
    """
    root = _seeded(tmp_path)
    with EventStore.open(root) as store:
        stamps = sorted({row.ingested_at for row in store.query(Query(limit=MAX_QUERY_LIMIT))})
        newest_group = sum(
            1 for row in store.query(Query(limit=MAX_QUERY_LIMIT)) if row.ingested_at == stamps[-1]
        )
    bundle = _bundle(tmp_path, _APPLY_LABEL)

    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--apply",
                "--policy",
                str(bundle),
                "--caller",
                "probe",
            ]
        )
        == 0
    )
    assert _held(root) == newest_group, (
        "a caught-up node retained more than the cursor's own commit"
    )


@pytest.mark.security
def test_the_withheld_count_reaches_the_report_and_the_chain(tmp_path: Path, capsys: Any) -> None:
    """Not only stderr, which is the shape task #48 fixed in this same file.

    Warn-only was rejected as the fix partly for this: measured, the warning
    reached stderr while the JSON report and the audit chain still said
    ``removed 29 of 40`` with no mention that 25 were never processed. A record
    that omits what the pass withheld is a record an operator cannot act on,
    and AGENTS.md §3 requires security-relevant actions to emit structured
    evidence of what happened.
    """
    root = _seeded(tmp_path)
    _behind(root)
    assert _cli_main()(["--root", str(root), "--caller", "probe", "--json"]) == 0
    captured = json.loads(capsys.readouterr().out)

    assert captured["cursor_state"] == "present"
    assert captured["events_withheld_unprocessed"] > 0
    assert captured["cursor_ingested_at"] is not None
    assert captured["effective_threshold"] == captured["cursor_ingested_at"]

    reasons = [str(record.get("reason", "")) for record in _chain_lines(root)]
    assert any("withheld as" in reason for reason in reasons), (
        f"the chain does not record what was withheld: {reasons}"
    )


@pytest.mark.security
def test_a_cursor_inside_a_commit_does_not_cost_that_commit_its_unprocessed_rows(
    tmp_path: Path,
) -> None:
    """The case a cursor on a commit *boundary* cannot reach.

    One ``append_many`` stamps every row with a single ``ingested_at`` — a
    collector pass of 5000 lines produced exactly one distinct stamp — while the
    cursor is the pair ``(ingested_at, event_id)``. So the cycle can be halfway
    through a commit, with processed and unprocessed rows sharing one stamp.

    ``prune`` is ``DELETE FROM events WHERE ingested_at < ?`` with no
    ``event_id`` tie-break, so a threshold is all-or-nothing over a tie group
    and cannot split one. That is why the clamp is ``min(threshold, bound)`` and
    **never** ``math.nextafter(bound, inf)``: nudging past the cursor's own
    stamp takes the whole group, and in this state the group contains rows the
    cycle has not read — 490 of 500 in one measurement.

    The other tests here put the cursor on a commit's last row, where its group
    holds nothing unprocessed, so none of them can see that mistake. This one
    can. The cost of the safe direction is asserted too: rows the cycle *has*
    processed, at the cursor's own stamp, are retained — under-deletion, which
    is the direction that cannot lose evidence.
    """
    root = tmp_path / "root"
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with EventStore.open(root) as store:
        # Two commits: an old one to prove the pass still deletes something, and
        # one the cursor will sit inside.
        store.append_many(
            tuple(
                normalize(_RECORD.replace("svc-deploy", f"old{index:04d}")) for index in range(20)
            ),
            ingested_at=store.next_stamp(now - 300 * 86_400),
        )
        store.append_many(
            tuple(
                normalize(_RECORD.replace("svc-deploy", f"tie{index:04d}")) for index in range(40)
            ),
            ingested_at=store.next_stamp(now - 200 * 86_400),
        )
        rows = store.query(Query(limit=MAX_QUERY_LIMIT, newest_first=False))

    stamps = sorted({row.ingested_at for row in rows})
    group = sorted(
        (row for row in rows if row.ingested_at == stamps[-1]), key=lambda row: row.event_id
    )
    assert len(group) > 2, "the tie group is too small to sit inside"
    midpoint = len(group) // 2
    save_cursor(
        cursor_path(root),
        Cursor(ingested_at=group[midpoint].ingested_at, event_id=group[midpoint].event_id),
    )
    unread = {row.event_id for row in group[midpoint + 1 :]}
    assert unread, "the cursor landed on the last row; this fixture proves nothing"

    bundle = _bundle(tmp_path, _APPLY_LABEL)
    assert (
        _cli_main()(
            [
                "--root",
                str(root),
                "--keep-days",
                "0",
                "--apply",
                "--policy",
                str(bundle),
                "--caller",
                "probe",
            ]
        )
        == 0
    )

    with EventStore.open(root) as store:
        survivors = {row.event_id for row in store.query(Query(limit=MAX_QUERY_LIMIT))}
    assert unread <= survivors, (
        f"{len(unread - survivors)} of {len(unread)} unread row(s) sharing the "
        "cursor's stamp were destroyed"
    )
    # Non-vacuity: the pass must still have deleted the older commit, or
    # "nothing was destroyed" is true of a pass that did nothing.
    assert len(survivors) == len(group), (
        f"expected only the cursor's own commit to survive, got {len(survivors)}"
    )
