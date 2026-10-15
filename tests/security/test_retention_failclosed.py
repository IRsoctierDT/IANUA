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
from store import EventStore

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
    root.mkdir(exist_ok=True)
    now = time.time()
    with EventStore.open(root) as store:
        store.append_many(
            tuple(
                normalize(_RECORD.replace("svc-deploy", f"user{index:05d}"))
                for index in range(events)
            ),
            ingested_at=store.next_stamp(now - 200 * 86_400),
        )
        assert store.count() == events, "the fixture collapsed its records"
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
