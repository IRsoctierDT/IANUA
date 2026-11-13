# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Local phishing simulation metrics from aggregate campaign observations."""

from __future__ import annotations

import sqlite3
from datetime import date

from store.lab_vulnerabilities import LabInputError, lab_id, source_time


def record_campaign(
    db: sqlite3.Connection,
    *,
    campaign: str,
    owner: str,
    start: date,
    end: date,
    source_at: str,
    delivered: int,
    reported: int,
    handled: int,
    response_minutes: int,
) -> None:
    """Store one immutable aggregate per campaign, rejecting invalid denominators."""
    campaign, owner = lab_id(campaign), lab_id(owner)
    stamp = source_time(source_at)
    if (
        not start <= end <= date.fromisoformat(stamp[:10])
        or not 0 <= handled <= reported <= delivered
        or response_minutes < 0
        or (not handled and response_minutes)
    ):
        raise LabInputError("Check campaign dates, counts and response minutes.")
    with db:
        db.execute("BEGIN IMMEDIATE")
        values = (
            campaign,
            owner,
            start.isoformat(),
            end.isoformat(),
            stamp,
            delivered,
            reported,
            handled,
            response_minutes,
        )
        prior = db.execute("SELECT * FROM phishing WHERE campaign=?", (campaign,)).fetchone()
        if prior is not None and tuple(prior) != values:
            raise LabInputError("This campaign alias already has a different record.")
        db.execute("INSERT OR IGNORE INTO phishing VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", values)


def campaign_metrics(
    db: sqlite3.Connection,
    start: date,
    end: date,
) -> tuple[list[sqlite3.Row], float | None, float | None]:
    """Return fully contained campaigns, weighted reporting rate and response time."""
    if start > end:
        raise LabInputError("Reporting period start must precede its end.")
    rows = db.execute(
        """
        SELECT * FROM phishing WHERE started>=? AND ended<=? ORDER BY ended DESC, campaign
    """,
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    delivered = sum(row["delivered"] for row in rows)
    reported = sum(row["reported"] for row in rows)
    handled = sum(row["handled"] for row in rows)
    minutes = sum(row["response_minutes"] for row in rows)
    return rows, reported / delivered if delivered else None, minutes / handled if handled else None
