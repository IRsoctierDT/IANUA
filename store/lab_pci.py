# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""PCI DSS v4.0.1 lab evidence and measurable weekly review."""

from __future__ import annotations

import sqlite3
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from store.lab_vulnerabilities import LabInputError, lab_id, source_time

PCI_SOURCE = "https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss"
PCI_REQUIREMENTS = {
    "6.3.1": (
        "Vulnerability identification and ranking",
        "Review vulnerability sources, ranking rationale and asset context.",
    ),
    "6.3.3": (
        "Security patches and updates",
        "Compare patch release and installation evidence to applicable deadlines.",
    ),
    "8.2.2": (
        "Exceptional use of shared or generic accounts",
        "Review exceptional-use approvals and individual accountability.",
    ),
    "11.3.1": (
        "Periodic internal vulnerability scanning",
        "Inspect internal scan coverage and rescan evidence for prioritized findings.",
    ),
    "11.3.1.1": (
        "Other internal scan vulnerabilities",
        "Review the targeted risk analysis, remediation timing and rescans.",
    ),
    "11.3.1.2": (
        "Authenticated internal scanning",
        "Inspect scan privileges, results and documented credential exceptions.",
    ),
    "11.3.1.3": (
        "Internal scans after significant changes",
        "Compare change records with scan coverage and remediation evidence.",
    ),
    "11.3.2": (
        "Periodic external ASV scans",
        "Inspect applicable ASV reports and passing rescans.",
    ),
    "11.3.2.1": (
        "External scans after significant changes",
        "Compare change records with external scan and rescan coverage.",
    ),
}


def link_evidence(
    db: sqlite3.Connection,
    *,
    asset: str,
    check: str,
    revision: int,
    requirement: str,
    evidence_id: str,
    reviewer: str,
    reviewed_at: datetime,
) -> None:
    """Record a local evidence reference against the verified finding revision."""
    if requirement not in PCI_REQUIREMENTS:
        raise LabInputError("Select a supported requirement.")
    evidence_id, reviewer = lab_id(evidence_id), lab_id(reviewer)
    with db:
        db.execute("BEGIN IMMEDIATE")
        finding = db.execute(
            """
            SELECT 1 FROM findings
            WHERE asset=? AND check_id=? AND revision=? AND state='Verified'
        """,
            (asset, check, revision),
        ).fetchone()
        if finding is None:
            raise LabInputError("Reload the current verified finding before linking evidence.")
        db.execute(
            """
            INSERT INTO pci_evidence VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset, check_id, revision, requirement, evidence_id) DO NOTHING
        """,
            (
                asset,
                check,
                revision,
                requirement,
                evidence_id,
                reviewer,
                source_time(reviewed_at.isoformat()),
            ),
        )


def evidence_rows(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """Read evidence links with the historical ticket, source and review time."""
    return [
        dict(row)
        for row in db.execute("""
        SELECT e.*, h.ticket, h.owner, h.baseline, h.rescan, s.sha256 AS rescan_sha256,
               s.scanned_at AS rescanned_at
        FROM pci_evidence e JOIN history h USING (asset, check_id, revision)
        JOIN scans s ON s.id=h.rescan ORDER BY e.reviewed_at DESC
    """)
    ]


def weekly_scorecard(db: sqlite3.Connection, monday: date) -> dict[str, int]:
    """Count UTC ISO-week activity using recorded times and distinct finding keys."""
    start = datetime.combine(monday, time.min, UTC).isoformat(timespec="microseconds")
    end = datetime.combine(monday + timedelta(days=7), time.min, UTC).isoformat(
        timespec="microseconds"
    )
    states = db.execute(
        """
        SELECT state, count(*) FROM (
            SELECT DISTINCT state, asset, check_id FROM history
            WHERE recorded_at>=? AND recorded_at<?
        ) GROUP BY state
    """,
        (start, end),
    )
    counts = dict(states)
    links = db.execute(
        """
        SELECT count(*) FROM pci_evidence WHERE reviewed_at>=? AND reviewed_at<?
    """,
        (start, end),
    ).fetchone()[0]
    return {
        "Findings opened": counts.get("Open", 0),
        "Owners assigned": counts.get("Assigned", 0),
        "Fixes recorded": counts.get("Awaiting rescan", 0),
        "Rescans verified": counts.get("Verified", 0),
        "Evidence links reviewed": links,
    }
