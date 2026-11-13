# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Validated, single-operator vulnerability workflow for redacted lab data."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents.vulnerability_assessment_agent import VulnerabilityAssessmentAgent
from store.events import refuse_unsafe_database, refuse_unsafe_sidecars
from store.paths import confine

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CRITICALITY = {"low": 0, "medium": 5, "high": 10}
_SCOPE = {"out-of-scope": 0, "connected": 5, "cde": 10}
_STATES = ("Open", "Assigned", "Awaiting rescan", "Verified")
MAX_SCAN_LENGTH = 131_072


class LabInputError(ValueError):
    """A safe, content-free validation or workflow error."""


def lab_id(value: object) -> str:
    """Validate a bounded pseudonymous identifier with no path syntax."""
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise LabInputError("Use lab aliases of 1 to 64 letters, digits, underscores or hyphens.")
    return value


def source_time(value: object) -> str:
    """Return a source timestamp in UTC, requiring an explicit timezone."""
    if not isinstance(value, str) or len(value) > 40 or "T" not in value:
        raise LabInputError("Provide an ISO 8601 timestamp with a timezone.")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise LabInputError("Provide an ISO 8601 timestamp with a timezone.") from None


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LabInputError("Scan contains a duplicate field.")
        result[key] = value
    return result


@dataclass(frozen=True)
class Check:
    """A single explicitly evaluated asset/check pair."""

    asset: str
    check: str
    outcome: str
    cvss: float | None
    exploit: bool | None
    exposed: bool | None
    criticality: str
    scope: str

    def risk(self) -> tuple[int | None, str]:
        """Extend the agent's priority score using lab-specific context."""
        if self.cvss is None:
            return None, "CVSS missing; analyst triage required."
        item = VulnerabilityAssessmentAgent().prioritize(
            [
                {
                    "id": self.check,
                    "cvss": self.cvss,
                    "exploit_available": self.exploit,
                    "exposed": self.exposed,
                }
            ]
        )["items"][0]
        criticality = _CRITICALITY[self.criticality]
        scope = _SCOPE[self.scope]
        rationale = " ".join(item["rationale"])
        if self.exploit is None or self.exposed is None:
            rationale += " Missing exploit or exposure data; score is provisional."
        return (
            min(100, int(item["priority_score"]) + criticality + scope),
            f"{rationale} Asset criticality +{criticality}. PCI scope +{scope}.",
        )


@dataclass(frozen=True)
class Scan:
    """Redacted scanner identity, profile, time, fingerprint and checked pairs."""

    id: str
    scanner: str
    profile: str
    timestamp: str
    sha256: str
    checks: tuple[Check, ...]


def parse_scan(raw: str) -> Scan:
    """Accept only the bounded lab scan schema and unique asset/check pairs."""
    if not raw or len(raw) > MAX_SCAN_LENGTH:
        raise LabInputError("Scan is empty or exceeds the import limit.")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_fields)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, LabInputError):
            raise
        raise LabInputError("Supply valid lab scan JSON.") from None
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "version",
            "scan_id",
            "scanner",
            "profile",
            "timestamp",
            "sha256",
            "checks",
        }
        or type(data["version"]) is not int
        or data["version"] != 1
    ):
        raise LabInputError("Use the documented lab scan schema version 1.")
    checks = data["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 500:
        raise LabInputError("A scan must include 1 to 500 explicit checks.")
    digest = data["sha256"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise LabInputError("Provide the lowercase SHA-256 of the source report.")
    results: dict[tuple[str, str], Check] = {}
    for row in checks:
        if not isinstance(row, dict) or set(row) != {
            "asset",
            "check",
            "outcome",
            "cvss",
            "exploit",
            "exposed",
            "criticality",
            "scope",
        }:
            raise LabInputError("Check fields must match the version 1 schema.")
        asset, check = lab_id(row["asset"]), lab_id(row["check"])
        cvss = row["cvss"]
        if cvss is not None and (type(cvss) not in (int, float) or not 0 <= cvss <= 10):
            raise LabInputError("CVSS must be a number from 0 to 10 or null.")
        if any(
            row[key] is not None and type(row[key]) is not bool for key in ("exploit", "exposed")
        ):
            raise LabInputError("Exploit and exposure must be true, false, or null.")
        if (
            row["outcome"] not in ("failed", "passed", "incomplete")
            or row["criticality"] not in tuple(_CRITICALITY)
            or row["scope"] not in tuple(_SCOPE)
        ):
            raise LabInputError("Use the documented outcome, criticality and PCI scope values.")
        if (asset, check) in results:
            raise LabInputError("Scan contains a duplicate asset and check pair.")
        results[asset, check] = Check(
            asset,
            check,
            row["outcome"],
            cvss,
            row["exploit"],
            row["exposed"],
            row["criticality"],
            row["scope"],
        )
    return Scan(
        lab_id(data["scan_id"]),
        lab_id(data["scanner"]),
        lab_id(data["profile"]),
        source_time(data["timestamp"]),
        digest,
        tuple(results[key] for key in sorted(results)),
    )


@contextmanager
def lab_database(root: Path) -> Iterator[sqlite3.Connection]:
    """Open the owner-local workspace, using the repository's path protections."""
    try:
        path = confine(root, Path("data/command-center"), "lab.sqlite3", error=LabInputError)
    except LabInputError:
        raise LabInputError("Unsafe workspace path.") from None
    refuse_unsafe_database(path)
    refuse_unsafe_sidecars(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.parent.chmod(0o700)
    with closing(sqlite3.connect(path)) as db:
        path.chmod(0o600)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, scanner TEXT NOT NULL, profile TEXT NOT NULL,
                scanned_at TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS checks (
                scan_id TEXT NOT NULL REFERENCES scans(id), asset TEXT NOT NULL,
                check_id TEXT NOT NULL, outcome TEXT NOT NULL, cvss REAL,
                score INTEGER, rationale TEXT NOT NULL, criticality TEXT NOT NULL,
                scope TEXT NOT NULL, exploit INTEGER, exposed INTEGER,
                PRIMARY KEY (scan_id, asset, check_id)
            );
            CREATE TABLE IF NOT EXISTS findings (
                asset TEXT NOT NULL, check_id TEXT NOT NULL, baseline TEXT NOT NULL,
                state TEXT NOT NULL, owner TEXT, ticket TEXT, remediated_at TEXT,
                rescan TEXT, revision INTEGER NOT NULL,
                PRIMARY KEY (asset, check_id),
                FOREIGN KEY (baseline, asset, check_id) REFERENCES checks
            );
            CREATE TABLE IF NOT EXISTS history (
                asset TEXT NOT NULL, check_id TEXT NOT NULL, revision INTEGER NOT NULL,
                state TEXT NOT NULL, recorded_at TEXT NOT NULL, baseline TEXT NOT NULL,
                owner TEXT, ticket TEXT, remediated_at TEXT, rescan TEXT,
                PRIMARY KEY (asset, check_id, revision)
            );
            CREATE TABLE IF NOT EXISTS phishing (
                campaign TEXT PRIMARY KEY, owner TEXT NOT NULL, started TEXT NOT NULL,
                ended TEXT NOT NULL, source_at TEXT NOT NULL, delivered INTEGER NOT NULL,
                reported INTEGER NOT NULL, handled INTEGER NOT NULL,
                response_minutes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pci_evidence (
                asset TEXT NOT NULL, check_id TEXT NOT NULL, revision INTEGER NOT NULL,
                requirement TEXT NOT NULL, evidence_id TEXT NOT NULL, reviewer TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                PRIMARY KEY (asset, check_id, revision, requirement, evidence_id),
                FOREIGN KEY (asset, check_id, revision) REFERENCES history
            );
        """)
        yield db


def _record_history(db: sqlite3.Connection, asset: str, check: str, stamp: str) -> None:
    db.execute(
        """
        INSERT INTO history
        SELECT asset, check_id, revision, state, ?, baseline, owner, ticket, remediated_at, rescan
        FROM findings WHERE asset=? AND check_id=?
    """,
        (stamp, asset, check),
    )


def import_scan(db: sqlite3.Connection, raw: str, *, recorded_at: datetime) -> bool:
    """Persist a validated scan atomically; accept exact retries and reopen recurrences."""
    scan = parse_scan(raw)
    recorded = source_time(recorded_at.isoformat())
    if scan.timestamp > recorded:
        raise LabInputError("A scan timestamp cannot be in the future.")
    rows = [
        (
            scan.id,
            c.asset,
            c.check,
            c.outcome,
            c.cvss,
            *c.risk(),
            c.criticality,
            c.scope,
            c.exploit,
            c.exposed,
        )
        for c in scan.checks
    ]
    metadata = (scan.id, scan.scanner, scan.profile, scan.timestamp, scan.sha256)
    with db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT * FROM scans WHERE id=? OR sha256=?",
            (
                scan.id,
                scan.sha256,
            ),
        ).fetchall()
        if existing:
            stored = db.execute(
                "SELECT * FROM checks WHERE scan_id=? ORDER BY asset, check_id", (scan.id,)
            )
            if (
                len(existing) == 1
                and tuple(existing[0]) == metadata
                and [(*tuple(row)[:5], *tuple(row)[7:]) for row in stored]
                == [(*row[:5], *row[7:]) for row in rows]
            ):
                return False
            raise LabInputError("The scan ID or source fingerprint is already in use.")
        db.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?)", metadata)
        db.executemany("INSERT INTO checks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        for row in scan.checks:
            if row.outcome != "failed":
                continue
            existing_finding = db.execute(
                """
                SELECT f.*, s.scanned_at FROM findings f
                JOIN scans s ON s.id=coalesce(f.rescan, f.baseline)
                WHERE asset=? AND check_id=?
            """,
                (row.asset, row.check),
            ).fetchone()
            if existing_finding is None:
                db.execute(
                    """
                    INSERT INTO findings VALUES (?, ?, ?, 'Open', NULL, NULL, NULL, NULL, 1)
                """,
                    (row.asset, row.check, scan.id),
                )
            elif (
                existing_finding["state"] == "Verified"
                and scan.timestamp >= existing_finding["scanned_at"]
            ):
                db.execute(
                    """
                    UPDATE findings SET baseline=?, state='Open', owner=NULL, ticket=NULL,
                    remediated_at=NULL, rescan=NULL, revision=revision+1
                    WHERE asset=? AND check_id=?
                """,
                    (scan.id, row.asset, row.check),
                )
            else:
                continue
            _record_history(db, row.asset, row.check, recorded)
    return True


def advance(
    db: sqlite3.Connection,
    asset: str,
    check: str,
    revision: int,
    *,
    recorded_at: datetime,
    owner: str = "",
    ticket: str = "",
    remediated_at: str = "",
    rescan: str = "",
) -> None:
    """Advance the current revision; verification requires a comparable explicit pass."""
    recorded = source_time(recorded_at.isoformat())
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            """
            SELECT f.*, s.scanner, s.profile, s.scanned_at FROM findings f
            JOIN scans s ON f.baseline=s.id WHERE f.asset=? AND f.check_id=?
        """,
            (asset, check),
        ).fetchone()
        if row is None or row["revision"] != revision or row["state"] == "Verified":
            raise LabInputError("The finding changed. Reload it before recording an update.")
        state = row["state"]
        if state == "Open":
            db.execute(
                "UPDATE findings SET owner=?, ticket=? WHERE asset=? AND check_id=?",
                (lab_id(owner), lab_id(ticket), asset, check),
            )
        elif state == "Assigned":
            stamp = source_time(remediated_at)
            if not row["scanned_at"] <= stamp <= recorded:
                raise LabInputError("Remediation must be after discovery and at or before now.")
            db.execute(
                "UPDATE findings SET remediated_at=? WHERE asset=? AND check_id=?",
                (stamp, asset, check),
            )
        else:
            rescan = lab_id(rescan)
            candidate = db.execute(
                """
                SELECT s.scanned_at FROM scans s JOIN checks c ON c.scan_id=s.id
                WHERE s.id=? AND c.asset=? AND c.check_id=? AND s.scanner=? AND s.profile=?
                AND c.outcome='passed' AND s.scanned_at > ?
            """,
                (rescan, asset, check, row["scanner"], row["profile"], row["remediated_at"]),
            ).fetchone()
            if candidate is None:
                raise LabInputError(
                    "Use a later matching scanner and profile with an explicit pass."
                )
            newer_failure = db.execute(
                """
                SELECT 1 FROM scans s JOIN checks c ON c.scan_id=s.id
                WHERE c.asset=? AND c.check_id=? AND c.outcome='failed' AND s.scanned_at>=?
                LIMIT 1
            """,
                (asset, check, candidate["scanned_at"]),
            ).fetchone()
            if newer_failure is not None:
                raise LabInputError("A failure at or after that rescan blocks verification.")
            db.execute(
                "UPDATE findings SET rescan=? WHERE asset=? AND check_id=?", (rescan, asset, check)
            )
        db.execute(
            """
            UPDATE findings SET state=?, revision=revision+1 WHERE asset=? AND check_id=?
        """,
            (_STATES[_STATES.index(state) + 1], asset, check),
        )
        _record_history(db, asset, check, recorded)


def finding_rows(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return current findings and the provenance of their baseline and rescan."""
    return [
        dict(row)
        for row in db.execute("""
        SELECT f.*, c.cvss, c.score, c.rationale, c.scope, c.criticality, c.exploit, c.exposed,
               s.scanned_at, s.scanner, s.profile, s.sha256 AS baseline_sha256,
               r.scanned_at AS rescanned_at, r.sha256 AS rescan_sha256
        FROM findings f JOIN checks c ON c.scan_id=f.baseline AND c.asset=f.asset
            AND c.check_id=f.check_id
        JOIN scans s ON s.id=f.baseline LEFT JOIN scans r ON r.id=f.rescan
        ORDER BY c.score IS NULL DESC, c.score DESC, f.asset, f.check_id
    """)
    ]
