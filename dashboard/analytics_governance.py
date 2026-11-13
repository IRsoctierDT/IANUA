# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Deterministic governance, validation and contextual risk for dashboard snapshots.

No I/O, credentials, or source mutation. Never treat missing evidence as passing.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

REQUIRED: dict[str, frozenset[str]] = {
    "phishing": frozenset({"department", "month", "clicks", "source_timestamp", "data_owner",
                           "reporting_period_start", "reporting_period_end", "source_system"}),
    "vulnerabilities": frozenset({"asset_id", "cvss", "exploitability", "exposure",
                                  "asset_criticality", "pci_scope", "status",
                                  "source_timestamp", "data_owner", "reporting_period_start",
                                  "reporting_period_end", "source_system"}),
    "pci": frozenset({"requirement", "evidence_id", "test_procedure", "owner", "ticket",
                       "status", "source_timestamp", "data_owner",
                       "reporting_period_start", "reporting_period_end", "source_system"}),
}
VALID_PCI = frozenset({"not_assessed", "in_progress", "tested_pass", "tested_fail"})
VALID_VULN = frozenset({"open", "in_progress", "remediated", "accepted"})


def _utc(value: str) -> datetime:
    """Parse timezone-aware ISO-8601 timestamps, refusing ambiguous local times."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def risk_score(row: dict[str, str]) -> float:
    """Calculate a 0-100 triage heuristic, separate from the official CVSS score.

    Exploitability and criticality are integer scales 1-4; exposure 1-3.
    The PCI-scope flag is exactly true/false. No missing input defaults to zero.
    """
    cvss = float(row["cvss"])
    exploit = int(row["exploitability"])
    exposure = int(row["exposure"])
    criticality = int(row["asset_criticality"])
    scope = row["pci_scope"].strip().lower()
    if not 0 <= cvss <= 10 or exploit not in range(1, 5):
        raise ValueError("invalid CVSS or exploitability")
    if exposure not in range(1, 4) or criticality not in range(1, 5):
        raise ValueError("invalid exposure or asset criticality")
    if scope not in {"true", "false"}:
        raise ValueError("PCI scope must be true or false")
    return round(
        35 * cvss / 10 + 25 * exploit / 4 + 15 * exposure / 3
        + 15 * criticality / 4 + (10 if scope == "true" else 0), 1
    )


def quality_report(dataset: str, rows: list[dict[str, str]], *, now: datetime,
                   freshness_hours: float = 24) -> list[str]:
    """Return validation errors; an empty result means checks passed, not compliance."""
    if dataset not in REQUIRED:
        raise ValueError("unknown dataset")
    if not rows:
        return ["no rows: source unavailable or empty"]
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    problems: list[str] = []
    seen: set[tuple[str, ...]] = set()
    identity = {"phishing": ("department", "month"),
                "vulnerabilities": ("asset_id", "cvss"),
                "pci": ("requirement", "evidence_id")}[dataset]
    for index, row in enumerate(rows, 1):
        missing = sorted(REQUIRED[dataset] - row.keys())
        if missing:
            problems.append(f"row {index}: missing columns {', '.join(missing)}")
            continue
        if any(not row[key].strip() for key in REQUIRED[dataset]):
            problems.append(f"row {index}: empty required field")
            continue
        key = tuple(row[field] for field in identity)
        if key in seen:
            problems.append(f"row {index}: duplicate logical key")
        seen.add(key)
        try:
            stamp = _utc(row["source_timestamp"])
            if stamp > now.astimezone(timezone.utc):
                problems.append(f"row {index}: source timestamp in future")
            elif (now.astimezone(timezone.utc) - stamp).total_seconds() > freshness_hours * 3600:
                problems.append(f"row {index}: stale source")
            start = datetime.fromisoformat(row["reporting_period_start"]).date()
            end = datetime.fromisoformat(row["reporting_period_end"]).date()
            if start > end:
                problems.append(f"row {index}: inverted reporting period")
            if dataset == "phishing":
                clicks = int(row["clicks"])
                if clicks < 0 or str(clicks) != row["clicks"].strip():
                    raise ValueError("invalid click count")
            elif dataset == "vulnerabilities":
                risk_score(row)
                if row["status"] not in VALID_VULN:
                    raise ValueError("invalid vulnerability status")
            elif dataset == "pci":
                if row["status"] not in VALID_PCI:
                    raise ValueError("invalid PCI evidence status")
                if not row["requirement"].startswith(tuple(f"{n}." for n in range(1, 13))):
                    if row["requirement"] not in {str(n) for n in range(1, 13)}:
                        raise ValueError("invalid requirement identifier")
        except (ValueError, TypeError, OverflowError) as exc:
            problems.append(f"row {index}: {exc}")
    return problems


METRIC_DEFINITIONS: dict[str, str] = {
    "soc_events": "Count of bounded recent ingested events; not an incident count.",
    "phishing_clicks": "Sum of simulation clicks; not a click rate without a delivered-message denominator.",
    "open_vulnerabilities": "Number of validated findings whose status is open or in_progress.",
    "contextual_risk": "35% CVSS + 25% exploitability + 15% exposure + 15% asset criticality + 10% PCI scope.",
    "pci_evidence": "Number of evidence rows per testing status; not a PCI DSS compliance percentage.",
}
