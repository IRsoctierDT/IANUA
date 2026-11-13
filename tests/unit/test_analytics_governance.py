# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure validation and RBAC regression coverage."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dashboard.analytics_access import authorized
from dashboard.analytics_governance import quality_report, risk_score

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)
PROVENANCE = {
    "source_timestamp": "2026-11-13T00:00:00Z",
    "data_owner": "security-team",
    "source_system": "authorized-lab",
    "reporting_period_start": "2026-11-01",
    "reporting_period_end": "2026-11-13",
}


def test_risk_score_and_pci_scope() -> None:
    """PCI scope raises priority but cannot replace CVSS or contextual factors."""
    base = {"cvss": "8.0", "exploitability": "3", "exposure": "2",
            "asset_criticality": "4", "pci_scope": "false"}
    assert risk_score({**base, "pci_scope": "true"}) - risk_score(base) == 10


@pytest.mark.parametrize("key,value", [
    ("cvss", "11"), ("exposure", "4"), ("exploitability", "0"),
    ("asset_criticality", "5"), ("pci_scope", "unknown"),
])
def test_invalid_risk_input(key: str, value: str) -> None:
    """No invalid contextual factor can be silently coerced into a priority."""
    row = {"cvss": "7", "exploitability": "2", "exposure": "2",
           "asset_criticality": "3", "pci_scope": "false"}
    with pytest.raises(ValueError):
        risk_score({**row, key: value})


def test_phishing_quality_and_staleness() -> None:
    """Fresh valid counts pass; stale sources are visible failures."""
    row = {**PROVENANCE, "department": "IT", "month": "2026-11", "clicks": "4"}
    assert quality_report("phishing", [row], now=NOW) == []
    stale = {**row, "source_timestamp": "2026-10-01T00:00:00Z"}
    assert any("stale" in issue for issue in quality_report("phishing", [stale], now=NOW))


def test_pci_evidence_validation() -> None:
    """Evidence must carry requirement, owner, test procedure and ticket."""
    row = {**PROVENANCE, "requirement": "8.3.1", "evidence_id": "EV-8-01",
           "test_procedure": "Examine identity configuration", "owner": "IAM",
           "ticket": "SEC-101", "status": "in_progress"}
    assert quality_report("pci", [row], now=NOW) == []
    assert quality_report("pci", [{**row, "status": "compliant"}], now=NOW)


def test_nonpublic_fails_closed() -> None:
    """Anonymous, unknown and insufficiently privileged users cannot read."""
    assert authorized(classification="synthetic", identity=None, assignments={})
    assert not authorized(classification="internal", identity=None, assignments={})
    assert not authorized(classification="internal", identity="unknown@example.test",
                          assignments={})
    assert authorized(classification="internal", identity="a@example.test",
                      assignments={"a@example.test": "viewer"})
    assert not authorized(classification="internal", identity="a@example.test",
                          assignments={"a@example.test": "viewer"}, permission="export")
    assert not authorized(classification="unknown", identity="a@example.test",
                          assignments={"a@example.test": "admin"})
