# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from dashboard.lab_soc import soc_snapshot
from ingest.schema import NormalizedEvent
from store import EventStore, Query
from store.lab_pci import evidence_rows, link_evidence, weekly_scorecard
from store.lab_phishing import campaign_metrics, record_campaign
from store.lab_vulnerabilities import (
    LabInputError,
    advance,
    finding_rows,
    import_scan,
    lab_database,
    parse_scan,
)

_RECORDED = datetime(2025, 1, 10, 12, tzinfo=UTC)


def _scan(alias: str, day: int, outcome: str, **overrides: object) -> str:
    check = {
        "asset": "lab-web",
        "check": "test-01",
        "outcome": outcome,
        "cvss": 7.5,
        "exploit": True,
        "exposed": True,
        "criticality": "high",
        "scope": "cde",
    } | overrides
    return json.dumps(
        {
            "version": 1,
            "scan_id": alias,
            "scanner": "lab-scanner",
            "profile": "authenticated",
            "timestamp": f"2025-01-{day:02d}T12:00:00Z",
            "sha256": hashlib.sha256(alias.encode()).hexdigest(),
            "checks": [check],
        }
    )


def test_scan_workflow_rescan_provenance_and_recurrence(tmp_path: Path) -> None:
    asset, check = "lab-web", "test-01"
    raw = _scan("baseline", 1, "failed")
    with lab_database(tmp_path) as db:
        assert import_scan(db, recorded_at=_RECORDED, raw=raw)
        assert not import_scan(db, recorded_at=_RECORDED, raw=raw)
        assert finding_rows(db)[0]["score"] == 100
        with pytest.raises(LabInputError, match="already in use"):
            import_scan(db, recorded_at=_RECORDED, raw=_scan("baseline", 1, "failed", cvss=4))
        advance(db, asset, check, 1, recorded_at=_RECORDED, owner="lab-owner", ticket="LAB-01")
        with pytest.raises(LabInputError, match="changed"):
            advance(db, asset, check, 1, recorded_at=_RECORDED, owner="other", ticket="LAB-02")
        advance(db, asset, check, 2, recorded_at=_RECORDED, remediated_at="2025-01-02T12:00:00Z")
    with lab_database(tmp_path) as db:
        for day, outcome, changed in (
            (2, "passed", {}),
            (3, "incomplete", {}),
            (4, "passed", {"asset": "other"}),
        ):
            scan_id = f"rescan-{day}"
            import_scan(db, recorded_at=_RECORDED, raw=_scan(scan_id, day, outcome, **changed))
            with pytest.raises(LabInputError, match="explicit pass"):
                advance(db, asset, check, 3, recorded_at=_RECORDED, rescan=scan_id)
        wrong_profile = json.loads(_scan("wrong-profile", 5, "passed"))
        wrong_profile["profile"] = "unauthenticated"
        import_scan(db, recorded_at=_RECORDED, raw=json.dumps(wrong_profile))
        with pytest.raises(LabInputError, match="explicit pass"):
            advance(db, asset, check, 3, recorded_at=_RECORDED, rescan="wrong-profile")
        import_scan(db, recorded_at=_RECORDED, raw=_scan("old-pass", 6, "passed"))
        import_scan(db, recorded_at=_RECORDED, raw=_scan("new-failure", 7, "failed"))
        with pytest.raises(LabInputError, match="blocks verification"):
            advance(db, asset, check, 3, recorded_at=_RECORDED, rescan="old-pass")
        import_scan(db, recorded_at=_RECORDED, raw=_scan("latest-pass", 8, "passed"))
        advance(db, asset, check, 3, recorded_at=_RECORDED, rescan="latest-pass")
        assert finding_rows(db)[0]["state"] == "Verified"
        for _ in range(2):
            link_evidence(
                db,
                asset=asset,
                check=check,
                revision=4,
                requirement="11.3.1",
                evidence_id="review-01",
                reviewer="lab-reviewer",
                reviewed_at=_RECORDED,
            )
        assert len(evidence_rows(db)) == 1
        assert evidence_rows(db)[0]["rescan"] == "latest-pass"
        import_scan(db, recorded_at=_RECORDED, raw=_scan("recurrence", 9, "failed"))
        assert finding_rows(db)[0]["state"] == "Open"
        assert evidence_rows(db)[0]["ticket"] == "LAB-01"
        with pytest.raises(LabInputError, match="current verified"):
            link_evidence(
                db,
                asset=asset,
                check=check,
                revision=4,
                requirement="11.3.1",
                evidence_id="review-02",
                reviewer="lab-reviewer",
                reviewed_at=_RECORDED,
            )
        today = _RECORDED.date()
        scorecard = weekly_scorecard(db, today - timedelta(days=today.weekday()))
        assert scorecard == {
            "Findings opened": 1,
            "Owners assigned": 1,
            "Fixes recorded": 1,
            "Rescans verified": 1,
            "Evidence links reviewed": 1,
        }


@pytest.mark.parametrize(
    "override",
    [{"cvss": True}, {"cvss": float("nan")}, {"scope": []}, {"asset": "../other"}, {"exploit": 1}],
)
def test_malformed_scan_checks(override: dict[str, object]) -> None:
    with pytest.raises(LabInputError):
        parse_scan(_scan("invalid", 1, "failed", **override))


def test_duplicate_fields_and_unknown_risk() -> None:
    with pytest.raises(LabInputError, match="duplicate field"):
        parse_scan('{"version":1,"version":1}')
    scan = parse_scan(_scan("unknown", 1, "failed", cvss=None))
    assert scan.checks[0].risk()[0] is None
    scan = parse_scan(_scan("provisional", 1, "failed", exploit=None, exposed=False))
    assert scan.checks[0].risk()[0] == 90
    assert "provisional" in scan.checks[0].risk()[1]


def test_phishing_aggregates_weighted_and_validated(tmp_path: Path) -> None:
    start, end = date(2025, 1, 1), date(2025, 1, 7)
    with lab_database(tmp_path) as db:
        with pytest.raises(LabInputError):
            record_campaign(
                db,
                campaign="bad",
                owner="lab",
                start=start,
                end=end,
                source_at="2025-01-08T00:00:00Z",
                delivered=1,
                reported=2,
                handled=0,
                response_minutes=0,
            )
        assert campaign_metrics(db, start, end) == ([], None, None)
        for alias, delivered, reported, handled, minutes in (
            ("one", 10, 5, 1, 6),
            ("two", 90, 15, 3, 14),
            ("one", 10, 5, 1, 6),
        ):
            record_campaign(
                db,
                campaign=alias,
                owner="lab",
                start=start,
                end=end,
                source_at="2025-01-08T00:00:00Z",
                delivered=delivered,
                reported=reported,
                handled=handled,
                response_minutes=minutes,
            )
        rows, rate, average = campaign_metrics(db, start, end)
        assert len(rows) == 2
        assert rate == 0.2
        assert average == 5
        assert campaign_metrics(db, date(2025, 1, 2), end) == ([], None, None)


def test_soc_reads_existing_events_and_keeps_source_time_distinct(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        soc_snapshot(tmp_path, 10, 20)
    assert not (tmp_path / "data").exists()
    with EventStore.open(tmp_path) as store:
        store.append(
            NormalizedEvent("network", "lab", None, 12, "lab", None, "structured"), ingested_at=22
        )
        store.append(
            NormalizedEvent("network", "lab", None, None, "lab", None, "structured"), ingested_at=30
        )
    result = soc_snapshot(tmp_path, 10, 20)
    assert result.counts == {"network / lab": 1}
    assert result.last_ingested == 30
    with EventStore.open_read_only(tmp_path) as read_only:
        assert len(read_only.query(Query())) == 2
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            read_only.append(
                NormalizedEvent("network", "lab", None, 13, "lab", None, "structured"),
                ingested_at=31,
            )
