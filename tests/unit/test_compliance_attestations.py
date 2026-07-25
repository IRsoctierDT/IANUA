"""Unit tests for compliance/attestations.py and ATTESTED engine behavior."""

import json
from pathlib import Path

import pytest
from compliance.attestations import Attestation, AttestationError, load, record
from compliance.controls import ControlStatus, registry
from compliance.engine import run_controls

_CLOCK = "2026-07-24T00:00:00+00:00"


def _entry(**overrides: str) -> dict[str, str]:
    entry = {
        "control_id": "MAN-01",
        "attested_by": "Repository maintainer",
        "date": "2026-07-01",
        "expires": "2026-09-29",
        "note": "Verified branch protection in GitHub settings.",
    }
    entry.update(overrides)
    return entry


def _store(tmp_path: Path, *entries: dict[str, str]) -> Path:
    path = tmp_path / "attestations.json"
    path.write_text(json.dumps({"version": 1, "attestations": list(entries)}), encoding="utf-8")
    return path


def test_load_valid_store(tmp_path: Path) -> None:
    atts = load(_store(tmp_path, _entry()))
    assert atts["MAN-01"].attested_by == "Repository maintainer"


def test_absent_store_means_no_attestations(tmp_path: Path) -> None:
    assert load(tmp_path / "missing.json") == {}


@pytest.mark.parametrize(
    "mutation",
    [
        {"date": "July 1"},
        {"expires": "2026-06-30"},  # precedes date
        {"attested_by": "  "},
        {"extra": "field"},
    ],
)
def test_malformed_entries_fail_closed(tmp_path: Path, mutation: dict[str, str]) -> None:
    with pytest.raises(AttestationError):
        load(_store(tmp_path, _entry(**mutation)))


def test_duplicate_control_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(AttestationError):
        load(_store(tmp_path, _entry(), _entry()))


def test_invalid_json_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "attestations.json"
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(AttestationError):
        load(path)


def test_validity_window_is_inclusive() -> None:
    att = Attestation(**_entry())
    assert att.valid_on("2026-07-01")
    assert att.valid_on("2026-09-29")
    assert not att.valid_on("2026-09-30")
    assert not att.valid_on("2026-06-30")


def test_engine_marks_current_attestation_attested(tmp_path: Path) -> None:
    atts = {"MAN-01": Attestation(**_entry())}
    report = run_controls(tmp_path, clock=lambda: _CLOCK, attestations=atts)
    by_id = {r.control.id: r for r in report.results}
    assert by_id["MAN-01"].status is ControlStatus.ATTESTED
    assert by_id["MAN-02"].status is ControlStatus.MANUAL  # unattested stays manual


def test_engine_reverts_expired_attestation_to_manual(tmp_path: Path) -> None:
    atts = {"MAN-01": Attestation(**_entry(date="2026-01-01", expires="2026-02-01"))}
    report = run_controls(tmp_path, clock=lambda: _CLOCK, attestations=atts)
    result = next(r for r in report.results if r.control.id == "MAN-01")
    assert result.status is ControlStatus.MANUAL
    assert "expired" in result.detail


def test_attested_counts_in_rollups_not_in_automated_score(tmp_path: Path) -> None:
    atts = {c.id: Attestation(**_entry(control_id=c.id)) for c in registry() if not c.automated}
    unattested = run_controls(tmp_path, clock=lambda: _CLOCK)
    attested = run_controls(tmp_path, clock=lambda: _CLOCK, attestations=atts)
    assert attested.score == unattested.score  # score stays automated-only
    for before, after in zip(
        unattested.framework_rollups(), attested.framework_rollups(), strict=True
    ):
        assert after.passing == before.passing + 2  # both manual controls now count


def test_record_round_trips_and_sorts(tmp_path: Path) -> None:
    path = tmp_path / "attestations.json"
    record(path, **_entry(control_id="MAN-02"))
    record(path, **_entry())
    loaded = load(path)
    assert set(loaded) == {"MAN-01", "MAN-02"}
    raw = json.loads(path.read_text(encoding="utf-8"))
    ids = [a["control_id"] for a in raw["attestations"]]
    assert ids == sorted(ids)  # deterministic order for clean diffs


def test_record_refuses_automated_or_unknown_controls(tmp_path: Path) -> None:
    path = tmp_path / "attestations.json"
    with pytest.raises(AttestationError):
        record(path, **_entry(control_id="POL-01"))
    with pytest.raises(AttestationError):
        record(path, **_entry(control_id="NOPE-99"))
