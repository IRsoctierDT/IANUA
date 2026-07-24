"""Security tests for compliance evidence recording (AGENTS.md §5).

Evidence must never leak secrets or environment values, must stay inside the
repository's data/ directory, must be created owner-only, and its audit chain
must detect tampering.
"""

import json
import stat
from pathlib import Path

import pytest
from compliance.controls import Category, CheckResult, Control, ControlStatus, Severity
from compliance.engine import run_controls
from compliance.evidence import export_bundle, load_recent, record_run, verify_chain

_CLOCK = "2026-07-24T00:00:00+00:00"


def _report(tmp_path: Path):  # type: ignore[no-untyped-def]
    control = Control(
        id="T-01",
        title="Test control",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        check=lambda root: CheckResult(ControlStatus.PASS, "ok"),
    )
    return run_controls(tmp_path, clock=lambda: _CLOCK, controls=(control,))


@pytest.mark.security
def test_evidence_contains_no_environment_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "SUPER-SECRET-CANARY-VALUE-123456"
    monkeypatch.setenv("API_TOKEN", canary)
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    evidence = (tmp_path / "data" / "compliance" / "evidence.jsonl").read_text(encoding="utf-8")
    audit = (tmp_path / "data" / "compliance" / "audit.log").read_text(encoding="utf-8")
    assert canary not in evidence
    assert canary not in audit


@pytest.mark.security
def test_evidence_files_are_owner_only(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    for name in ("evidence.jsonl", "audit.log"):
        mode = stat.S_IMODE((tmp_path / "data" / "compliance" / name).stat().st_mode)
        assert mode == 0o600, f"{name} mode is {oct(mode)}"


@pytest.mark.security
def test_export_bundle_refuses_path_escape(tmp_path: Path) -> None:
    report = _report(tmp_path)
    with pytest.raises(ValueError):
        export_bundle(report, root=tmp_path, dest=tmp_path / ".." / "outside.json")


@pytest.mark.security
def test_chain_detects_tampered_evidence_history(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    assert verify_chain(tmp_path).intact

    audit_path = tmp_path / "data" / "compliance" / "audit.log"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["decision"] = "pass-definitely"  # rewrite history
    lines[0] = json.dumps(entry)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify_chain(tmp_path).intact


@pytest.mark.security
def test_malformed_evidence_lines_are_skipped_not_trusted(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    path = tmp_path / "data" / "compliance" / "evidence.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json}\n")
        fh.write(json.dumps({"unexpected": "shape"}) + "\n")
    records = load_recent(tmp_path)
    assert len(records) == 1
    assert records[0].control_id == "T-01"


@pytest.mark.security
def test_export_bundle_content_is_declared_and_bounded(tmp_path: Path) -> None:
    report = _report(tmp_path)
    dest = tmp_path / "reports" / "bundle.json"
    written = export_bundle(report, root=tmp_path, dest=dest)
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["disclaimer"].startswith("Automated posture evidence")
    assert {c["id"] for c in payload["controls"]} == {"T-01"}
