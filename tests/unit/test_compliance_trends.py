"""Unit tests for compliance/trends.py — score history aggregation."""

from pathlib import Path

from compliance.controls import Category, CheckResult, Control, ControlStatus, Severity
from compliance.engine import run_controls
from compliance.evidence import record_run
from compliance.trends import TrendPoint, score_history


def _control(id_: str, passing: bool) -> Control:
    status = ControlStatus.PASS if passing else ControlStatus.FAIL

    def check(root: Path) -> CheckResult:
        return CheckResult(status, "detail")

    return Control(
        id=id_,
        title=f"Control {id_}",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        check=check,
    )


def _run(tmp_path: Path, stamp: str, *passing_flags: bool) -> None:
    controls = tuple(_control(f"C-{i:02}", flag) for i, flag in enumerate(passing_flags))
    report = run_controls(tmp_path, clock=lambda: stamp, controls=controls)
    record_run(report, root=tmp_path, clock=lambda: stamp)


def test_history_groups_by_run_and_orders_chronologically(tmp_path: Path) -> None:
    _run(tmp_path, "2026-07-22T00:00:00+00:00", True, False)
    _run(tmp_path, "2026-07-23T00:00:00+00:00", True, True)
    history = score_history(tmp_path)
    assert history == (
        TrendPoint("2026-07-22T00:00:00+00:00", 1, 2),
        TrendPoint("2026-07-23T00:00:00+00:00", 2, 2),
    )
    assert [p.score for p in history] == [50, 100]


def test_manual_and_attested_records_do_not_skew_score(tmp_path: Path) -> None:
    manual = Control(
        id="M-01",
        title="Manual",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        attestation_hint="attest",
    )
    report = run_controls(
        tmp_path,
        clock=lambda: "2026-07-24T00:00:00+00:00",
        controls=(_control("C-00", True), manual),
    )
    record_run(report, root=tmp_path, clock=lambda: "2026-07-24T00:00:00+00:00")
    (point,) = score_history(tmp_path)
    assert point.automated_total == 1
    assert point.score == 100


def test_empty_history(tmp_path: Path) -> None:
    assert score_history(tmp_path) == ()
