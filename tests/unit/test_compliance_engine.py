"""Unit tests for compliance/engine.py — evaluation, fail-closed, rollups."""

from pathlib import Path

import pytest
from compliance.controls import (
    Category,
    CheckResult,
    Control,
    ControlStatus,
    Severity,
)
from compliance.engine import run_controls
from compliance.frameworks import Framework, FrameworkRef, FrameworkRollup, rollup

_CLOCK = "2026-07-24T00:00:00+00:00"


def _control(
    id_: str,
    check: object,
    refs: frozenset[FrameworkRef] = frozenset(),
) -> Control:
    return Control(
        id=id_,
        title=f"Control {id_}",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        framework_refs=refs,
        check=check,  # type: ignore[arg-type]
        attestation_hint="attest" if check is None else "",
    )


def test_run_controls_deterministic_with_injected_clock(tmp_path: Path) -> None:
    controls = (_control("A-01", lambda root: CheckResult(ControlStatus.PASS, "ok")),)
    a = run_controls(tmp_path, clock=lambda: _CLOCK, controls=controls)
    b = run_controls(tmp_path, clock=lambda: _CLOCK, controls=controls)
    assert a == b
    assert a.generated_at == _CLOCK


def test_crashing_check_becomes_error_not_pass(tmp_path: Path) -> None:
    def boom(root: Path) -> CheckResult:
        raise RuntimeError("secret detail that must not leak")

    report = run_controls(tmp_path, clock=lambda: _CLOCK, controls=(_control("A-01", boom),))
    result = report.results[0]
    assert result.status is ControlStatus.ERROR
    assert "secret detail" not in result.detail  # only the exception class leaks
    assert report.score == 0  # ERROR counts as non-passing (fail closed)


def test_manual_controls_excluded_from_score_but_counted(tmp_path: Path) -> None:
    controls = (
        _control("A-01", lambda root: CheckResult(ControlStatus.PASS, "ok")),
        _control("M-01", None),
    )
    report = run_controls(tmp_path, clock=lambda: _CLOCK, controls=controls)
    assert report.score == 100  # manual does not dilute the automated score
    assert len(report.manual) == 1
    assert report.manual[0].status is ControlStatus.MANUAL


def test_missing_root_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_controls(tmp_path / "nope", clock=lambda: _CLOCK)


def test_framework_rollup_counts_controls_once_per_framework() -> None:
    refs = frozenset(
        {
            FrameworkRef(Framework.NIST_CSF, "GV.PO-01"),
            FrameworkRef(Framework.NIST_CSF, "PR.AA-05"),  # same framework twice
            FrameworkRef(Framework.SOC_2, "CC5.2"),
        }
    )
    rollups = rollup([(refs, True), (refs, False)])
    by_fw = {r.framework: r for r in rollups}
    assert by_fw[Framework.NIST_CSF] == FrameworkRollup(Framework.NIST_CSF, 1, 2)
    assert by_fw[Framework.SOC_2] == FrameworkRollup(Framework.SOC_2, 1, 2)
    assert Framework.ISO_27001 not in by_fw  # unmapped frameworks are omitted


def test_manual_controls_hold_back_framework_coverage(tmp_path: Path) -> None:
    refs = frozenset({FrameworkRef(Framework.SOC_2, "CC8.1")})
    controls = (
        _control("A-01", lambda root: CheckResult(ControlStatus.PASS, "ok"), refs),
        _control("M-01", None, refs),
    )
    report = run_controls(tmp_path, clock=lambda: _CLOCK, controls=controls)
    (ru,) = report.framework_rollups()
    assert (ru.passing, ru.total, ru.percent) == (1, 2, 50)
