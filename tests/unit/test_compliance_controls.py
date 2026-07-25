"""Unit tests for compliance/controls.py — each check against fixture repos."""

from pathlib import Path

import pytest
from compliance.controls import (
    ControlStatus,
    check_approval_gates,
    check_ci_gates,
    check_dependency_lock,
    check_governance_docs,
    check_lab_data_isolated,
    check_policy_default_deny,
    check_secret_hygiene,
    check_security_test_suite,
    registry,
)


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _policy(root: Path, **overrides: str) -> None:
    policy = {
        "boundary_crossing": "deny",
        "unknown": "require_approval",
        "destructive": "require_approval",
        "external_network": "require_approval",
        "deployment": "require_approval",
        "secret_handling": "require_approval",
    }
    policy.update(overrides)
    _write(
        root,
        "agents/policies/policy.json",
        __import__("json").dumps({"version": 1, "policy": policy}),
    )


def test_registry_ids_unique_and_ordered() -> None:
    ids = [c.id for c in registry()]
    assert len(ids) == len(set(ids))
    assert all(c.automated or c.attestation_hint for c in registry())


def test_policy_default_deny_passes_on_hardened_policy(tmp_path: Path) -> None:
    _policy(tmp_path)
    assert check_policy_default_deny(tmp_path).status is ControlStatus.PASS


def test_policy_default_deny_fails_when_weakened(tmp_path: Path) -> None:
    _policy(tmp_path, boundary_crossing="allow")
    result = check_policy_default_deny(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert "boundary_crossing" in result.detail


def test_policy_missing_fails_closed(tmp_path: Path) -> None:
    assert check_policy_default_deny(tmp_path).status is ControlStatus.FAIL


def test_approval_gates_fail_when_class_ungated(tmp_path: Path) -> None:
    _policy(tmp_path, destructive="allow")
    result = check_approval_gates(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert "destructive" in result.detail


def test_secret_hygiene_requires_gitignored_env(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "data/\n")
    _write(tmp_path, ".env.example", "API_KEY=\n")
    result = check_secret_hygiene(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert ".env is not gitignored" in result.detail


def test_secret_hygiene_flags_value_bearing_example(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", ".env\n")
    # Zero-entropy placeholder, assembled so secret scanners don't flag the
    # fixture itself — the check only cares about length, not entropy.
    _write(tmp_path, ".env.example", "API_KEY=" + "x" * 30 + "\n")
    result = check_secret_hygiene(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert "API_KEY" in result.detail


def test_secret_hygiene_passes_on_keys_only(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", ".env\n")
    _write(tmp_path, ".env.example", "API_KEY=\nLLM_MODEL=qwen3.5:9b\n")
    assert check_secret_hygiene(tmp_path).status is ControlStatus.PASS


def test_lab_data_isolated(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "data/\n")
    assert check_lab_data_isolated(tmp_path).status is ControlStatus.PASS
    _write(tmp_path, ".gitignore", "other/\n")
    assert check_lab_data_isolated(tmp_path).status is ControlStatus.FAIL


def test_dependency_lock(tmp_path: Path) -> None:
    assert check_dependency_lock(tmp_path).status is ControlStatus.FAIL
    _write(tmp_path, "uv.lock", "version = 1\n")
    assert check_dependency_lock(tmp_path).status is ControlStatus.PASS


def test_ci_gates_requires_all_stages(tmp_path: Path) -> None:
    _write(tmp_path, ".github/workflows/ci.yml", "run: ruff check\nrun: pytest\n")
    result = check_ci_gates(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert "mypy" in result.detail and "bandit" in result.detail


def test_security_test_suite_threshold(tmp_path: Path) -> None:
    for i in range(4):
        _write(tmp_path, f"tests/security/test_{i}.py", "")
    assert check_security_test_suite(tmp_path).status is ControlStatus.FAIL
    _write(tmp_path, "tests/security/test_more.py", "")
    assert check_security_test_suite(tmp_path).status is ControlStatus.PASS


def test_governance_docs_reports_missing(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md", "x")
    result = check_governance_docs(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert "DESIGN.md" in result.detail


@pytest.mark.security
def test_live_repository_passes_every_automated_control() -> None:
    """The repo must comply with its own posture (self-scan, T-lite dogfood)."""
    root = Path(__file__).resolve().parents[2]
    failing = [
        (c.id, result.detail)
        for c in registry()
        if c.check is not None and (result := c.check(root)).status is not ControlStatus.PASS
    ]
    assert failing == []
