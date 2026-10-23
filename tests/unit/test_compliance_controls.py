# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for compliance/controls.py — each check against fixture repos."""

from pathlib import Path

import pytest

from compliance.controls import (
    ControlStatus,
    check_approval_gates,
    check_ci_gates,
    check_dashboard_binds_loopback,
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


# --------------------------------------------------------------------------
# CFG-02 — the dashboard binds loopback only
# --------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_dashboard_loopback_passes_on_loopback_addresses(tmp_path: Path, address: str) -> None:
    _write(tmp_path, ".streamlit/config.toml", f'[server]\naddress = "{address}"\n')
    assert check_dashboard_binds_loopback(tmp_path).status is ControlStatus.PASS


@pytest.mark.unit
# Suppression justified, as in correlation/entities.py: these literals are
# addresses being asserted as REFUSED, not addresses being bound. The rule
# cannot tell the difference.
@pytest.mark.parametrize(
    "address",
    ["0.0.0.0", "10.0.0.5", "192.168.1.20", "::"],  # noqa: S104  # nosec B104
)
def test_dashboard_loopback_fails_on_a_reachable_address(tmp_path: Path, address: str) -> None:
    """The dashboard authenticates nobody and renders stored event content.

    A reachable bind publishes hostnames, accounts, addresses and raw log
    messages to whoever can reach the port, so this is the failure the control
    exists for.
    """
    _write(tmp_path, ".streamlit/config.toml", f'[server]\naddress = "{address}"\n')
    result = check_dashboard_binds_loopback(tmp_path)
    assert result.status is ControlStatus.FAIL
    assert address in result.detail


@pytest.mark.unit
def test_dashboard_loopback_fails_when_the_address_is_unset(tmp_path: Path) -> None:
    """Unset is the state this control was added for.

    The address was absent until it was pinned, which meant it came from
    whatever the installed Streamlit defaulted to — not a property this
    repository controlled — while the production plan described loopback-only
    binding as an invariant stage 7 would have to cross. Unset is a FAIL, not a
    pass-by-omission.
    """
    _write(tmp_path, ".streamlit/config.toml", "[server]\nmaxUploadSize = 10\n")
    assert check_dashboard_binds_loopback(tmp_path).status is ControlStatus.FAIL


@pytest.mark.unit
def test_dashboard_loopback_fails_closed_without_a_config(tmp_path: Path) -> None:
    assert check_dashboard_binds_loopback(tmp_path).status is ControlStatus.FAIL


@pytest.mark.unit
def test_the_repository_itself_binds_loopback() -> None:
    """Against the committed config, not a fixture — the property that ships."""
    root = Path(__file__).resolve().parents[2]
    result = check_dashboard_binds_loopback(root)
    assert result.status is ControlStatus.PASS, result.detail
