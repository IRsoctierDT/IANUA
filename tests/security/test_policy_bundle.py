"""Security tests for the declarative policy bundle loader (fail-closed)."""

from pathlib import Path

import pytest
from agents.policies import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle


@pytest.mark.security
def test_default_bundle_loads_and_matches_defaults() -> None:
    engine = load_bundle(DEFAULT_BUNDLE_PATH)
    assert engine.decide(action_class="read_only").decision == "allow"
    assert engine.decide(action_class="boundary_crossing").decision == "deny"
    assert engine.decide(action_class="destructive").decision == "require_approval"


@pytest.mark.security
def test_policy_override_is_applied(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"policy": {"dependency": "deny"}}', encoding="utf-8")
    engine = load_bundle(bundle)
    assert engine.decide(action_class="dependency").decision == "deny"


@pytest.mark.security
def test_allow_and_deny_lists_are_applied(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text(
        '{"allow": ["deploy to staging"], "deny": ["analyze the log"]}', encoding="utf-8"
    )
    engine = load_bundle(bundle)
    assert engine.evaluate("Deploy to staging").decision == "allow"
    assert engine.evaluate("Analyze the log").decision == "deny"


@pytest.mark.security
def test_bundle_cannot_override_prohibition(tmp_path: Path) -> None:
    """A bundle allow-list must never downgrade a §5 prohibition."""
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"allow": ["exploit the target host"]}', encoding="utf-8")
    engine = load_bundle(bundle)
    assert engine.evaluate("Exploit the target host").decision == "deny"


@pytest.mark.security
def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PolicyBundleError):
        load_bundle(tmp_path / "does-not-exist.json")


@pytest.mark.security
def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)


@pytest.mark.security
def test_non_object_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)


@pytest.mark.security
def test_unknown_action_class_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"policy": {"launch_missiles": "allow"}}', encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)


@pytest.mark.security
def test_invalid_decision_value_fails_closed(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"policy": {"read_only": "maybe"}}', encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)


@pytest.mark.security
def test_allow_must_be_list_of_strings(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"allow": "deploy"}', encoding="utf-8")
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)
