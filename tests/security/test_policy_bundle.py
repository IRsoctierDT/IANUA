# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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


# ------------------------------------------------- the file must mean what it reads
@pytest.mark.security
def test_duplicate_allow_key_is_refused_not_last_wins(tmp_path: Path) -> None:
    """``json.loads`` keeps the last duplicate silently. Measured before the hook:
    this file *enforced* the grant while its first ``allow`` — the one a reviewer
    reads — is empty. The bundle is the standing-grant mechanism, so a file that
    reads one way and enforces another defeats the review that is the control."""
    bundle = tmp_path / "policy.json"
    bundle.write_text(
        '{"version": 1, "allow": [], "allow": ["retain_events:apply"]}', encoding="utf-8"
    )
    with pytest.raises(PolicyBundleError, match="duplicate key 'allow'"):
        load_bundle(bundle)


@pytest.mark.security
def test_duplicate_deny_key_is_refused(tmp_path: Path) -> None:
    """The mirror case: a visible deny-list silently replaced by an empty one."""
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"deny": ["analyze the log"], "deny": []}', encoding="utf-8")
    with pytest.raises(PolicyBundleError, match="duplicate key 'deny'"):
        load_bundle(bundle)


@pytest.mark.security
@pytest.mark.parametrize("key", ["deni", "polcy", "alow", "extra"])
def test_unknown_top_level_key_is_refused(tmp_path: Path, key: str) -> None:
    """Measured before the check: ``{"deni": ["analyze the log"]}`` loaded and the
    label stayed allowed — a deny-list the operator believes is in force and is not."""
    bundle = tmp_path / "policy.json"
    bundle.write_text(f'{{"{key}": ["analyze the log"]}}', encoding="utf-8")
    with pytest.raises(PolicyBundleError, match="unknown keys"):
        load_bundle(bundle)


@pytest.mark.security
@pytest.mark.parametrize("version", ["2", "0", "true", '"1"', "1.0", "null"])
def test_unsupported_or_mistyped_version_is_refused(tmp_path: Path, version: str) -> None:
    """Every one of these loaded before the check (measured). ``true`` is the
    sharp one: ``bool`` is an ``int`` subclass, so ``true == 1`` without a guard."""
    bundle = tmp_path / "policy.json"
    bundle.write_text(f'{{"version": {version}}}', encoding="utf-8")
    with pytest.raises(PolicyBundleError, match="version"):
        load_bundle(bundle)


@pytest.mark.security
def test_version_one_and_absent_version_both_load(tmp_path: Path) -> None:
    """``version`` is optional because every field has a fail-closed default."""
    bundle = tmp_path / "policy.json"
    bundle.write_text('{"version": 1}', encoding="utf-8")
    assert load_bundle(bundle).decide(action_class="destructive").decision == "require_approval"
    bundle.write_text("{}", encoding="utf-8")
    assert load_bundle(bundle).decide(action_class="destructive").decision == "require_approval"
