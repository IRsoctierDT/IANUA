"""Security tests for the defensive `containment` action class.

Proves the DESIGN.md (2026-08-21) compensating controls: containment is
auto-allowed and audited, but it can never weaken the existing gates — hybrid
phrasing that also matches an offensive, secret, or destructive keyword keeps
the more restrictive classification, and §5 denies remain non-negotiable.
"""

import json
from pathlib import Path

import pytest
from agents.policies import (
    PolicyBundleError,
    PolicyEngine,
    classify_action,
    load_bundle,
)


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.mark.security
@pytest.mark.parametrize(
    "action",
    [
        "Quarantine the dropped payload",
        "Isolate host web-01 from the network",
        "Kill process 4242 immediately",
        "Suspend process 999 for forensics",
        "Stop the ransomware before it finishes encrypting",
        "Shut down the payload on the file server",
        "Initiate containment of the outbreak",
        "Contain the incident on the lab segment",
        "Block c2 traffic to the beacon",
        "Block indicator 203.0.113.7",
        "Disable account mallory pending investigation",
        "Revoke session for the compromised analyst",
    ],
)
def test_containment_phrases_classify_as_containment(action: str) -> None:
    assert classify_action(action) == "containment"


@pytest.mark.security
def test_containment_is_allowed_and_audited_reason(engine: PolicyEngine) -> None:
    d = engine.evaluate("Quarantine the ransomware payload")
    assert d.decision == "allow"
    assert d.requires_human is False
    # The reason must point at the recorded human authorization, not "benign".
    assert "2026-08-21" in d.reason
    assert "containment" in d.reason.lower()


@pytest.mark.security
@pytest.mark.parametrize(
    "action,expected",
    [
        # Hybrid phrasing keeps the MORE restrictive class — no weakening.
        ("Quarantine the payload and delete the backups", "destructive"),
        ("Isolate the host and wipe the disk", "destructive"),
        ("Contain the incident and rotate the api key", "secret_handling"),
        ("Kill process 4242 and purge the logs", "destructive"),
        # Destructive synonyms gate too, not just the classic keywords.
        ("Kill process 4242 and remove all files in /backups", "destructive"),
        ("Quarantine the payload and shred the backups", "destructive"),
        ("Stop the ransomware and erase the logs", "destructive"),
        ("Isolate the host and format the disk", "destructive"),
        ("Quarantine the payload and destroy the snapshots", "destructive"),
        ("Quarantine the payload and encrypt the backups", "destructive"),
        # Containment is classified after EVERY gated class, not just the
        # first three — network/deploy/dependency hybrids stay gated.
        ("Quarantine the sample and upload it to virustotal", "external_network"),
        ("Block c2 by posting a webhook to the SOAR", "external_network"),
        ("Deploy new firewall rules to the isolated lab segment", "deployment"),
        ("Isolate the host and pip install the forensic toolkit", "dependency"),
    ],
)
def test_hybrid_phrasing_stays_gated(engine: PolicyEngine, action: str, expected: str) -> None:
    assert classify_action(action) == expected
    assert engine.evaluate(action).decision == "require_approval"


@pytest.mark.security
@pytest.mark.parametrize(
    "action",
    [
        # Benign text must not slide into the containment carve-out via loose
        # substrings ("processing", "isolated") — it stays unknown/fail-closed.
        "Stop processing the ingest queue",
        "Run the job in an isolated container",
    ],
)
def test_benign_text_does_not_widen_the_carve_out(engine: PolicyEngine, action: str) -> None:
    assert classify_action(action) == "unknown"
    assert engine.evaluate(action).decision == "require_approval"


@pytest.mark.security
def test_containment_cannot_mask_a_prohibition(engine: PolicyEngine) -> None:
    """§5 prohibitions win over the containment carve-out, always."""
    d = engine.evaluate("Exploit the target host, then quarantine the artifacts")
    assert d.action_class == "boundary_crossing"
    assert d.decision == "deny"


@pytest.mark.security
def test_operator_can_deny_list_a_single_capability() -> None:
    eng = PolicyEngine(deny=["quarantine_file"])
    d = eng.decide(action_class="containment", label="quarantine_file")
    assert d.decision == "deny"
    # Other containment capabilities are unaffected.
    assert eng.decide(action_class="containment", label="stop_process").decision == "allow"


@pytest.mark.security
def test_shipped_bundle_allows_containment() -> None:
    """The committed policy.json carries the containment decision explicitly."""
    engine = load_bundle()
    assert engine.decide(action_class="containment", label="stop_process").decision == "allow"


@pytest.mark.security
def test_bundle_can_re_gate_containment(tmp_path: Path) -> None:
    """Operators can flip containment back to a human gate without code changes."""
    bundle = tmp_path / "policy.json"
    bundle.write_text(
        json.dumps({"version": 1, "policy": {"containment": "require_approval"}}),
        encoding="utf-8",
    )
    engine = load_bundle(bundle)
    d = engine.decide(action_class="containment", label="isolate_host")
    assert d.decision == "require_approval"
    assert d.requires_human is True


@pytest.mark.security
def test_bundle_still_rejects_unknown_classes(tmp_path: Path) -> None:
    bundle = tmp_path / "policy.json"
    bundle.write_text(
        json.dumps({"version": 1, "policy": {"counterstrike": "allow"}}),
        encoding="utf-8",
    )
    with pytest.raises(PolicyBundleError):
        load_bundle(bundle)
