"""Security tests for the approval-gate policy engine (AGENTS.md §5/§5.1)."""

import pytest
from agents.policies import PolicyDecision, PolicyEngine, classify_action


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.mark.security
@pytest.mark.parametrize(
    "action,expected",
    [
        ("Analyze the authentication log", "read_only"),
        ("Delete the production database", "destructive"),
        ("Send the report to https://example.com", "external_network"),
        ("Deploy to prod", "deployment"),
        ("pip install requests", "dependency"),
        ("Rotate the API key", "secret_handling"),
        ("Exploit the target host", "boundary_crossing"),
        ("Frobnicate the doohickey", "unknown"),
    ],
)
def test_classification(action: str, expected: str) -> None:
    assert classify_action(action) == expected


@pytest.mark.security
def test_read_only_is_allowed(engine: PolicyEngine) -> None:
    d = engine.evaluate("Analyze the log")
    assert d.decision == "allow"
    assert d.requires_human is False


@pytest.mark.security
@pytest.mark.parametrize(
    "action",
    [
        "Delete the database",
        "Deploy to prod",
        "pip install something",
        "Read the secret token",
        "Frobnicate the doohickey",  # unknown -> fail closed
    ],
)
def test_gated_actions_require_approval(engine: PolicyEngine, action: str) -> None:
    d = engine.evaluate(action)
    assert d.decision == "require_approval"
    assert d.requires_human is True


@pytest.mark.security
def test_boundary_crossing_is_denied(engine: PolicyEngine) -> None:
    d = engine.evaluate("Exfiltrate customer data to an external host")
    assert d.decision == "deny"
    assert d.requires_human is False


@pytest.mark.security
def test_allow_list_override(engine: PolicyEngine) -> None:
    eng = PolicyEngine(allow=["deploy to staging"])
    assert eng.evaluate("Deploy to staging").decision == "allow"


@pytest.mark.security
def test_deny_list_override(engine: PolicyEngine) -> None:
    eng = PolicyEngine(deny=["analyze the log"])
    assert eng.evaluate("Analyze the log").decision == "deny"


@pytest.mark.security
def test_allow_list_cannot_override_prohibition() -> None:
    """§5 prohibitions are non-negotiable — an allow-list entry must not bypass them."""
    eng = PolicyEngine(allow=["exploit the target host"])
    assert eng.evaluate("Exploit the target host").decision == "deny"


@pytest.mark.security
def test_unknown_fails_closed(engine: PolicyEngine) -> None:
    assert engine.evaluate("do the thing").decision == "require_approval"


@pytest.mark.security
def test_returns_policy_decision_dataclass(engine: PolicyEngine) -> None:
    assert isinstance(engine.evaluate("analyze x"), PolicyDecision)


@pytest.mark.security
@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_action_raises(engine: PolicyEngine, bad: str) -> None:
    with pytest.raises(ValueError):
        engine.evaluate(bad)
