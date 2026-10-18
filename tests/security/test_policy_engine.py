# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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


# ------------------------------------------------ grant scope, pinned (task #28)
_ALL_CLASSES = [
    "read_only",
    "collection",
    "containment",
    "destructive",
    "external_network",
    "deployment",
    "dependency",
    "secret_handling",
    "boundary_crossing",
    "unknown",
]


@pytest.mark.security
@pytest.mark.parametrize("action_class", _ALL_CLASSES)
def test_allow_list_grant_is_label_scoped_not_class_scoped(action_class: str) -> None:
    """Pins the measured decision table so a change to it shows up in a diff.

    An allow-list entry matches on the label alone: one grant permits that label
    in EVERY class except ``boundary_crossing``. So a grant written for one
    capability also permits the same string re-declared under another class, and
    an "egress grant" is a grant of that string anywhere. Whether grants should
    carry a class is the owner's decision (#28); until it is made, this is the
    behaviour, stated rather than incidental. The one row that must never move
    is ``boundary_crossing``.
    """
    eng = PolicyEngine(allow=["ship_wal:apply"])
    decision = eng.decide(action_class=action_class, label="ship_wal:apply").decision  # type: ignore[arg-type]
    assert decision == ("deny" if action_class == "boundary_crossing" else "allow")


@pytest.mark.security
def test_deny_list_wins_over_allow_list_for_the_same_label() -> None:
    eng = PolicyEngine(allow=["ship_wal:apply"], deny=["ship_wal:apply"])
    assert eng.decide(action_class="destructive", label="ship_wal:apply").decision == "deny"


@pytest.mark.security
@pytest.mark.parametrize("decision", ["allow", "require_approval"])
def test_boundary_crossing_table_override_is_refused_at_construction(decision: str) -> None:
    """``decide`` denies ``boundary_crossing`` before reading the table, so a value
    other than ``deny`` would be stored and never enforced. Measured before this
    check: ``engine.policy["boundary_crossing"] == "allow"`` while ``decide`` denied."""
    with pytest.raises(ValueError, match="boundary_crossing"):
        PolicyEngine(policy={"boundary_crossing": decision})  # type: ignore[dict-item]


@pytest.mark.security
def test_boundary_crossing_cannot_be_downgraded_by_both_mechanisms_together() -> None:
    """Explicit ``deny`` in the table plus an allow-list entry for the label: still denied."""
    eng = PolicyEngine(policy={"boundary_crossing": "deny"}, allow=["exploit the target host"])
    assert eng.evaluate("Exploit the target host").decision == "deny"
