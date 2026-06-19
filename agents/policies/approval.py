"""Approval-gate policy engine — codifies the AGENTS.md §5 / §5.1 boundaries.

Turns the charter's prose security boundaries into enforced, testable code. Given a
described action, the engine classifies it and returns a decision:

- ``allow`` — read-only / benign; proceed.
- ``require_approval`` — destructive, external-network, deployment, dependency, or
  secret-handling action; a human must approve (§5.1).
- ``deny`` — a §5 prohibition (offensive tooling, exfiltration, weakening a control);
  never proceed.

Design (AGENTS.md §3): **default-deny and fail-closed** — an unrecognized action is
gated for human approval, never silently allowed. The §5 prohibitions are
non-negotiable: an allow-list entry can never downgrade a ``boundary_crossing``
action.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

ActionClass = Literal[
    "read_only",
    "destructive",
    "external_network",
    "deployment",
    "dependency",
    "secret_handling",
    "boundary_crossing",
    "unknown",
]
Decision = Literal["allow", "require_approval", "deny"]

# Default-deny policy: only read-only is auto-allowed; §5 prohibitions are denied;
# everything else (and the unknown fallback) requires a human (fail closed).
_DEFAULT_POLICY: dict[ActionClass, Decision] = {
    "read_only": "allow",
    "destructive": "require_approval",
    "external_network": "require_approval",
    "deployment": "require_approval",
    "dependency": "require_approval",
    "secret_handling": "require_approval",  # nosec B105 - policy decision label, not a credential
    "boundary_crossing": "deny",
    "unknown": "require_approval",
}

# Classification rules, checked in order of severity — first match wins.
_CLASS_RULES: tuple[tuple[ActionClass, frozenset[str]], ...] = (
    (
        "boundary_crossing",
        frozenset(
            {
                "exploit",
                "brute force",
                "exfiltrate",
                "ddos",
                "denial of service",
                "deploy malware",
                "weaken control",
                "disable auth",
                "bypass control",
                "attack ",
            }
        ),
    ),
    (
        "secret_handling",
        frozenset(
            {
                "secret",
                "api key",
                "password",
                "token",
                "credential",
                "private key",
                ".env",
                "rotate key",
            }
        ),
    ),
    (
        "destructive",
        frozenset(
            {
                "rm -rf",
                "delete",
                "drop table",
                "truncate",
                "force-push",
                "force push",
                "overwrite",
                "purge",
                "wipe",
            }
        ),
    ),
    (
        "deployment",
        frozenset(
            {"deploy", "terraform apply", "kubectl apply", "restart prod", "release to prod"}
        ),
    ),
    (
        "dependency",
        frozenset({"pip install", "npm install", "add dependency", "poetry add"}),
    ),
    (
        "external_network",
        frozenset(
            {
                "http://",
                "https://",
                "send email",
                "publish",
                "webhook",
                "upload",
                "post to",
                "curl ",
                "fetch ",
            }
        ),
    ),
    (
        "read_only",
        frozenset(
            {
                "read ",
                "list ",
                "analyze",
                "classify",
                "summarize",
                "draft",
                "report",
                "retrieve",
                "scan logs",
                "review",
            }
        ),
    ),
)


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of evaluating an action against the policy."""

    action: str
    action_class: ActionClass
    decision: Decision
    requires_human: bool
    reason: str


def classify_action(description: str) -> ActionClass:
    """Classify an action description into an ``ActionClass`` (first match wins)."""
    lowered = description.lower()
    for action_class, keywords in _CLASS_RULES:
        if any(kw in lowered for kw in keywords):
            return action_class
    return "unknown"


class PolicyEngine:
    """Evaluate actions against the §5/§5.1 boundaries (default-deny, fail-closed)."""

    def __init__(
        self,
        policy: dict[ActionClass, Decision] | None = None,
        *,
        allow: Iterable[str] = (),
        deny: Iterable[str] = (),
    ) -> None:
        self.policy = dict(_DEFAULT_POLICY)
        if policy:
            self.policy.update(policy)
        # Exact-match operator overrides (case-insensitive). deny wins over allow.
        self._allow = frozenset(a.strip().lower() for a in allow)
        self._deny = frozenset(d.strip().lower() for d in deny)

    def evaluate(self, action: str) -> PolicyDecision:
        """Return a :class:`PolicyDecision` for the described ``action``."""
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action must be a non-empty string.")

        key = action.strip().lower()
        action_class = classify_action(action)

        # §5 prohibitions are non-negotiable — no allow-list override.
        if action_class == "boundary_crossing":
            return self._decide(
                action, action_class, "deny", "Crosses an AGENTS.md §5 prohibition."
            )

        if key in self._deny:
            return self._decide(action, action_class, "deny", "Action is on the deny-list.")
        if key in self._allow:
            return self._decide(
                action, action_class, "allow", "Action is on the operator allow-list."
            )

        decision = self.policy.get(action_class, "require_approval")
        reason = {
            "allow": "Read-only/benign action.",
            "require_approval": "Gated action — requires human approval (AGENTS.md §5.1).",
            "deny": "Denied by policy.",
        }[decision]
        return self._decide(action, action_class, decision, reason)

    @staticmethod
    def _decide(
        action: str, action_class: ActionClass, decision: Decision, reason: str
    ) -> PolicyDecision:
        return PolicyDecision(
            action=action,
            action_class=action_class,
            decision=decision,
            requires_human=decision == "require_approval",
            reason=reason,
        )
