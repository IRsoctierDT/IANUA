"""Policy & audit layer — enforces and records the AGENTS.md §5/§5.1 boundaries.

Public API:
- :class:`PolicyEngine` / :func:`classify_action` / :class:`PolicyDecision` — decide
  whether an action is allowed, requires human approval, or is denied (default-deny,
  fail-closed).
- :func:`load_bundle` / :data:`DEFAULT_BUNDLE_PATH` / :class:`PolicyBundleError` — load
  the policy from a declarative JSON bundle (fail-closed) instead of editing Python.
- :class:`AuditLogger` / :class:`AuditEvent` — append tamper-evident, hash-chained
  audit records for security-relevant decisions.
- :func:`guard` — evaluate an action and record the decision in one call.
"""

from __future__ import annotations

from agents.policies.approval import (
    ActionClass,
    Decision,
    PolicyDecision,
    PolicyEngine,
    classify_action,
)
from agents.policies.audit import AuditEvent, AuditLogger, signing_key_from_env
from agents.policies.bundle import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle

__all__ = [
    "DEFAULT_BUNDLE_PATH",
    "ActionClass",
    "AuditEvent",
    "AuditLogger",
    "Decision",
    "PolicyBundleError",
    "PolicyDecision",
    "PolicyEngine",
    "classify_action",
    "guard",
    "load_bundle",
    "signing_key_from_env",
]


def guard(
    action: str,
    *,
    engine: PolicyEngine,
    logger: AuditLogger,
    actor: str,
) -> PolicyDecision:
    """Evaluate ``action`` against ``engine`` and record the decision via ``logger``.

    Returns the :class:`PolicyDecision`. The caller is responsible for honoring it —
    in particular, not proceeding when ``decision`` is ``require_approval`` (until a
    human approves) or ``deny``.
    """
    decision = engine.evaluate(action)
    logger.record(
        actor=actor,
        action=decision.action,
        action_class=decision.action_class,
        decision=decision.decision,
        reason=decision.reason,
    )
    return decision
