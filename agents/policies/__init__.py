# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Policy & audit layer — enforces and records the AGENTS.md §5/§5.1 boundaries.

Public API:
- :class:`PolicyEngine` / :func:`classify_action` / :class:`PolicyDecision` — decide
  whether an action is allowed, requires human approval, or is denied (default-deny,
  fail-closed).
- :func:`load_bundle` / :data:`DEFAULT_BUNDLE_PATH` / :class:`PolicyBundleError` — load
  the policy from a declarative JSON bundle (fail-closed) instead of editing Python.
- :class:`EgressAllowlist` / :class:`LabHost` / :data:`DEFAULT_EGRESS_ALLOWLIST_PATH` —
  what "lab host" means: a destination named in the committed egress allow-list, which
  ships empty, so the default answer is deny. The bundle's ``allow`` list names the
  *action* that may egress; this names the *destination*, and neither alone suffices.
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
from agents.policies.audit import (
    AUDIT_FIELD_DELIMITER,
    AuditEvent,
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    reject_delimiter,
    signing_key_from_env,
    verifier_from_env,
)
from agents.policies.bundle import DEFAULT_BUNDLE_PATH, PolicyBundleError, load_bundle
from agents.policies.egress import (
    DEFAULT_EGRESS_ALLOWLIST_PATH,
    EgressAllowlist,
    EgressAllowlistError,
    EgressDenied,
    LabHost,
)
from agents.policies.principal import Principal, PrincipalError, coerce
from agents.policies.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    HmacSigner,
    Signer,
    ed25519_signer_from_env,
    ed25519_verifier_from_env,
    generate_ed25519_keypair,
)

__all__ = [
    "AUDIT_FIELD_DELIMITER",
    "DEFAULT_BUNDLE_PATH",
    "DEFAULT_EGRESS_ALLOWLIST_PATH",
    "ActionClass",
    "AuditEvent",
    "AuditFieldError",
    "AuditLogger",
    "Decision",
    "Ed25519Signer",
    "Ed25519Verifier",
    "EgressAllowlist",
    "EgressAllowlistError",
    "EgressDenied",
    "HmacSigner",
    "LabHost",
    "PolicyBundleError",
    "PolicyDecision",
    "PolicyEngine",
    "Principal",
    "PrincipalError",
    "Signer",
    "classify_action",
    "coerce",
    "ed25519_signer_from_env",
    "ed25519_verifier_from_env",
    "escape_delimiter",
    "generate_ed25519_keypair",
    "guard",
    "load_bundle",
    "reject_delimiter",
    "signing_key_from_env",
    "verifier_from_env",
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
