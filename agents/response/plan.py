"""Response plans: evidence-linked containment guidance a **human** executes.

DESIGN.md §5 boundary 8 is closed by construction. This package produces a
``ResponsePlan`` in ``draft`` state and nothing else — there is no executor,
no arming flag, and no code path from a plan to a host. That is not caution
for its own sake; it is what the repository's own controls permit today:

* ``mcp/sandbox`` hard-codes ``--network none``, ``--cap-drop ALL``,
  ``--read-only`` and no PID namespace, so it cannot signal a host process or
  hold ``CAP_NET_ADMIN``. Making it able to would mean weakening an existing
  control (AGENTS.md §2.6).
* ``agents/policies/approval.py`` resolves its allow-list *before* the policy
  table, so an allow-list entry is a **standing, permanent, unscoped grant**,
  not per-invocation human approval. ``guarded.enforce(report_only=True)``
  bypasses the raise entirely.
* ``AuditLogger.record`` takes five strings with no structured payload slot,
  so an approval could not be bound to a specific target even if one existed.
* The repository has no caller identity at all.

Opening this boundary therefore requires first designing an explicit, signed,
expiring, per-target approval primitive — a separate reviewed change, never a
flag. ``tests/security/test_response_no_executor.py`` fails the build if
executor code appears here.

**Allow-list projection.** Plans serialize through an explicit field
projection: only the declared fields of the frozen dataclasses are emitted.
Nothing from raw incident text, log content, or the process environment can
transit into a plan, because there is no field for it to travel in — the
free-text surface is limited to catalogue-declared constants plus a bounded,
sanitized target label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

#: A plan is always a draft. The type has no other member: there is no
#: "approved" or "executed" state to reach, because nothing executes.
ExecutionState = Literal["draft"]

#: Response tiers. Tier 0 is auto-generatable enrichment/collection; tiers 2
#: and 3 describe human-gated containment (tier 1 — the plan artifact itself —
#: is what this module produces, so it is not an action tier).
Tier = Literal[0, 2, 3]

#: Verbs the catalogue may use. Every one *restricts* an adversary's
#: capability. There is deliberately no verb for gaining access, moving
#: laterally, or acting on a third party — a closed allow-list, so an
#: offensive action cannot be expressed in this schema at all.
RESTRICT_ONLY_VERBS: frozenset[str] = frozenset(
    {"collect", "revoke", "isolate", "block", "reset", "quarantine", "terminate"}
)

#: Bound on a rendered target label. Targets come from incident entities
#: (a hostname, an account); they are sanitized and capped so no log content
#: can ride into a plan through the one free-text field.
MAX_TARGET_LEN = 120

_TARGET_ALLOWED = re.compile(r"[^A-Za-z0-9._:@\-]")


def sanitize_target(value: str) -> str:
    """Reduce a target label to a bounded, printable identifier.

    Anything outside the identifier alphabet becomes ``-``: an entity label
    is a hostname, address, or account name, so nothing legitimate is lost,
    and Markdown syntax, control characters, and injected newlines cannot
    survive into a rendered plan.
    """
    if not isinstance(value, str):
        raise ValueError("target must be a string.")
    cleaned = _TARGET_ALLOWED.sub("-", value.strip())
    if not cleaned:
        raise ValueError("target must contain at least one identifier character.")
    return cleaned[:MAX_TARGET_LEN]


@dataclass(frozen=True, slots=True)
class ResponseAction:
    """One catalogue action bound to a target, as a proposal for a human.

    Every field is either catalogue-declared (constant, reviewed content) or a
    sanitized identifier. ``owner`` names who performs it — never this
    platform.
    """

    action_id: str
    title: str
    tier: Tier
    verb: str
    action_class: str
    target: str
    owner: str
    rationale: str
    steps: tuple[str, ...]
    rollback: str
    reversible: bool
    destroys_evidence: bool
    prerequisites: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Allow-list projection: only declared fields are serialized."""
        return {
            "action_id": self.action_id,
            "title": self.title,
            "tier": self.tier,
            "verb": self.verb,
            "action_class": self.action_class,
            "target": self.target,
            "owner": self.owner,
            "rationale": self.rationale,
            "steps": list(self.steps),
            "rollback": self.rollback,
            "reversible": self.reversible,
            "destroys_evidence": self.destroys_evidence,
            "prerequisites": list(self.prerequisites),
        }


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    """A draft containment plan: evidence-linked, ATT&CK-anchored, unexecuted."""

    plan_id: str
    title: str
    techniques: tuple[str, ...]
    targets: tuple[str, ...]
    actions: tuple[ResponseAction, ...]
    attack_version: str
    execution_state: ExecutionState = "draft"

    #: Stated on every rendering so a reader never mistakes a plan for an act.
    DISCLAIMER: str = (
        "This is a DRAFT PLAN. IANUA does not execute containment actions: every "
        "step below is performed by a human operator on systems they own or are "
        "authorized to administer. Actions are ordered so evidence capture "
        "precedes any disruptive step."
    )

    def to_dict(self) -> dict[str, Any]:
        """Allow-list projection over the whole plan."""
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "execution_state": self.execution_state,
            "techniques": list(self.techniques),
            "targets": list(self.targets),
            "attack_version": self.attack_version,
            "disclaimer": self.DISCLAIMER,
            "actions": [action.to_dict() for action in self.actions],
        }

    @property
    def irreversible_actions(self) -> tuple[ResponseAction, ...]:
        """Actions a human cannot undo — surfaced prominently before approval."""
        return tuple(action for action in self.actions if not action.reversible)

    @property
    def evidence_affecting_actions(self) -> tuple[ResponseAction, ...]:
        """Actions that alter or destroy evidence, so capture must precede them."""
        return tuple(action for action in self.actions if action.destroys_evidence)
