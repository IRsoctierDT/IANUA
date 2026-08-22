"""Approval-gate policy engine — codifies the AGENTS.md §5 / §5.1 boundaries.

Turns the charter's prose security boundaries into enforced, testable code. Given a
described action, the engine classifies it and returns a decision:

- ``allow`` — read-only / benign, or a defensive ``containment`` action; proceed.
- ``require_approval`` — destructive, external-network, deployment, dependency, or
  secret-handling action; a human must approve (§5.1).
- ``deny`` — a §5 prohibition (offensive tooling, exfiltration, weakening a control);
  never proceed.

Design (AGENTS.md §3): **default-deny and fail-closed** — an unrecognized action is
gated for human approval, never silently allowed. The §5 prohibitions are
non-negotiable: an allow-list entry can never downgrade a ``boundary_crossing``
action.

Containment (DESIGN.md decision log, 2026-08-21): ``containment`` covers defensive
incident-response actions that stop or contain an active payload — quarantining a
dropped file, stopping a malicious process, isolating a lab host, blocking an
indicator, disabling a compromised account. It is auto-allowed by default because
ransomware/extortion response is time-critical (encryption completes in minutes;
a human gate defeats the control), under standing human authorization recorded in
the decision log. Three compensating controls keep this safe:

1. The class covers only **reversible-by-design, lab-scoped** actions
   (``agents/tools/containment.py``), with one narrow, labeled exception:
   ``stop_process(force=True)`` sends SIGKILL to halt active encryption —
   process-level, never data-destructive, and separately deny-listable under
   its own ``stop_process_force`` label. Irreversible eradication stays
   ``destructive`` and keeps its human gate.
2. Classification order checks ``containment`` **after every gated class**
   (``boundary_crossing``, ``secret_handling``, ``destructive``,
   ``deployment``, ``dependency``, ``external_network``) — hybrid phrasing
   ("quarantine and delete the backups", "quarantine the sample and upload
   it") keeps the more restrictive class; nothing gated or denied can ride in
   under a containment label. Keyword classification of free text is
   best-effort by nature (the enforced surface at tool dispatch uses declared
   action classes), so unmatched text still falls to ``unknown`` and fails
   closed.
3. Every invocation is recorded to the tamper-evident audit trail (via the
   engine/toolkit's audit logger), and operators can re-gate the class (or
   deny-list individual capabilities) via the policy bundle without touching
   code.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

ActionClass = Literal[
    "read_only",
    "containment",
    "destructive",
    "external_network",
    "deployment",
    "dependency",
    "secret_handling",
    "boundary_crossing",
    "unknown",
]
Decision = Literal["allow", "require_approval", "deny"]

# Default-deny policy: read-only and defensive containment are auto-allowed
# (containment rationale + compensating controls in the module docstring);
# §5 prohibitions are denied; everything else (and the unknown fallback)
# requires a human (fail closed).
_DEFAULT_POLICY: dict[ActionClass, Decision] = {
    "read_only": "allow",
    "containment": "allow",
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
                "remove",
                "erase",
                "shred",
                "destroy",
                "drop table",
                "truncate",
                "force-push",
                "force push",
                "overwrite",
                "purge",
                "wipe",
                "reimage",
                "format disk",
                "format the disk",
                "reformat",
                "encrypt the",
                "encrypt all",
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
    # Containment is deliberately checked AFTER every gated class above: an
    # action that also matches an offensive, secret, destructive, deployment,
    # dependency, or network keyword ("quarantine and delete the backups",
    # "quarantine the sample and upload it") classifies as the more restrictive
    # class and stays gated/denied — the containment carve-out can never weaken
    # those controls. Keywords are deliberately narrow (trailing spaces avoid
    # "isolated"/"processing" false matches); unmatched text stays `unknown`
    # and fails closed.
    (
        "containment",
        frozenset(
            {
                "quarantine",
                "isolate ",
                "network isolation",
                "containment",
                "contain ",
                "kill process",
                "kill the process",
                "kill ransomware",
                "kill the ransomware",
                "terminate process",
                "suspend process",
                "stop process ",
                "stop the process",
                "stop ransomware",
                "stop the ransomware",
                "stop payload",
                "shut down payload",
                "shut down the payload",
                "shutdown payload",
                "block indicator",
                "block ioc",
                "block c2",
                "disable account",
                "disable the account",
                "disable compromised",
                "revoke session",
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
        """Classify ``action`` from its description and return a decision."""
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action must be a non-empty string.")
        return self.decide(action_class=classify_action(action), label=action)

    def decide(self, *, action_class: ActionClass, label: str = "") -> PolicyDecision:
        """Decide for a known ``action_class`` (e.g. a registered tool's declared class).

        ``label`` is the human-meaningful action string used for allow/deny-list
        matching and recorded on the decision.
        """
        action = label.strip() or action_class
        key = label.strip().lower()

        # §5 prohibitions are non-negotiable — no allow-list override.
        if action_class == "boundary_crossing":
            return self._decide(
                action, action_class, "deny", "Crosses an AGENTS.md §5 prohibition."
            )

        if key and key in self._deny:
            return self._decide(action, action_class, "deny", "Action is on the deny-list.")
        if key and key in self._allow:
            return self._decide(
                action, action_class, "allow", "Action is on the operator allow-list."
            )

        decision = self.policy.get(action_class, "require_approval")
        if decision == "allow" and action_class == "containment":
            reason = (
                "Defensive containment action — auto-allowed for time-critical "
                "response and audited (DESIGN.md decision log, 2026-08-21)."
            )
        else:
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
