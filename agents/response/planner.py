"""Build draft response plans from triage results — deterministic, unexecuted.

Selection is table-driven off the ATT&CK techniques a mapping result
attributes, so what a plan proposes is reviewable data rather than embedded
control flow. Ordering is a safety property, not a presentation choice:
evidence collection (tier 0) always precedes reversible containment (tier 2),
which always precedes irreversible action (tier 3), and every
evidence-affecting action's prerequisite is pulled in ahead of it.

No clock, no network, no filesystem beyond reading the committed catalogue,
and no execution of any kind.
"""

from __future__ import annotations

import hashlib
from typing import Any

from agents.response.catalogue import build_action, load_catalogue
from agents.response.plan import ResponseAction, ResponsePlan

#: Technique -> containment actions worth *proposing*. Deliberately narrow:
#: an action appears only where the technique genuinely implies it. Every
#: plan additionally receives the tier-0 evidence actions.
_TECHNIQUE_ACTIONS: dict[str, tuple[str, ...]] = {
    # Credential access / valid accounts -> identity containment.
    "T1110": ("revoke-account-sessions", "reset-account-credentials"),
    "T1078": ("revoke-account-sessions", "reset-account-credentials"),
    "T1021.004": ("revoke-account-sessions",),
    # Persistence primitives -> identity + host containment.
    "T1136.001": ("revoke-account-sessions",),
    "T1098": ("revoke-account-sessions", "reset-account-credentials"),
    "T1098.004": ("revoke-account-sessions", "isolate-host-network"),
    "T1053.003": ("isolate-host-network", "quarantine-suspect-file"),
    # Defense impairment / evidence destruction -> preserve, then isolate.
    "T1685": ("preserve-log-evidence", "isolate-host-network"),
    "T1070.003": ("preserve-log-evidence",),
    # Execution and resident payloads -> isolate, quarantine, terminate.
    "T1204.002": ("isolate-host-network", "quarantine-suspect-file"),
    "T1059.001": ("isolate-host-network", "terminate-malicious-process"),
    "T1059.004": ("isolate-host-network", "terminate-malicious-process"),
    "T1620": ("isolate-host-network", "terminate-malicious-process"),
    # Command and control -> block egress and isolate.
    "T1105": ("block-indicator-egress", "isolate-host-network"),
    # Adversary-in-the-middle -> network containment.
    "T1557": ("isolate-host-network",),
    "T1557.002": ("isolate-host-network",),
    # Discovery alone justifies no containment: proposing one on a port scan
    # is exactly the false-positive-driven outage this design guards against.
}

#: Collection actions every plan opens with — capture precedes disruption.
_ALWAYS_FIRST: tuple[str, ...] = ("capture-volatile-memory",)


def _plan_id(techniques: tuple[str, ...], targets: tuple[str, ...]) -> str:
    """Deterministic id from the plan's identity — never a clock or a counter."""
    digest = hashlib.sha256()
    for part in (*sorted(techniques), "|", *sorted(targets)):
        digest.update(part.encode("utf-8"))
        digest.update(b"\x00")
    return f"plan-{digest.hexdigest()[:16]}"


class ResponsePlanner:
    """Produce draft containment plans. Never executes anything."""

    def __init__(self, catalogue: dict[str, dict[str, Any]] | None = None) -> None:
        self.catalogue = load_catalogue() if catalogue is None else catalogue

    def plan_for_techniques(
        self,
        techniques: list[str] | tuple[str, ...],
        targets: list[str] | tuple[str, ...],
        *,
        attack_version: str = "",
    ) -> ResponsePlan:
        """Build the draft plan for a set of attributed techniques and targets."""
        if not isinstance(techniques, (list, tuple)):
            raise ValueError("techniques must be a list or tuple.")
        if not isinstance(targets, (list, tuple)) or not targets:
            raise ValueError("targets must be a non-empty list or tuple.")

        technique_ids = tuple(str(t) for t in techniques)
        selected: list[str] = list(_ALWAYS_FIRST)
        for technique_id in technique_ids:
            for action_id in _TECHNIQUE_ACTIONS.get(technique_id, ()):
                if action_id not in selected:
                    selected.append(action_id)

        # Pull every prerequisite in ahead of the action that needs it.
        resolved: list[str] = []
        for action_id in selected:
            for prerequisite in self.catalogue[action_id]["prerequisites"]:
                if prerequisite not in resolved:
                    resolved.append(prerequisite)
            if action_id not in resolved:
                resolved.append(action_id)

        actions: list[ResponseAction] = []
        for action_id in resolved:
            for target in targets:
                actions.append(build_action(action_id, str(target), self.catalogue))

        # Tier order is the safety ordering: collect -> reversible -> irreversible.
        actions.sort(key=lambda action: (action.tier, action.action_id, action.target))

        clean_targets = tuple(dict.fromkeys(action.target for action in actions))
        return ResponsePlan(
            plan_id=_plan_id(technique_ids, clean_targets),
            title=f"Containment plan for {len(clean_targets)} target(s)",
            techniques=technique_ids,
            targets=clean_targets,
            actions=tuple(actions),
            attack_version=attack_version,
        )

    def plan_for_event(
        self, mitre_result: dict[str, Any], soc_result: dict[str, Any]
    ) -> ResponsePlan | None:
        """Build a plan from pipeline results, or ``None`` when none is warranted.

        Returns ``None`` rather than an empty plan when the attributed
        techniques imply no containment (a port scan, an unattributed IDS
        alert) — proposing action on weak signal is how false positives turn
        into outages.
        """
        technique_ids: list[str] = []
        for attribution in mitre_result.get("techniques", []) or []:
            if isinstance(attribution, dict):
                technique_id = attribution.get("technique_id")
                if isinstance(technique_id, str):
                    technique_ids.append(technique_id)
        if not technique_ids:
            legacy = mitre_result.get("technique_id")
            if isinstance(legacy, str) and legacy != "UNKNOWN":
                technique_ids.append(legacy)

        if not any(tid in _TECHNIQUE_ACTIONS for tid in technique_ids):
            return None

        targets: list[str] = []
        for indicator in soc_result.get("indicators", []) or []:
            if isinstance(indicator, str) and indicator.strip():
                targets.append(indicator)
        if not targets:
            targets = ["affected-host"]

        return self.plan_for_techniques(
            technique_ids,
            targets,
            attack_version=str(mitre_result.get("attack_version", "")),
        )
