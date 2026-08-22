"""The event→technique mapping engine (replaces the if/elif ladder).

Evaluates the ordered ruleset against a classified event, collects every
matching rule's attributions, merges same-technique duplicates, and projects
both the modern multi-technique view and the exact legacy scalar shape the
rest of the pipeline consumes.

Semantics (deterministic; DESIGN.md §11 2026-08-21):
* Rules evaluate in committed order; **the first matching rule owns the
  primary attribution** (and the legacy scalars), mirroring the ladder's
  precedence. Later matching rules contribute secondary attributions.
* Same-technique attributions merge: the first occurrence keeps its evidence
  and investigation (rule order is the precedence), the merged confidence is
  the maximum declared.
* A matching sentinel rule (legacy block, no techniques) claims the primary
  when it is first, but never suppresses later rules' attributions.
* No rule matched → the store's explicit fallback block, never a guess.

Every output string is a store- or corpus-declared constant — log text never
transits into a result (pinned by tests/security/test_mapping_template_injection.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.mapping.schema import (
    LegacyBlock,
    RuleStore,
    RuleTechnique,
    confidence_rank,
)
from agents.mapping.store import load_store


@dataclass(frozen=True, slots=True)
class MappingOutcome:
    """The engine's raw outcome before dict projection."""

    primary: RuleTechnique | LegacyBlock
    techniques: tuple[RuleTechnique, ...]
    matched_rule_ids: tuple[str, ...]


class MappingEngine:
    """Deterministic, corpus-validated event→technique mapping."""

    def __init__(self, store: RuleStore | None = None) -> None:
        self.store = load_store() if store is None else store

    def map(self, event_type: str, log_text: str = "") -> MappingOutcome:
        """Map a classified event to its ATT&CK attributions.

        Validates its own inputs fail-closed (AGENTS.md §4): both must be
        strings and ``event_type`` non-empty — callers may pass untrusted,
        LLM-derived text safely; it is only ever *matched against*, never
        echoed into the result.
        """
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string.")
        if not isinstance(log_text, str):
            raise ValueError("log_text must be a string.")
        normalized_event = event_type.lower()
        normalized_log = log_text.lower()

        primary: RuleTechnique | LegacyBlock | None = None
        merged: dict[str, RuleTechnique] = {}
        matched: list[str] = []
        for rule in self.store.rules:
            if not rule.matches(normalized_event, normalized_log):
                continue
            matched.append(rule.rule_id)
            if primary is None:
                primary = rule.techniques[0] if rule.techniques else rule.legacy
            for technique in rule.techniques:
                existing = merged.get(technique.technique_id)
                if existing is None:
                    merged[technique.technique_id] = technique
                elif confidence_rank(technique.confidence) > confidence_rank(existing.confidence):
                    # First occurrence keeps its evidence (rule order is the
                    # precedence); only the confidence upgrades.
                    merged[technique.technique_id] = RuleTechnique(
                        technique_id=existing.technique_id,
                        name=existing.name,
                        tactic_shortname=existing.tactic_shortname,
                        tactic=existing.tactic,
                        confidence=technique.confidence,
                        evidence=existing.evidence,
                        investigation=existing.investigation,
                        url=existing.url,
                    )
        return MappingOutcome(
            primary=self.store.fallback if primary is None else primary,
            techniques=tuple(merged.values()),
            matched_rule_ids=tuple(matched),
        )

    def map_as_dict(self, event_type: str, log_text: str = "") -> dict[str, Any]:
        """The pipeline-facing dict: legacy scalars + additive multi-technique view.

        The legacy keys (``tactic``/``technique``/``technique_id``/
        ``confidence``/``evidence``/``recommended_investigation``) keep the
        exact shape the orchestrator, incident report, detection matcher, and
        dashboard consume. New keys are additive: ``techniques`` (every merged
        attribution, insertion-ordered), ``matched_rules``, and
        ``attack_version`` so a report re-read after a corpus bump does not
        silently change meaning.
        """
        outcome = self.map(event_type, log_text)
        primary = outcome.primary
        if isinstance(primary, RuleTechnique):
            legacy = {
                "tactic": primary.tactic,
                "technique": primary.name,
                "technique_id": primary.technique_id,
                "confidence": primary.confidence,
                "evidence": list(primary.evidence),
                "recommended_investigation": list(primary.investigation),
            }
        else:
            legacy = {
                "tactic": primary.tactic,
                "technique": primary.technique,
                "technique_id": primary.technique_id,
                "confidence": primary.confidence,
                "evidence": list(primary.evidence),
                "recommended_investigation": list(primary.investigation),
            }
        return {
            "event_type": event_type,
            **legacy,
            "techniques": [
                {
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "tactic_shortname": technique.tactic_shortname,
                    "confidence": technique.confidence,
                    "evidence": list(technique.evidence),
                    "investigation": list(technique.investigation),
                    "url": technique.url,
                }
                for technique in outcome.techniques
            ],
            "matched_rules": list(outcome.matched_rule_ids),
            "attack_version": self.store.attack_version,
        }
