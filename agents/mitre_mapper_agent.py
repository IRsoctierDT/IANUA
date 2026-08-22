"""MITRE ATT&CK Mapper Agent — facade over the data-driven mapping engine.

Historically an if/elif ladder of ~8 hardcoded mappings; now a thin facade
over :class:`agents.mapping.MappingEngine`, which evaluates the committed,
reviewed ruleset in ``agents/mapping/rules/`` against the pinned local
ATT&CK corpus (``attack/``). The ``map_event`` signature and legacy result
keys are preserved exactly; the result additionally carries the merged
multi-technique view (``techniques``), the matched rule ids, and the pinned
``attack_version`` so downstream artifacts are version-stamped.

Security consideration: ``map_event`` validates both inputs fail-closed
(strings; non-empty ``event_type``) — callers may pass untrusted,
LLM-derived text safely; input is only matched against literal predicates
(no regex exists in the rule schema) and never echoed into the result.
"""

from __future__ import annotations

from typing import Any

from agents.mapping import MappingEngine


class MitreMapperAgent:
    def __init__(self) -> None:
        # One engine per agent: the ruleset and corpus load once, fail-closed.
        self._engine = MappingEngine()

    def map_event(self, event_type: str, log_text: str = "") -> dict[str, Any]:
        """Map ``event_type`` (+ optional raw ``log_text``) to an ATT&CK result dict.

        Legacy keys (``tactic``, ``technique``, ``technique_id``,
        ``confidence``, ``evidence``, ``recommended_investigation``,
        ``event_type``) keep their exact shape; ``techniques``,
        ``matched_rules``, and ``attack_version`` are additive.
        """
        return self._engine.map_as_dict(event_type, log_text)


if __name__ == "__main__":
    mapper = MitreMapperAgent()
    result = mapper.map_event(
        "authentication failure",
        "Failed password for root from 10.0.0.5 port 22 ssh2",
    )
    print(result)
