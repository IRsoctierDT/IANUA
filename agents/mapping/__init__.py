"""Data-driven event→technique mapping over the pinned ATT&CK corpus.

Public surface: :class:`MappingEngine` (the evaluator), :func:`load_store`
(fail-closed ruleset loading), and the schema types. The committed ruleset
lives in ``agents/mapping/rules/`` and is drift-gated by
``scripts/check_mapping_rules.py --check`` against ``rules.sha256``.
"""

from agents.mapping.engine import MappingEngine, MappingOutcome
from agents.mapping.schema import (
    Clause,
    LegacyBlock,
    MappingRule,
    MappingStoreError,
    RuleStore,
    RuleTechnique,
)
from agents.mapping.store import load_store, parse_store

__all__ = [
    "Clause",
    "LegacyBlock",
    "MappingEngine",
    "MappingOutcome",
    "MappingRule",
    "MappingStoreError",
    "RuleStore",
    "RuleTechnique",
    "load_store",
    "parse_store",
]
