"""Typed schema for the committed event→technique mapping ruleset.

The ruleset (``agents/mapping/rules/*.json``) is reviewed data, not code:
rules land through PRs, are validated fail-closed against the pinned ATT&CK
corpus at load, and are drift-gated by a committed canonicalized digest
(``scripts/check_mapping_rules.py --check``).

Security considerations (DESIGN.md §5 boundary 7):
* Predicates are **literal-only by schema** — there is no regex operator, so
  ReDoS over attacker-influenced log text is structurally impossible.
* Every output string (evidence, investigation) is a static store- or
  corpus-declared string; log content never transits into a mapping result.
* Bounds on rule count, clause count, value sizes, and file size are
  enforced before any matching happens.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Confidence = Literal["low", "medium", "high"]
FieldName = Literal["event_type", "log_text"]
Operator = Literal["equals", "contains_any", "contains_all"]

#: Whole-store bounds, enforced fail-closed by the loader.
MAX_RULES = 200
MAX_CLAUSES_PER_RULE = 8
MAX_VALUES_PER_CLAUSE = 32
MAX_VALUE_LEN = 200
MAX_TECHNIQUES_PER_RULE = 4
MAX_STRINGS_PER_LIST = 8
MAX_STRING_LEN = 500
MAX_STORE_BYTES = 256 * 1024

_CONFIDENCE_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


def confidence_rank(confidence: str) -> int:
    """Deterministic ordering for declared confidence labels."""
    return _CONFIDENCE_RANK[confidence]


class MappingStoreError(ValueError):
    """Raised when the committed ruleset fails validation (whole-store)."""


@dataclass(frozen=True, slots=True)
class Clause:
    """One literal predicate over a normalized input field (clauses AND)."""

    field: FieldName
    op: Operator
    values: tuple[str, ...]

    def matches(self, value: str) -> bool:
        """Case-insensitive literal matching; ``value`` is pre-lowercased."""
        if self.op == "equals":
            return any(value == needle for needle in self.values)
        if self.op == "contains_any":
            return any(needle in value for needle in self.values)
        return all(needle in value for needle in self.values)


@dataclass(frozen=True, slots=True)
class RuleTechnique:
    """One technique attribution a rule emits, resolved against the corpus."""

    technique_id: str
    name: str
    tactic_shortname: str
    tactic: str
    confidence: Confidence
    evidence: tuple[str, ...]
    investigation: tuple[str, ...]
    url: str


@dataclass(frozen=True, slots=True)
class LegacyBlock:
    """Explicit legacy scalars for results with no technique attribution.

    The ``ids alert`` review sentinel and the no-match fallback have no
    technique by construction; a naive ``techniques[0]`` projection breaks on
    exactly these, so they are modeled explicitly.
    """

    tactic: str
    technique: str
    technique_id: str
    confidence: Confidence
    evidence: tuple[str, ...]
    investigation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MappingRule:
    """An ordered, first-match-precedence mapping rule."""

    rule_id: str
    description: str
    when: tuple[Clause, ...]
    techniques: tuple[RuleTechnique, ...]
    legacy: LegacyBlock | None

    def matches(self, event_type: str, log_text: str) -> bool:
        """All clauses must match (Sigma-style AND within a rule)."""
        values = {"event_type": event_type, "log_text": log_text}
        return all(clause.matches(values[clause.field]) for clause in self.when)


@dataclass(frozen=True, slots=True)
class RuleStore:
    """The validated, ordered ruleset plus its explicit fallback."""

    rules: tuple[MappingRule, ...]
    fallback: LegacyBlock
    attack_version: str
