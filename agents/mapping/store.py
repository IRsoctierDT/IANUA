"""Fail-closed loader for the committed mapping ruleset.

Follows the ``compliance/attestations.py`` posture: exact field sets, strict
shapes, and whole-store rejection on any anomaly. Every technique reference
is resolved against the pinned ATT&CK corpus at load — an unknown ID rejects
the store; a revoked ID rejects it **naming the successor**; a deprecated ID
rejects it too (a mapping rule is operational content and must re-anchor
deliberately, unlike intel records which merely degrade).
"""

from __future__ import annotations

import json
from pathlib import Path

from attack import AttackError, Corpus, load_corpus, validate_reference

from agents.mapping.schema import (
    MAX_CLAUSES_PER_RULE,
    MAX_RULES,
    MAX_STORE_BYTES,
    MAX_STRING_LEN,
    MAX_STRINGS_PER_LIST,
    MAX_TECHNIQUES_PER_RULE,
    MAX_VALUE_LEN,
    MAX_VALUES_PER_CLAUSE,
    Clause,
    LegacyBlock,
    MappingRule,
    MappingStoreError,
    RuleStore,
    RuleTechnique,
)

RULES_DIR = Path(__file__).resolve().parent / "rules"

_TOP_FIELDS = {"schema", "rules", "fallback"}
_RULE_FIELDS = {"id", "description", "when", "techniques"}
_RULE_FIELDS_WITH_LEGACY = _RULE_FIELDS | {"legacy"}
_CLAUSE_FIELDS = {"field", "op", "values"}
_TECHNIQUE_FIELDS = {"technique_id", "tactic", "confidence", "evidence", "investigation"}
_LEGACY_FIELDS = {"tactic", "technique", "technique_id", "confidence", "evidence", "investigation"}
_FIELDS = {"event_type", "log_text"}
_OPS = {"equals", "contains_any", "contains_all"}
_CONFIDENCES = {"low", "medium", "high"}


def _reject(reason: str) -> MappingStoreError:
    return MappingStoreError(f"invalid mapping ruleset: {reason}")


def _string_list(value: object, context: str, *, max_len: int = MAX_STRING_LEN) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_STRINGS_PER_LIST
        or not all(isinstance(item, str) and 0 < len(item) <= max_len for item in value)
    ):
        raise _reject(
            f"{context} must be 1..{MAX_STRINGS_PER_LIST} non-empty strings of <= {max_len} chars"
        )
    return tuple(value)


def _parse_clause(raw: object, context: str) -> Clause:
    if not isinstance(raw, dict) or set(raw) != _CLAUSE_FIELDS:
        raise _reject(f"{context}: clause must carry exactly field/op/values")
    field = raw["field"]
    if field not in _FIELDS:
        raise _reject(f"{context}: unknown field {field!r}")
    op = raw["op"]
    if op not in _OPS:
        raise _reject(f"{context}: unknown operator {op!r} (predicates are literal-only)")
    values = raw["values"]
    if (
        not isinstance(values, list)
        or not values
        or len(values) > MAX_VALUES_PER_CLAUSE
        or not all(isinstance(item, str) and 0 < len(item) <= MAX_VALUE_LEN for item in values)
    ):
        raise _reject(f"{context}: values must be 1..{MAX_VALUES_PER_CLAUSE} bounded strings")
    return Clause(field=field, op=op, values=tuple(item.lower() for item in values))


def _parse_technique(raw: object, context: str, corpus: Corpus) -> RuleTechnique:
    if not isinstance(raw, dict) or set(raw) != _TECHNIQUE_FIELDS:
        raise _reject(f"{context}: technique must carry exactly {sorted(_TECHNIQUE_FIELDS)}")
    technique_id = raw["technique_id"]
    if not isinstance(technique_id, str):
        raise _reject(f"{context}: technique_id must be a string")
    try:
        verdict = validate_reference(technique_id, corpus)
    except AttackError as exc:
        raise _reject(f"{context}: {exc}") from exc
    if verdict.status == "unknown":
        raise _reject(f"{context}: {technique_id} does not exist in the pinned ATT&CK release")
    if verdict.status == "revoked":
        raise _reject(
            f"{context}: {technique_id} is revoked in the pinned release"
            + (f" — re-anchor to its successor {verdict.successor}" if verdict.successor else "")
        )
    if verdict.status == "deprecated":
        raise _reject(
            f"{context}: {technique_id} is deprecated in the pinned release — "
            "re-anchor this rule deliberately (deprecation carries no successor)"
        )
    technique = corpus.techniques[technique_id]
    tactic_shortname = raw["tactic"]
    if tactic_shortname not in technique.tactics:
        raise _reject(
            f"{context}: tactic {tactic_shortname!r} is not one of {technique_id}'s "
            f"tactics {list(technique.tactics)} in the pinned release"
        )
    confidence = raw["confidence"]
    if confidence not in _CONFIDENCES:
        raise _reject(f"{context}: unknown confidence {confidence!r}")
    return RuleTechnique(
        technique_id=technique_id,
        name=technique.name,
        tactic_shortname=tactic_shortname,
        tactic=corpus.tactics[tactic_shortname].name,
        confidence=confidence,
        evidence=_string_list(raw["evidence"], f"{context} evidence"),
        investigation=_string_list(raw["investigation"], f"{context} investigation"),
        url=technique.url,
    )


def _parse_legacy(raw: object, context: str) -> LegacyBlock:
    if not isinstance(raw, dict) or set(raw) != _LEGACY_FIELDS:
        raise _reject(f"{context}: legacy block must carry exactly {sorted(_LEGACY_FIELDS)}")
    for key in ("tactic", "technique", "technique_id"):
        if not isinstance(raw[key], str) or not raw[key]:
            raise _reject(f"{context}: legacy {key} must be a non-empty string")
    if raw["confidence"] not in _CONFIDENCES:
        raise _reject(f"{context}: unknown legacy confidence {raw['confidence']!r}")
    return LegacyBlock(
        tactic=raw["tactic"],
        technique=raw["technique"],
        technique_id=raw["technique_id"],
        confidence=raw["confidence"],
        evidence=_string_list(raw["evidence"], f"{context} legacy evidence"),
        investigation=_string_list(raw["investigation"], f"{context} legacy investigation"),
    )


def parse_store(document: object, *, corpus: Corpus) -> RuleStore:
    """Validate one parsed ruleset document fail-closed; return the store."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise _reject(f"top level must carry exactly {sorted(_TOP_FIELDS)}")
    if document["schema"] != 1:
        raise _reject(f"unsupported schema: {document['schema']!r}")
    raw_rules = document["rules"]
    if not isinstance(raw_rules, list) or not raw_rules or len(raw_rules) > MAX_RULES:
        raise _reject(f"rules must be a list of 1..{MAX_RULES} entries")

    rules: list[MappingRule] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_rules):
        context = f"rule[{index}]"
        if not isinstance(raw, dict) or not _RULE_FIELDS <= set(raw) <= _RULE_FIELDS_WITH_LEGACY:
            raise _reject(f"{context}: unexpected field set")
        rule_id = raw["id"]
        if not isinstance(rule_id, str) or not rule_id or rule_id in seen_ids:
            raise _reject(f"{context}: id must be a unique non-empty string")
        seen_ids.add(rule_id)
        context = f"rule {rule_id!r}"
        if not isinstance(raw["description"], str) or not raw["description"]:
            raise _reject(f"{context}: description is required")
        raw_when = raw["when"]
        if not isinstance(raw_when, list) or not raw_when or len(raw_when) > MAX_CLAUSES_PER_RULE:
            raise _reject(f"{context}: when must be 1..{MAX_CLAUSES_PER_RULE} clauses")
        clauses = tuple(_parse_clause(clause, context) for clause in raw_when)
        raw_techniques = raw["techniques"]
        if not isinstance(raw_techniques, list) or len(raw_techniques) > MAX_TECHNIQUES_PER_RULE:
            raise _reject(f"{context}: techniques must be a list of <= {MAX_TECHNIQUES_PER_RULE}")
        techniques = tuple(_parse_technique(entry, context, corpus) for entry in raw_techniques)
        legacy_raw = raw.get("legacy")
        if techniques and legacy_raw is not None:
            raise _reject(f"{context}: a rule carries techniques OR a legacy block, never both")
        if not techniques and legacy_raw is None:
            raise _reject(f"{context}: a rule with no techniques must carry a legacy block")
        legacy = _parse_legacy(legacy_raw, context) if legacy_raw is not None else None
        rules.append(
            MappingRule(
                rule_id=rule_id,
                description=raw["description"],
                when=clauses,
                techniques=techniques,
                legacy=legacy,
            )
        )

    fallback = _parse_legacy(document["fallback"], "fallback")
    return RuleStore(rules=tuple(rules), fallback=fallback, attack_version=corpus.attack_version)


def load_store(rules_dir: Path | None = None, *, corpus: Corpus | None = None) -> RuleStore:
    """Load and validate every ruleset file (sorted, deterministic order).

    Multiple files concatenate their ``rules`` in filename order; exactly one
    file must declare the ``fallback``. Whole-store rejection on any anomaly.
    """
    directory = RULES_DIR if rules_dir is None else rules_dir
    resolved_corpus = load_corpus() if corpus is None else corpus
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise _reject(f"no ruleset files under {directory}")
    if len(paths) == 1:
        raw = paths[0].read_bytes()
        if len(raw) > MAX_STORE_BYTES:
            raise _reject(f"{paths[0].name} exceeds {MAX_STORE_BYTES} bytes")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise _reject(f"{paths[0].name} is not valid JSON ({exc})") from exc
        return parse_store(document, corpus=resolved_corpus)
    # Multi-file: merge rules in filename order; exactly one fallback.
    merged_rules: list[object] = []
    fallback: object | None = None
    for path in paths:
        raw = path.read_bytes()
        if len(raw) > MAX_STORE_BYTES:
            raise _reject(f"{path.name} exceeds {MAX_STORE_BYTES} bytes")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise _reject(f"{path.name} is not valid JSON ({exc})") from exc
        if not isinstance(document, dict):
            raise _reject(f"{path.name}: top level must be an object")
        merged_rules.extend(document.get("rules", []))
        if "fallback" in document:
            if fallback is not None:
                raise _reject("multiple ruleset files declare a fallback")
            fallback = document["fallback"]
    if fallback is None:
        raise _reject("no ruleset file declares the fallback")
    return parse_store(
        {"schema": 1, "rules": merged_rules, "fallback": fallback}, corpus=resolved_corpus
    )
