"""Minimal deterministic evaluator for the base-rule Sigma subset used here.

Enough of the Sigma detection grammar to *replay* this repository's base rules
against fixture events in CI (detection-as-code: every rule ships with
known-good/known-bad fixtures and a regression fails the build). This is NOT a
general Sigma engine — it supports exactly the field/modifier subset the local
corpus uses, and raises on anything outside it rather than guessing (fail
closed, so an unsupported construct can never silently pass a rule).

Supported per selection:
    <field>|contains         : substring match (any of a list)
    <field>|contains|all     : substring match (all of a list)
    <field>|startswith       : prefix match
    <field>                  : exact match (string equality)
Condition grammar:
    ``<term> and <term> and not <term>`` where each term is a selection name
    or ``1 of selection_*`` / ``all of selection_*`` wildcards.

Correlation rules (which chain base rules over time) are validated for
*structure* by tests/test_detections.py and executed by the SOC sequence
correlator, not here — this module scores single events against base rules.
"""

from __future__ import annotations

import re
from typing import Any

_SUPPORTED_MODIFIERS = {"contains", "startswith", "contains|all"}


def _field_value(event: dict[str, Any], field: str) -> str:
    """Return the event's value for ``field`` as a lowercased string.

    Events are flat dicts; a missing field is the empty string (no match),
    never an error, so a rule referencing an absent field simply does not fire.
    """
    return str(event.get(field, "")).lower()


def _match_field(event: dict[str, Any], key: str, spec: Any) -> bool:
    """Evaluate a single ``field[|modifier]`` clause against the event."""
    parts = key.split("|")
    field = parts[0]
    modifier = "|".join(parts[1:])
    value = _field_value(event, field)

    if modifier == "":
        return value == str(spec).lower()
    if modifier == "contains":
        needles = spec if isinstance(spec, list) else [spec]
        return any(str(n).lower() in value for n in needles)
    if modifier == "contains|all":
        needles = spec if isinstance(spec, list) else [spec]
        return all(str(n).lower() in value for n in needles)
    if modifier == "startswith":
        needles = spec if isinstance(spec, list) else [spec]
        return any(value.startswith(str(n).lower()) for n in needles)
    raise ValueError(f"unsupported Sigma field modifier: {key!r}")


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    """A selection matches when ALL of its field clauses match (Sigma AND)."""
    if not isinstance(selection, dict):
        raise ValueError(f"selection must be a mapping, got {type(selection).__name__}")
    return all(_match_field(event, key, spec) for key, spec in selection.items())


def _resolve_term(term: str, matched: dict[str, bool]) -> bool:
    """Resolve a single condition term to a boolean."""
    term = term.strip()
    m = re.fullmatch(r"(1|all) of (\w+)\*", term)
    if m:
        quantifier, prefix = m.group(1), m.group(2)
        hits = [v for name, v in matched.items() if name.startswith(prefix)]
        if not hits:
            raise ValueError(f"condition wildcard matched no selections: {term!r}")
        return any(hits) if quantifier == "1" else all(hits)
    if term not in matched:
        raise ValueError(f"condition references unknown selection: {term!r}")
    return matched[term]


def evaluate(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return True if ``event`` triggers the base Sigma ``rule``.

    Raises ``ValueError`` on any unsupported construct — the harness must never
    report a false pass because it silently skipped a clause it did not grasp.
    """
    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError("rule has no detection/condition (correlation rule?)")
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise ValueError("only string conditions are supported")

    matched = {
        name: _match_selection(event, sel) for name, sel in detection.items() if name != "condition"
    }

    # Tokenize the flat AND/NOT grammar the local corpus uses.
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    # Reconstruct into terms, honoring "1 of sel_*" / "all of sel_*" phrases.
    result: bool | None = None
    op: str | None = None
    negate = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if low == "and":
            op = "and"
        elif low == "or":
            op = "or"
        elif low == "not":
            negate = True
        elif low in ("(", ")"):
            pass
        elif low in ("1", "all") and i + 2 < len(tokens) and tokens[i + 1].lower() == "of":
            term = f"{tok} of {tokens[i + 2]}"
            value = _resolve_term(term, matched)
            value = (not value) if negate else value
            result = (
                value if result is None else (result and value if op == "and" else result or value)
            )
            negate = False
            i += 2
        else:
            value = _resolve_term(tok, matched)
            value = (not value) if negate else value
            result = (
                value if result is None else (result and value if op == "and" else result or value)
            )
            negate = False
        i += 1

    if result is None:
        raise ValueError(f"could not evaluate condition: {condition!r}")
    return result
