"""Minimal deterministic evaluator for the base-rule Sigma subset used here.

Enough of the Sigma detection grammar to *replay* this repository's base rules
against fixture events in CI (detection-as-code: every rule ships with
known-good/known-bad fixtures and a regression fails the build). This is NOT a
general Sigma engine — it supports exactly the field/modifier subset the local
corpus uses, and raises on anything outside it rather than guessing (fail
closed, so an unsupported construct can never silently pass a rule).

Supported per selection (the keys of ``_SUPPORTED_MODIFIERS``, which drives
dispatch — an unlisted modifier raises):
    <field>                  : exact match (string equality)
    <field>|contains         : substring match (any of a list)
    <field>|contains|all     : substring match (all of a list)
    <field>|startswith       : prefix match
Condition grammar (recursive descent, standard precedence not > and > or,
with parenthesized grouping):
    expr     := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | primary
    primary  := "(" expr ")" | quantifier | selection-name
    quantifier := ("all" | <N>) "of" <prefix>*
Unbalanced parentheses, unknown selections, quantifiers whose wildcard matches
nothing (or that require more selections than exist), and trailing tokens all
raise — a malformed condition must never silently evaluate.

Security consideration: a ``filter``-style suppression (``... and not
(filter_a or filter_b)``) depends on parenthesized precedence being honored;
this evaluator parses it properly rather than folding tokens left-to-right,
so a false-positive filter can never be silently inert.

Correlation rules (which chain base rules over time) are validated for
*structure* by tests/test_detections.py and executed by the SOC sequence
correlator, not here — this module scores single events against base rules.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


def _match_exact(value: str, spec: Any) -> bool:
    return value == str(spec).lower()


def _match_contains(value: str, spec: Any) -> bool:
    needles = spec if isinstance(spec, list) else [spec]
    return any(str(n).lower() in value for n in needles)


def _match_contains_all(value: str, spec: Any) -> bool:
    needles = spec if isinstance(spec, list) else [spec]
    return all(str(n).lower() in value for n in needles)


def _match_startswith(value: str, spec: Any) -> bool:
    needles = spec if isinstance(spec, list) else [spec]
    return any(value.startswith(str(n).lower()) for n in needles)


def _match_endswith(value: str, spec: Any) -> bool:
    """``field|endswith`` — the dominant modifier in endpoint Sigma content.

    Almost every published process rule is written as ``Image|endswith:
    '\\cmd.exe'``, so a corpus written against real endpoint telemetry needs
    it. It was previously absent, which meant such a rule raised rather than
    matching — loud, but still unusable.
    """
    needles = spec if isinstance(spec, list) else [spec]
    return any(value.endswith(str(n).lower()) for n in needles)


# Modifier -> matcher. This mapping IS the supported surface: _match_field
# dispatches through it, so adding a modifier here is the only way to enable
# one, and anything absent raises rather than silently not matching.
_SUPPORTED_MODIFIERS: dict[str, Callable[[str, Any], bool]] = {
    "": _match_exact,
    "contains": _match_contains,
    "contains|all": _match_contains_all,
    "startswith": _match_startswith,
    "endswith": _match_endswith,
}

_QUANTIFIER_TARGET = re.compile(r"(\w+)\*")


def _field_value(event: dict[str, Any], field: str) -> str:
    """Return the event's value for ``field`` as a lowercased string.

    Events are flat dicts; a missing field — or a field present with a null
    value — is the empty string (no match), never an error, so a rule
    referencing an absent field simply does not fire. Normalizing null here
    matters: stringifying ``None`` would yield the literal ``"none"``, and any
    rule matching that word would false-positive on every null field.
    """
    value = event.get(field)
    return "" if value is None else str(value).lower()


def _match_field(event: dict[str, Any], key: str, spec: Any) -> bool:
    """Evaluate a single ``field[|modifier]`` clause against the event."""
    parts = key.split("|")
    field = parts[0]
    modifier = "|".join(parts[1:])
    matcher = _SUPPORTED_MODIFIERS.get(modifier)
    if matcher is None:
        raise ValueError(f"unsupported Sigma field modifier: {key!r}")
    return matcher(_field_value(event, field), spec)


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    """A selection matches when ALL of its field clauses match (Sigma AND)."""
    if not isinstance(selection, dict):
        raise ValueError(f"selection must be a mapping, got {type(selection).__name__}")
    return all(_match_field(event, key, spec) for key, spec in selection.items())


def _resolve_quantifier(quantifier: str, pattern: str, matched: dict[str, bool]) -> bool:
    """Resolve ``<quantifier> of <prefix>*`` against the matched selections.

    ``quantifier`` is ``"all"`` or a positive integer literal. Fail closed on
    authoring errors: a wildcard matching no selections, or a numeric
    quantifier larger than the number of selections it could ever count,
    describes a rule that can never fire and raises rather than silently
    evaluating False forever.
    """
    m = _QUANTIFIER_TARGET.fullmatch(pattern)
    if m is None:
        raise ValueError(f"unsupported quantifier target: {pattern!r}")
    prefix = m.group(1)
    hits = [value for name, value in matched.items() if name.startswith(prefix)]
    term = f"{quantifier} of {pattern}"
    if not hits:
        raise ValueError(f"condition wildcard matched no selections: {term!r}")
    if quantifier == "all":
        return all(hits)
    needed = int(quantifier)
    if needed < 1:
        raise ValueError(f"quantifier must be positive: {term!r}")
    if needed > len(hits):
        raise ValueError(
            f"quantifier requires {needed} selections but only {len(hits)} match: {term!r}"
        )
    return sum(hits) >= needed


def _resolve_name(name: str, matched: dict[str, bool]) -> bool:
    """Resolve a bare selection-name term."""
    if name not in matched:
        raise ValueError(f"condition references unknown selection: {name!r}")
    return matched[name]


def _parse_condition(tokens: list[str], matched: dict[str, bool]) -> bool:
    """Recursive-descent evaluation with not > and > or precedence and parens.

    Both operands of ``and``/``or`` are always evaluated (no short-circuit),
    so every referenced selection is validated even when the outcome is
    already determined — an unknown name on the right of an ``or`` still
    raises instead of hiding until the left side is False.
    """
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or() -> bool:
        value = parse_and()
        while (tok := peek()) is not None and tok.lower() == "or":
            take()
            rhs = parse_and()
            value = value or rhs
        return value

    def parse_and() -> bool:
        value = parse_not()
        while (tok := peek()) is not None and tok.lower() == "and":
            take()
            rhs = parse_not()
            value = value and rhs
        return value

    def parse_not() -> bool:
        if (tok := peek()) is not None and tok.lower() == "not":
            take()
            return not parse_not()
        return parse_primary()

    def parse_primary() -> bool:
        tok = peek()
        if tok is None:
            raise ValueError("condition ended unexpectedly")
        if tok == "(":
            take()
            value = parse_or()
            if peek() != ")":
                raise ValueError("unbalanced parentheses in condition")
            take()
            return value
        if tok == ")":
            raise ValueError("unbalanced parentheses in condition")
        take()
        low = tok.lower()
        next_tok = peek()
        if (low == "all" or low.isdigit()) and next_tok is not None and next_tok.lower() == "of":
            take()
            target = peek()
            if target is None:
                raise ValueError(f"quantifier missing selection pattern: {tok!r}")
            take()
            return _resolve_quantifier(low, target, matched)
        return _resolve_name(tok, matched)

    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"unexpected tok in condition: {tokens[pos]!r}")
    return result


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

    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens:
        raise ValueError(f"could not evaluate condition: {condition!r}")
    return _parse_condition(tokens, matched)
