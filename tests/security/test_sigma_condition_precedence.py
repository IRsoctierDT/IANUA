"""Sigma condition parsing: precedence and parentheses are load-bearing.

The evaluator previously discarded parentheses and folded operators strictly
left-to-right, which silently inverted ``filter``-style false-positive
suppressions: ``a and not (f1 or f2)`` returned True on an event matching
``a`` and ``f2``. Every test here pins the corrected, fail-closed grammar so a
parser regression can never make a suppression clause inert again.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from agents.tools.sigma_eval import evaluate

_REPO = Path(__file__).resolve().parents[2]
_SIGMA = _REPO / "detections" / "sigma"


def _rule(condition: str, **selections: dict) -> dict:
    return {"detection": {"condition": condition, **selections}}


_A = {"message|contains": "alpha"}
_F1 = {"message|contains": "friendly-one"}
_F2 = {"message|contains": "friendly-two"}


@pytest.mark.security
def test_not_over_parenthesized_or_suppresses() -> None:
    # The filter-suppression shape: fires on the signal unless EITHER
    # false-positive marker is present. The old left-fold returned True here.
    rule = _rule("a and not (f1 or f2)", a=_A, f1=_F1, f2=_F2)
    assert evaluate(rule, {"message": "alpha friendly-two"}) is False
    assert evaluate(rule, {"message": "alpha friendly-one"}) is False
    assert evaluate(rule, {"message": "alpha benign"}) is True


@pytest.mark.security
def test_and_binds_tighter_than_or() -> None:
    # a or (f1 and f2) — standard precedence with no parens in the condition.
    rule = _rule("a or f1 and f2", a=_A, f1=_F1, f2=_F2)
    assert evaluate(rule, {"message": "alpha"}) is True
    assert evaluate(rule, {"message": "friendly-one friendly-two"}) is True
    assert evaluate(rule, {"message": "friendly-one"}) is False


@pytest.mark.security
def test_parenthesized_group_with_partial_match() -> None:
    # a and (b or c) with only c matching alongside a: True. With neither: False.
    rule = _rule("a and (f1 or f2)", a=_A, f1=_F1, f2=_F2)
    assert evaluate(rule, {"message": "alpha friendly-two"}) is True
    assert evaluate(rule, {"message": "alpha"}) is False


@pytest.mark.security
def test_not_applies_to_quantifier_group() -> None:
    rule = _rule("a and not 1 of f_*", a=_A, f_one=_F1, f_two=_F2)
    assert evaluate(rule, {"message": "alpha friendly-one"}) is False
    assert evaluate(rule, {"message": "alpha clean"}) is True


@pytest.mark.security
def test_unbalanced_parentheses_raise() -> None:
    for condition in ("a and (f1 or f2", "a and f1)", "(a", ")a("):
        rule = _rule(condition, a=_A, f1=_F1, f2=_F2)
        with pytest.raises(ValueError):
            evaluate(rule, {"message": "alpha"})


@pytest.mark.security
def test_unknown_selection_raises_even_when_outcome_already_known() -> None:
    # No short-circuit that hides validation: 'a or ghost' must raise even
    # though the left side already matched.
    rule = _rule("a or ghost", a=_A)
    with pytest.raises(ValueError, match="unknown selection"):
        evaluate(rule, {"message": "alpha"})


@pytest.mark.security
def test_every_corpus_base_rule_still_evaluates() -> None:
    # The stricter grammar must not orphan any committed rule.
    for path in sorted(_SIGMA.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "correlation" in rule:
            continue
        evaluate(rule, {"message": "probe event"})  # must not raise
