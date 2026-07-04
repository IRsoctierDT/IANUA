"""Property-based fuzzing of tool input validators (HARDENING_ROADMAP #3).

Uses Hypothesis to assert invariants over generated inputs rather than only the
hand-written examples. Runs deterministically in CI (``derandomize=True``) so any
counterexample reproduces; found counterexamples are pinned with ``@example``.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import get_args

import pytest
from agents.policies import PolicyEngine, classify_action
from agents.policies.approval import ActionClass, Decision
from agents.tools.validation import ValidationError, resolve_within
from hypothesis import example, given, settings
from hypothesis import strategies as st

# Deterministic, CI-friendly profile.
_FUZZ = settings(max_examples=250, derandomize=True, deadline=None)

# A single trusted root reused across generated examples (see resolve_within).
_BASE = Path(tempfile.mkdtemp(prefix="fuzz-root-")).resolve()

_VALID_CLASSES: frozenset[str] = frozenset(get_args(ActionClass))
_VALID_DECISIONS: frozenset[str] = frozenset(get_args(Decision))


@pytest.mark.security
@_FUZZ
@given(candidate=st.text(max_size=512))
@example(candidate="\x00")  # NUL byte must be rejected, not crash
@example(candidate="../../etc/passwd")  # classic traversal must be rejected
@example(candidate="a" * 5000)  # oversized must be rejected
def test_resolve_within_confines_or_rejects(candidate: str) -> None:
    """resolve_within either returns a path inside base, or raises ValidationError.

    No other exception type may escape — that is the invariant the fuzzer proves.
    """
    try:
        result = resolve_within(_BASE, candidate)
    except ValidationError:
        return  # rejecting hostile input is a valid outcome
    assert result == _BASE or _BASE in result.parents


@pytest.mark.security
@_FUZZ
@given(text=st.text())
def test_classify_action_is_total_and_valid(text: str) -> None:
    """classify_action returns a valid ActionClass for any string, never raises."""
    assert classify_action(text) in _VALID_CLASSES


@pytest.mark.security
@_FUZZ
@given(text=st.text(min_size=1).filter(lambda s: s.strip() != ""))
def test_policy_evaluate_returns_valid_decision(text: str) -> None:
    """Any non-blank action evaluates to a structured, valid decision."""
    decision = PolicyEngine().evaluate(text)
    assert decision.decision in _VALID_DECISIONS
    assert decision.action_class in _VALID_CLASSES
    assert isinstance(decision.requires_human, bool)


@pytest.mark.security
@_FUZZ
@given(blank=st.text(alphabet=" \t\n\r\f\v", max_size=8))
def test_policy_evaluate_rejects_blank(blank: str) -> None:
    """Empty/whitespace-only actions fail closed with a ValueError."""
    with pytest.raises(ValueError):
        PolicyEngine().evaluate(blank)
