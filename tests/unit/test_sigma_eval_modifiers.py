"""Unit contracts for the Sigma evaluator's field/modifier layer.

Pins the dispatch-through-``_SUPPORTED_MODIFIERS`` design (an unlisted
modifier raises), the null-field normalization (a present-but-None field can
never match the literal string "none"), and the ``N of prefix_*`` quantifier
including its fail-closed authoring-error cases.
"""

from __future__ import annotations

import pytest
from agents.tools.sigma_eval import _SUPPORTED_MODIFIERS, evaluate


def _rule(condition: str, **selections: dict) -> dict:
    return {"detection": {"condition": condition, **selections}}


@pytest.mark.unit
def test_supported_modifiers_is_load_bearing() -> None:
    # The constant drives dispatch: exactly these modifiers evaluate, and
    # anything else raises rather than silently not matching.
    assert set(_SUPPORTED_MODIFIERS) == {
        "",
        "contains",
        "contains|all",
        "startswith",
        "endswith",
    }
    rule = _rule("sel", sel={"message|re": "ssh2$"})
    with pytest.raises(ValueError, match="unsupported Sigma field modifier"):
        evaluate(rule, {"message": "Failed password ssh2"})


@pytest.mark.unit
def test_endswith_anchors_at_the_end_and_accepts_a_list() -> None:
    """The modifier endpoint Sigma content is overwhelmingly written against."""
    rule = _rule("sel", sel={"image|endswith": "\\cmd.exe"})
    assert evaluate(rule, {"image": "C:\\Windows\\System32\\cmd.exe"}) is True
    # Anchored: a match anywhere else must not fire.
    assert evaluate(rule, {"image": "C:\\cmd.exe.disguised.dll"}) is False
    listed = _rule("sel", sel={"image|endswith": ["\\powershell.exe", "\\cmd.exe"]})
    assert evaluate(listed, {"image": "C:\\Windows\\System32\\cmd.exe"}) is True
    assert evaluate(listed, {"image": "C:\\Windows\\explorer.exe"}) is False


@pytest.mark.unit
def test_null_field_is_absent_not_the_string_none() -> None:
    rule = _rule("sel", sel={"user|contains": "none"})
    assert evaluate(rule, {"user": None}) is False
    assert evaluate(rule, {"user": "nonexistent-acct"}) is True
    # Exact match on null likewise cannot fire.
    exact = _rule("sel", sel={"user": "none"})
    assert evaluate(exact, {"user": None}) is False


@pytest.mark.unit
def test_n_of_quantifier_counts_matches() -> None:
    sels = {
        "q_a": {"message|contains": "one"},
        "q_b": {"message|contains": "two"},
        "q_c": {"message|contains": "three"},
    }
    rule = _rule("2 of q_*", **sels)
    assert evaluate(rule, {"message": "one two"}) is True
    assert evaluate(rule, {"message": "one"}) is False
    assert evaluate(rule, {"message": "one two three"}) is True


@pytest.mark.unit
def test_quantifier_authoring_errors_fail_closed() -> None:
    sels = {"q_a": {"message|contains": "one"}}
    with pytest.raises(ValueError, match="matched no selections"):
        evaluate(_rule("1 of ghost_*", **sels), {"message": "one"})
    with pytest.raises(ValueError, match="requires 2 selections"):
        evaluate(_rule("2 of q_*", **sels), {"message": "one"})


@pytest.mark.unit
def test_trailing_tokens_raise() -> None:
    rule = _rule("sel sel", sel={"message|contains": "x"})
    with pytest.raises(ValueError):
        evaluate(rule, {"message": "x"})


@pytest.mark.unit
def test_exact_contains_all_and_startswith_still_match() -> None:
    rule = _rule(
        "s_exact and s_all and s_start",
        s_exact={"proto": "tcp"},
        s_all={"message|contains|all": ["alpha", "beta"]},
        s_start={"message|startswith": "alert"},
    )
    event = {"proto": "TCP", "message": "ALERT beta alpha"}
    assert evaluate(rule, event) is True
