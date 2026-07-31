"""Detection-as-code: replay every base Sigma rule against fixtures.

Each base rule in ``detections/sigma/`` must have a fixtures entry with
``should_fire`` and ``should_not_fire`` events, and the deterministic evaluator
must agree with every one. A rule whose logic regresses (or a new base rule
added without fixtures) fails the build — the practice the detection-engineering
field is converging on, implemented locally with zero cloud dependency.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from agents.tools.sigma_eval import evaluate

_REPO = Path(__file__).resolve().parents[1]
_SIGMA = _REPO / "detections" / "sigma"
_FIXTURES = _REPO / "detections" / "fixtures" / "base_rule_fixtures.json"


def _base_rules() -> dict[str, dict]:
    rules: dict[str, dict] = {}
    for path in sorted(_SIGMA.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "correlation" in rule:
            continue  # correlation rules are executed by the sequence correlator
        rules[rule.get("name", path.stem)] = rule
    return rules


def _fixtures() -> dict[str, dict]:
    data = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


@pytest.mark.unit
def test_every_base_rule_has_fixtures() -> None:
    rules = set(_base_rules())
    fixtures = set(_fixtures())
    missing = rules - fixtures
    assert not missing, f"base rules without replay fixtures: {sorted(missing)}"


@pytest.mark.unit
def test_no_orphan_fixtures() -> None:
    # A fixtures entry with no matching base rule is dead weight / a typo.
    orphans = set(_fixtures()) - set(_base_rules())
    assert not orphans, f"fixtures with no matching base rule: {sorted(orphans)}"


@pytest.mark.unit
def test_base_rules_fire_on_known_good_events() -> None:
    rules = _base_rules()
    for name, fx in _fixtures().items():
        rule = rules[name]
        for event in fx["should_fire"]:
            assert evaluate(rule, event), f"{name} did not fire on {event}"


@pytest.mark.unit
def test_base_rules_silent_on_known_bad_events() -> None:
    rules = _base_rules()
    for name, fx in _fixtures().items():
        rule = rules[name]
        for event in fx["should_not_fire"]:
            assert not evaluate(rule, event), f"{name} wrongly fired on {event}"


@pytest.mark.unit
def test_evaluator_rejects_unsupported_modifier() -> None:
    bad_rule = {"detection": {"selection": {"message|regex": "x"}, "condition": "selection"}}
    with pytest.raises(ValueError):
        evaluate(bad_rule, {"message": "x"})


@pytest.mark.unit
def test_evaluator_rejects_correlation_rule() -> None:
    corr = {"correlation": {"type": "event_count"}}
    with pytest.raises(ValueError):
        evaluate(corr, {"message": "x"})
