"""Detection-as-code: replay every behavioral rule against its fixtures.

The post-compromise corpus in ``detections/behaviors/`` is held to the same
bar as the base Sigma corpus: every rule ships known-good and known-bad
events, and the deterministic evaluator must agree with all of them. A rule
that stops firing — or starts firing on its own negative cases — fails the
build.

The negatives matter more here than anywhere else in the repo. Behavioral
rules key on ordinary administrative tooling (``systemctl``, ``crontab``,
``certutil``), so each rule carries deliberate near-misses proving its
AND-clauses and filters actually discriminate. Those filters only work
because the evaluator honors parentheses and precedence — before that fix
every ``filter`` selection was silently inert, which is exactly the class of
bug this suite exists to catch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from agents.tools.sigma_eval import evaluate

_REPO = Path(__file__).resolve().parents[1]
_BEHAVIORS = _REPO / "detections" / "behaviors"
_FIXTURES = _REPO / "detections" / "fixtures" / "behavior_fixtures.json"

#: Minimum negatives per rule. Behavioral detections fire on administrative
#: activity; one negative proves nothing about discrimination.
_MIN_NEGATIVES = 3


def _rules() -> dict[str, dict]:
    rules: dict[str, dict] = {}
    for path in sorted(_BEHAVIORS.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules[str(rule["name"])] = rule
    return rules


def _fixtures() -> dict[str, dict]:
    data = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


_RULE_NAMES = sorted(_rules())


@pytest.mark.unit
def test_behavioral_rules_present() -> None:
    assert _RULE_NAMES, "expected at least one behavioral rule"


@pytest.mark.unit
def test_every_behavioral_rule_has_fixtures() -> None:
    missing = set(_rules()) - set(_fixtures())
    assert not missing, f"behavioral rules without replay fixtures: {sorted(missing)}"


@pytest.mark.unit
def test_no_orphan_behavior_fixtures() -> None:
    orphans = set(_fixtures()) - set(_rules())
    assert not orphans, f"fixtures with no matching behavioral rule: {sorted(orphans)}"


@pytest.mark.unit
@pytest.mark.parametrize("name", _RULE_NAMES)
def test_rule_fires_on_known_good_events(name: str) -> None:
    rule = _rules()[name]
    events = _fixtures()[name]["should_fire"]
    assert events, f"{name}: needs at least one should_fire event"
    for event in events:
        assert evaluate(rule, event), f"{name} did not fire on {event}"


@pytest.mark.unit
@pytest.mark.parametrize("name", _RULE_NAMES)
def test_rule_stays_silent_on_known_bad_events(name: str) -> None:
    rule = _rules()[name]
    events = _fixtures()[name]["should_not_fire"]
    assert len(events) >= _MIN_NEGATIVES, (
        f"{name}: needs at least {_MIN_NEGATIVES} should_not_fire events — behavioral "
        "rules fire on administrative activity and must prove they discriminate"
    )
    for event in events:
        assert not evaluate(rule, event), f"{name} false-positived on {event}"
