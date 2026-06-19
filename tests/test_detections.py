"""Structural validation of the Sigma detection rules in detections/sigma/.

Guards the detection content: every rule must parse, carry the required Sigma
fields, declare a valid unique UUID, and reference a MITRE ATT&CK technique tag.
Correlation rules must additionally reference base rules that actually exist — so
the corpus stays usable and internally consistent.
"""

import re
import uuid
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SIGMA_DIR = _REPO_ROOT / "detections" / "sigma"
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_CORRELATION_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")

_RULE_FILES = sorted(_SIGMA_DIR.glob("*.yml")) if _SIGMA_DIR.is_dir() else []


def _load(path: Path) -> dict:
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(rule, dict), f"{path.name} is not a YAML mapping"
    return rule


def _all_rule_names() -> set[str]:
    names: set[str] = set()
    for path in _RULE_FILES:
        rule = _load(path)
        if "name" in rule:
            names.add(str(rule["name"]))
    return names


@pytest.mark.security
@pytest.mark.skipif(not _RULE_FILES, reason="no Sigma rules present")
def test_sigma_rules_present() -> None:
    assert _RULE_FILES, "expected at least one Sigma rule in detections/sigma/"


@pytest.mark.security
@pytest.mark.parametrize("rule_path", _RULE_FILES, ids=lambda p: p.name)
def test_sigma_rule_is_structurally_valid(rule_path: Path) -> None:
    rule = _load(rule_path)

    # Fields required of every Sigma rule.
    for key in ("title", "id", "description", "level"):
        assert key in rule, f"{rule_path.name} missing required field '{key}'"

    assert str(uuid.UUID(str(rule["id"]))) == str(rule["id"]), f"{rule_path.name} id not a UUID"
    assert rule["level"] in _VALID_LEVELS, f"{rule_path.name} invalid level {rule['level']!r}"

    tags = rule.get("tags", [])
    assert any(_TECHNIQUE_TAG.match(str(t)) for t in tags), (
        f"{rule_path.name} has no attack.tXXXX technique tag"
    )

    if "correlation" in rule:
        corr = rule["correlation"]
        assert corr.get("type") in _CORRELATION_TYPES, (
            f"{rule_path.name} invalid correlation type {corr.get('type')!r}"
        )
        referenced = corr.get("rules", [])
        assert referenced, f"{rule_path.name} correlation references no rules"
        known = _all_rule_names()
        for name in referenced:
            assert name in known, f"{rule_path.name} references unknown rule name {name!r}"
    else:
        # A plain detection rule.
        assert "logsource" in rule, f"{rule_path.name} missing logsource"
        assert "condition" in rule.get("detection", {}), (
            f"{rule_path.name} detection has no condition"
        )


@pytest.mark.security
@pytest.mark.skipif(not _RULE_FILES, reason="no Sigma rules present")
def test_sigma_rule_ids_are_unique() -> None:
    ids = [_load(p)["id"] for p in _RULE_FILES]
    assert len(ids) == len(set(ids)), "duplicate Sigma rule ids detected"
