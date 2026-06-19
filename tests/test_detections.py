"""Structural validation of the Sigma detection rules in detections/sigma/.

Guards the detection content: every rule must parse, carry the required Sigma
fields, declare a valid unique UUID, and reference a MITRE ATT&CK technique tag —
so the corpus stays usable and aligned with the agents' MITRE mappings.
"""

import re
import uuid
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SIGMA_DIR = _REPO_ROOT / "detections" / "sigma"
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")

_RULE_FILES = sorted(_SIGMA_DIR.glob("*.yml")) if _SIGMA_DIR.is_dir() else []


@pytest.mark.security
@pytest.mark.skipif(not _RULE_FILES, reason="no Sigma rules present")
def test_sigma_rules_present() -> None:
    assert _RULE_FILES, "expected at least one Sigma rule in detections/sigma/"


@pytest.mark.security
@pytest.mark.parametrize("rule_path", _RULE_FILES, ids=lambda p: p.name)
def test_sigma_rule_is_structurally_valid(rule_path: Path) -> None:
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    assert isinstance(rule, dict), f"{rule_path.name} is not a YAML mapping"

    # Required Sigma fields.
    for key in ("title", "id", "description", "logsource", "detection", "level"):
        assert key in rule, f"{rule_path.name} missing required field '{key}'"

    # Valid UUID id.
    assert str(uuid.UUID(str(rule["id"]))) == str(rule["id"]), f"{rule_path.name} id not a UUID"

    # detection must define a condition.
    assert "condition" in rule["detection"], f"{rule_path.name} detection has no condition"

    # level must be a recognized Sigma severity.
    assert rule["level"] in _VALID_LEVELS, f"{rule_path.name} has invalid level {rule['level']!r}"

    # At least one MITRE ATT&CK technique tag (keeps detections aligned with agents).
    tags = rule.get("tags", [])
    assert any(_TECHNIQUE_TAG.match(str(t)) for t in tags), (
        f"{rule_path.name} has no attack.tXXXX technique tag"
    )


@pytest.mark.security
@pytest.mark.skipif(not _RULE_FILES, reason="no Sigma rules present")
def test_sigma_rule_ids_are_unique() -> None:
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in _RULE_FILES]
    assert len(ids) == len(set(ids)), "duplicate Sigma rule ids detected"
