"""The ruleset drift gate: canonicalized, so formatting churn cannot flake it."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "check_mapping_rules", _REPO / "scripts" / "check_mapping_rules.py"
)
assert _SPEC and _SPEC.loader
_gate = importlib.util.module_from_spec(_SPEC)
sys.modules["check_mapping_rules"] = _gate
_SPEC.loader.exec_module(_gate)

_RULES = _REPO / "agents" / "mapping" / "rules" / "core.json"


@pytest.mark.security
def test_committed_digest_is_in_sync() -> None:
    assert _gate.main(["--check"]) == 0


@pytest.mark.security
def test_whitespace_reformat_leaves_digest_unchanged(tmp_path: Path) -> None:
    before = _gate.compute_digest()
    original = _RULES.read_bytes()
    try:
        document = json.loads(original)
        _RULES.write_text(json.dumps(document, indent=4) + "\n\n", encoding="utf-8")
        assert _gate.compute_digest() == before
    finally:
        _RULES.write_bytes(original)


@pytest.mark.security
def test_semantic_edit_fails_the_gate() -> None:
    before = _gate.compute_digest()
    original = _RULES.read_bytes()
    try:
        document = json.loads(original)
        document["rules"][0]["techniques"][0]["confidence"] = "high"
        _RULES.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        assert _gate.compute_digest() != before
        assert _gate.main(["--check"]) == 1
    finally:
        _RULES.write_bytes(original)
