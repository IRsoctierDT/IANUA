"""Contracts for the ATT&CK Navigator coverage-layer generator + drift gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "build_attack_navigator.py"
_LAYER = _REPO / "docs" / "attack-navigator-layer.json"

_spec = importlib.util.spec_from_file_location("build_attack_navigator", _SCRIPT)
assert _spec and _spec.loader
_nav = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_nav)


@pytest.mark.unit
def test_layer_is_valid_navigator_json() -> None:
    layer = _nav.build_layer()
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"], "no techniques in the layer"
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T")
        assert t["score"] >= 1


@pytest.mark.unit
def test_known_techniques_are_covered() -> None:
    ids = {t["techniqueID"] for t in _nav.build_layer()["techniques"]}
    # Techniques the corpus is known to tag (guards against regex regressions).
    for expected in ("T1110", "T1046", "T1070.003", "T1557.002"):
        assert expected in ids, f"{expected} missing from coverage layer"


@pytest.mark.unit
def test_committed_layer_is_in_sync() -> None:
    # Drift gate parity: the committed file must equal a fresh render.
    rendered = _nav.render(_nav.build_layer())
    assert _LAYER.read_text(encoding="utf-8") == rendered, (
        "docs/attack-navigator-layer.json is stale — run scripts/build_attack_navigator.py"
    )


@pytest.mark.unit
def test_output_is_deterministic() -> None:
    assert _nav.render(_nav.build_layer()) == _nav.render(_nav.build_layer())


@pytest.mark.unit
def test_malformed_tags_raise() -> None:
    with pytest.raises(ValueError):
        _nav._extract_techniques("attack.t1110")  # tags must be a list, not str


@pytest.mark.unit
def test_check_mode_passes_when_in_sync() -> None:
    assert _nav.main(["--check"]) == 0
