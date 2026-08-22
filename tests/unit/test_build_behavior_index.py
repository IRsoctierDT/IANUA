"""Contracts for the behavioral index builder and its reference gate.

The builder is where behavioral content meets the pinned ATT&CK corpus: a
rule anchored to a technique a later release revokes or deprecates must fail
the build with the successor named, which is what stops the corpus rotting
silently. It is also where the honesty markers are enforced — every rule
declares whether the telemetry it needs is actually ingested, and every rule
states at least one false-positive source.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "build_behavior_index", _REPO / "scripts" / "build_behavior_index.py"
)
assert _SPEC and _SPEC.loader
_bbi = importlib.util.module_from_spec(_SPEC)
sys.modules["build_behavior_index"] = _bbi
_SPEC.loader.exec_module(_bbi)

_BEHAVIORS = _REPO / "detections" / "behaviors"


def _workdir(tmp_path: Path) -> Path:
    work = tmp_path / "behaviors"
    shutil.copytree(_BEHAVIORS, work)
    return work


def _mutate(work: Path, filename: str, mutate: Callable[[dict], None]) -> None:
    path = work / filename
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(rule)
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")


@pytest.mark.unit
def test_committed_index_is_in_sync() -> None:
    assert _bbi.main(["--check"]) == 0


@pytest.mark.unit
def test_index_shape_and_stamping() -> None:
    index = _bbi.build_index()
    assert index["schema"] == 1
    assert index["attack_version"], "index must stamp the pinned ATT&CK version"
    assert index["behaviors"], "index must carry rules"
    for entry in index["behaviors"]:
        assert entry["techniques"], f"{entry['name']}: no techniques"
        assert entry["validation"] in {"telemetry-available", "telemetry-required"}
        assert entry["false_positives"], f"{entry['name']}: no false positives"


@pytest.mark.unit
def test_render_is_deterministic() -> None:
    assert _bbi.render(_bbi.build_index()) == _bbi.render(_bbi.build_index())


_MUTATIONS: list[tuple[str, Callable[[dict], None]]] = [
    ("missing validation marker", lambda r: r.pop("validation")),
    ("unknown validation marker", lambda r: r.update(validation="works-on-my-machine")),
    ("missing falsepositives", lambda r: r.pop("falsepositives")),
    ("empty falsepositives", lambda r: r.update(falsepositives=[])),
    ("invalid level", lambda r: r.update(level="catastrophic")),
    ("non-uuid id", lambda r: r.update(id="not-a-uuid")),
    ("no technique tag", lambda r: r.update(tags=["attack.stealth"])),
    ("missing detection", lambda r: r.pop("detection")),
    ("detection without condition", lambda r: r.update(detection={"selection": {"a": "b"}})),
    ("missing title", lambda r: r.pop("title")),
]


@pytest.mark.unit
@pytest.mark.parametrize(("label", "mutate"), _MUTATIONS, ids=[m[0] for m in _MUTATIONS])
def test_malformed_rule_rejects_corpus(
    label: str, mutate: Callable[[dict], None], tmp_path: Path
) -> None:
    work = _workdir(tmp_path)
    _mutate(work, "auditd_stopped.yml", mutate)
    with pytest.raises(_bbi.BehaviorCorpusError):
        _bbi.build_index(work)


@pytest.mark.unit
def test_revoked_technique_anchor_fails_with_successor(tmp_path: Path) -> None:
    # T1562.001 was revoked in ATT&CK 19 (superseded by T1685). A behavioral
    # rule anchored to it must not merge, and the error must name where to go.
    work = _workdir(tmp_path)
    _mutate(
        work,
        "auditd_stopped.yml",
        lambda r: r.update(tags=["attack.defense-impairment", "attack.t1562.001"]),
    )
    with pytest.raises(_bbi.BehaviorCorpusError, match="revoked"):
        _bbi.build_index(work)


@pytest.mark.unit
def test_unknown_technique_anchor_fails(tmp_path: Path) -> None:
    work = _workdir(tmp_path)
    _mutate(work, "auditd_stopped.yml", lambda r: r.update(tags=["attack.t9999"]))
    with pytest.raises(_bbi.BehaviorCorpusError, match="does not exist"):
        _bbi.build_index(work)


@pytest.mark.unit
def test_duplicate_name_and_id_rejected(tmp_path: Path) -> None:
    work = _workdir(tmp_path)
    source = yaml.safe_load((work / "auditd_stopped.yml").read_text(encoding="utf-8"))
    (work / "zz_duplicate.yml").write_text(yaml.safe_dump(source), encoding="utf-8")
    with pytest.raises(_bbi.BehaviorCorpusError, match="duplicate"):
        _bbi.build_index(work)


@pytest.mark.unit
def test_empty_corpus_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(_bbi.BehaviorCorpusError, match="no behavioral rules"):
        _bbi.build_index(empty)


@pytest.mark.unit
def test_index_matches_the_yaml_corpus() -> None:
    """The committed projection must describe the committed YAML exactly."""
    committed: dict[str, Any] = json.loads(
        (_REPO / "detections" / "behaviors.index.json").read_text(encoding="utf-8")
    )
    names = {entry["name"] for entry in committed["behaviors"]}
    on_disk = {
        str(yaml.safe_load(path.read_text(encoding="utf-8"))["name"])
        for path in _BEHAVIORS.glob("*.yml")
    }
    assert names == on_disk
