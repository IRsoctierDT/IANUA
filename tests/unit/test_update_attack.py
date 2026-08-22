"""Distiller contracts against a synthetic STIX fixture.

The fixture carries a nonzero count of every consumed object and relationship
type, so an upstream shape change (fields moving, relationship directions
flipping) fails loudly in _distill instead of silently emptying an index.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "update_attack_unit", _REPO / "scripts" / "update_attack.py"
)
assert _SPEC and _SPEC.loader
_upd = importlib.util.module_from_spec(_SPEC)
sys.modules["update_attack_unit"] = _upd
_SPEC.loader.exec_module(_upd)


def _obj(obj_type: str, obj_id: str, **fields: Any) -> dict[str, Any]:
    return {"type": obj_type, "id": f"{obj_type}--{obj_id}", **fields}


def _ext(external_id: str) -> list[dict[str, str]]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
            "url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}",
        }
    ]


def _rel(rel_id: str, rel_type: str, source: str, target: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{rel_id}",
        "relationship_type": rel_type,
        "source_ref": source,
        "target_ref": target,
    }


def _fixture_bundle() -> dict[str, Any]:
    kcp = [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}]
    return {
        "type": "bundle",
        "id": "bundle--fixture",
        "objects": [
            _obj("x-mitre-collection", "c", name="Enterprise ATT&CK", x_mitre_version="99.1"),
            _obj(
                "x-mitre-tactic",
                "t",
                name="Discovery",
                x_mitre_shortname="discovery",
                external_references=[{"source_name": "mitre-attack", "external_id": "TA0007"}],
            ),
            _obj(
                "attack-pattern",
                "parent",
                name="Fixture Parent",
                description="Parent description.",
                kill_chain_phases=kcp,
                x_mitre_platforms=["Linux"],
                external_references=_ext("T9001"),
            ),
            _obj(
                "attack-pattern",
                "child",
                name="Fixture Child",
                description="Child description.",
                kill_chain_phases=kcp,
                x_mitre_is_subtechnique=True,
                external_references=_ext("T9001.001"),
            ),
            _obj(
                "attack-pattern",
                "revoked",
                name="Fixture Revoked",
                revoked=True,
                external_references=_ext("T9002"),
            ),
            _obj(
                "attack-pattern",
                "deprecated",
                name="Fixture Deprecated",
                x_mitre_deprecated=True,
                external_references=_ext("T9003"),
            ),
            _obj(
                "x-mitre-data-component",
                "dc",
                name="Fixture Component",
            ),
            _obj(
                "x-mitre-analytic",
                "an",
                name="Fixture Analytic",
                description="Watch the fixture logs.",
                x_mitre_log_source_references=[
                    {
                        "x_mitre_data_component_ref": "x-mitre-data-component--dc",
                        "name": "fixture:log",
                        "channel": "events",
                    }
                ],
            ),
            _obj(
                "x-mitre-detection-strategy",
                "ds",
                name="Fixture Strategy",
                x_mitre_analytic_refs=["x-mitre-analytic--an"],
            ),
            _obj("course-of-action", "coa", name="Fixture Mitigation"),
            _obj("intrusion-set", "grp", name="FIXTURE GROUP"),
            _obj("malware", "mal", name="FixtureRAT"),
            _rel("r1", "subtechnique-of", "attack-pattern--child", "attack-pattern--parent"),
            _rel("r2", "detects", "x-mitre-detection-strategy--ds", "attack-pattern--parent"),
            _rel("r3", "mitigates", "course-of-action--coa", "attack-pattern--parent"),
            _rel("r4", "uses", "intrusion-set--grp", "attack-pattern--parent"),
            _rel("r5", "uses", "malware--mal", "attack-pattern--parent"),
            _rel("r6", "revoked-by", "attack-pattern--revoked", "attack-pattern--parent"),
        ],
    }


@pytest.mark.unit
def test_distill_joins_the_relationship_graph() -> None:
    distilled = _upd._distill(_fixture_bundle())
    assert distilled["version"] == "99.1"
    assert distilled["techniques"]["T9001"]["status"] == "active"
    assert distilled["techniques"]["T9001.001"]["parent"] == "T9001"
    assert distilled["descriptions"]["T9001"] == "Parent description."
    detection = distilled["detection"]["T9001"]
    assert detection["strategies"][0]["name"] == "Fixture Strategy"
    analytic = detection["strategies"][0]["analytics"][0]
    assert analytic["log_sources"] == ["fixture:log:events"]
    assert detection["data_components"] == ["Fixture Component"]
    rels = distilled["relationships"]["T9001"]
    assert rels["mitigations"] == ["Fixture Mitigation"]
    assert rels["groups"] == ["FIXTURE GROUP"]
    assert rels["software"] == ["FixtureRAT"]
    assert distilled["tombstones"]["T9002"] == {
        "status": "revoked",
        "name": "Fixture Revoked",
        "successor": "T9001",
    }
    assert distilled["tombstones"]["T9003"] == {
        "status": "deprecated",
        "name": "Fixture Deprecated",
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "drop_type",
    [
        "attack-pattern",
        "x-mitre-tactic",
        "x-mitre-data-component",
        "course-of-action",
        "intrusion-set",
    ],
)
def test_missing_object_type_fails_loudly(drop_type: str) -> None:
    bundle = _fixture_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o["type"] != drop_type]
    with pytest.raises(Exception, match=r"shape change|tactic|objects"):
        _upd._distill(bundle)


@pytest.mark.unit
@pytest.mark.parametrize(
    "drop_rel", ["subtechnique-of", "detects", "mitigates", "uses", "revoked-by"]
)
def test_missing_relationship_type_fails_loudly(drop_rel: str) -> None:
    bundle = _fixture_bundle()
    bundle["objects"] = [
        o
        for o in bundle["objects"]
        if o["type"] != "relationship" or o["relationship_type"] != drop_rel
    ]
    with pytest.raises(Exception, match=r"shape change"):
        _upd._distill(bundle)


@pytest.mark.unit
def test_revoked_without_successor_fails() -> None:
    bundle = _fixture_bundle()
    bundle["objects"] = [
        o
        for o in bundle["objects"]
        if not (o["type"] == "relationship" and o.get("relationship_type") == "revoked-by")
    ] + [_rel("r7", "revoked-by", "course-of-action--coa", "attack-pattern--parent")]
    with pytest.raises(Exception, match="revoked but has no"):
        _upd._distill(bundle)


@pytest.mark.unit
def test_unknown_tactic_shortname_fails() -> None:
    bundle = _fixture_bundle()
    for obj in bundle["objects"]:
        if obj.get("name") == "Fixture Parent":
            obj["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": "no-such-tactic"}
            ]
    with pytest.raises(Exception, match="unknown tactic"):
        _upd._distill(bundle)


@pytest.mark.unit
def test_split_items_is_deterministic_and_bounded() -> None:
    items = {f"T{i:04d}": {"description": "x" * 5000} for i in range(400)}
    parts = _upd._split_items("descriptions", items)
    assert len(parts) > 1, "400 x 5KB must split"
    merged: dict[str, Any] = {}
    for name in sorted(parts):
        assert len(_upd._canonical(parts[name])) <= 1024 * 1024
        merged.update(parts[name]["items"])
    assert merged == items
    assert parts == _upd._split_items("descriptions", dict(reversed(list(items.items()))))


@pytest.mark.unit
def test_canonical_rendering_is_byte_stable() -> None:
    doc = {"b": [2, 1], "a": {"nested": True}}
    assert _upd._canonical(doc) == _upd._canonical({"a": {"nested": True}, "b": [2, 1]})
    assert _upd._canonical(doc).endswith(b"\n")
