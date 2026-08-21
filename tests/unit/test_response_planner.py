"""Unit contracts for the plan-only response layer."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.response import (
    ResponseCatalogueError,
    ResponsePlanner,
    build_action,
    load_catalogue,
)
from agents.soc_analyst_agent import SocAnalystAgent

_CATALOGUE = Path(__file__).resolve().parents[2] / "agents" / "response" / "actions.json"


@pytest.fixture(scope="module")
def planner() -> ResponsePlanner:
    return ResponsePlanner()


@pytest.mark.unit
def test_committed_catalogue_loads(planner: ResponsePlanner) -> None:
    assert planner.catalogue
    for action in planner.catalogue.values():
        assert action["steps"], f"{action['action_id']}: no steps"
        assert action["rollback"], f"{action['action_id']}: no rollback"


@pytest.mark.unit
def test_plan_orders_collection_before_containment(planner: ResponsePlanner) -> None:
    plan = planner.plan_for_techniques(["T1059.004"], ["web-01"])
    assert plan.actions[0].action_id == "capture-volatile-memory"
    assert plan.actions[0].tier == 0
    assert [a.tier for a in plan.actions] == sorted(a.tier for a in plan.actions)


@pytest.mark.unit
def test_prerequisites_are_pulled_in_ahead_of_their_action(
    planner: ResponsePlanner,
) -> None:
    plan = planner.plan_for_techniques(["T1078"], ["svc-account"])
    ids = [a.action_id for a in plan.actions]
    # reset-account-credentials requires revoke-account-sessions.
    assert ids.index("revoke-account-sessions") < ids.index("reset-account-credentials")


@pytest.mark.unit
def test_weak_signal_yields_no_plan(planner: ResponsePlanner) -> None:
    """A port scan must not produce containment — that is how FPs become outages."""
    log = "Suricata alert: ET SCAN Nmap TCP scan from 198.51.100.9"
    soc = SocAnalystAgent().analyze_log(log)
    mitre = MitreMapperAgent().map_event(soc["event_type"], log)
    assert planner.plan_for_event(mitre, soc) is None


@pytest.mark.unit
def test_unattributed_event_yields_no_plan(planner: ResponsePlanner) -> None:
    soc = SocAnalystAgent().analyze_log("something entirely unclassified happened")
    mitre = MitreMapperAgent().map_event(soc["event_type"], "unclassified")
    assert mitre["technique_id"] == "UNKNOWN"
    assert planner.plan_for_event(mitre, soc) is None


@pytest.mark.unit
def test_plan_covers_every_attributed_technique(planner: ResponsePlanner) -> None:
    log = "Accepted password for root from 203.0.113.66 port 22 ssh2"
    soc = SocAnalystAgent().analyze_log(log)
    mitre = MitreMapperAgent().map_event(soc["event_type"], log)
    plan = planner.plan_for_event(mitre, soc)
    assert plan is not None
    # T1078 and T1021.004 are both attributed; both contribute session revocation.
    assert "T1078" in plan.techniques
    assert any(a.action_id == "revoke-account-sessions" for a in plan.actions)
    assert plan.attack_version == mitre["attack_version"]


@pytest.mark.unit
def test_plan_id_is_stable_and_identity_derived(planner: ResponsePlanner) -> None:
    a = planner.plan_for_techniques(["T1110"], ["web-01"])
    b = planner.plan_for_techniques(["T1110"], ["web-01"])
    c = planner.plan_for_techniques(["T1110"], ["web-02"])
    assert a.plan_id == b.plan_id
    assert a.plan_id != c.plan_id


@pytest.mark.unit
def test_input_validation_fails_closed(planner: ResponsePlanner) -> None:
    with pytest.raises(ValueError):
        planner.plan_for_techniques(["T1110"], [])
    with pytest.raises(ValueError):
        planner.plan_for_techniques(["T1110"], "web-01")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        planner.plan_for_techniques("T1110", ["web-01"])  # type: ignore[arg-type]


@pytest.mark.unit
def test_unknown_action_id_rejected(planner: ResponsePlanner) -> None:
    with pytest.raises(ResponseCatalogueError, match="unknown action_id"):
        build_action("delete-everything", "web-01", planner.catalogue)


@pytest.mark.unit
def test_irreversible_and_evidence_views(planner: ResponsePlanner) -> None:
    plan = planner.plan_for_techniques(["T1078", "T1059.004"], ["web-01"])
    irreversible = {a.action_id for a in plan.irreversible_actions}
    assert "reset-account-credentials" in irreversible
    evidence = {a.action_id for a in plan.evidence_affecting_actions}
    assert "terminate-malicious-process" in evidence


def _document() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_CATALOGUE.read_text(encoding="utf-8"))
    return loaded


_MUTATIONS: list[tuple[str, Callable[[dict], None]]] = [
    ("bad schema", lambda d: d.update(schema=2)),
    ("empty actions", lambda d: d.update(actions=[])),
    ("unknown field", lambda d: d["actions"][0].update(surprise=1)),
    ("missing rollback", lambda d: d["actions"][0].pop("rollback")),
    ("offensive verb", lambda d: d["actions"][0].update(verb="exploit")),
    ("unknown tier", lambda d: d["actions"][0].update(tier=9)),
    ("unknown action_class", lambda d: d["actions"][0].update(action_class="offensive")),
    ("platform as owner", lambda d: d["actions"][0].update(owner="IANUA response agent")),
    ("duplicate action_id", lambda d: d["actions"].append(copy.deepcopy(d["actions"][0]))),
    ("dangling prerequisite", lambda d: d["actions"][0].update(prerequisites=["ghost"])),
    ("non-bool reversible", lambda d: d["actions"][0].update(reversible="yes")),
]


@pytest.mark.unit
@pytest.mark.parametrize(("label", "mutate"), _MUTATIONS, ids=[m[0] for m in _MUTATIONS])
def test_malformed_catalogue_rejects_wholly(
    label: str, mutate: Callable[[dict], None], tmp_path: Path
) -> None:
    document = _document()
    mutate(document)
    path = tmp_path / "actions.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ResponseCatalogueError):
        load_catalogue(path)


@pytest.mark.unit
def test_irreversible_without_finality_statement_rejected(tmp_path: Path) -> None:
    document = _document()
    for action in document["actions"]:
        if not action["reversible"]:
            action["rollback"] = "Just restore it from backup."
            break
    path = tmp_path / "actions.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ResponseCatalogueError, match="cannot be undone"):
        load_catalogue(path)


@pytest.mark.unit
def test_evidence_affecting_without_prerequisite_rejected(tmp_path: Path) -> None:
    document = _document()
    for action in document["actions"]:
        if action["destroys_evidence"]:
            action["prerequisites"] = []
            break
    path = tmp_path / "actions.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ResponseCatalogueError, match="prerequisite"):
        load_catalogue(path)


@pytest.mark.unit
def test_missing_catalogue_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ResponseCatalogueError, match="not found"):
        load_catalogue(tmp_path / "absent.json")
