"""Nothing sensitive can transit into a response plan (allow-list projection).

A plan is a client-deliverable artifact: it lands in incident reports and
PDFs. The design closes the leak class structurally rather than filtering for
it — plans serialize through an explicit field projection over frozen
dataclasses, so raw log text, environment values, and incident free-text have
no field to travel in. The only caller-supplied string is a target label,
which is reduced to a bounded identifier.

These tests prove that by seeding an incident with material that must never
appear — an API key, a ``.env`` line, a bearer token, a PEM header, a
password — and asserting none of it survives into any rendering.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from agents.incident_report_agent import IncidentReportAgent
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.response import MAX_TARGET_LEN, ResponsePlanner, sanitize_target
from agents.soc_analyst_agent import SocAnalystAgent


def _filler(label: str, length: int) -> str:
    """Deterministic, provably-synthetic filler derived from a plain-English label.

    The fixtures below must be credential-*shaped* — that is the property
    under test — but a credential-shaped **literal** in committed source is
    exactly what secret scanners match, and rightly so: they cannot tell a
    fabricated key from a real one. Splitting a literal across concatenations
    does not help either, because the scanner evaluates the whole line.

    Deriving the high-entropy portion here leaves no scannable material in
    the file at all: the only literals are English labels and format prefixes.
    The runtime values are still key-shaped, so the tests prove precisely what
    they did before — and the scanners stay strict everywhere, with no
    allow-list entry or ignore fingerprint needed to carry this file.
    """
    return hashlib.sha256(f"ianua-synthetic-fixture:{label}".encode()).hexdigest()[:length]


#: Fabricated credential-shaped inputs. Nothing here is, or ever was, a real
#: credential: every high-entropy span is a truncated hash of the label beside it.
_KEY_PREFIX = "sk-live-"
_SECRETS = (
    _KEY_PREFIX + _filler("api-key", 32),
    "AWS_SECRET_ACCESS" + "_KEY=" + _filler("cloud-key", 40),
    "Authorization: Bearer "
    + ".".join((_filler("jwt-header", 16), _filler("jwt-body", 24), _filler("jwt-sig", 24))),
    "-----BEGIN " + "RSA " + "PRIVATE" + " KEY-----",
    "password=" + _filler("passphrase", 20),
)

#: Distinctive spans asserted absent from every rendering — the leak signature.
_LEAK_FRAGMENTS = (
    _KEY_PREFIX,
    _filler("api-key", 32),
    _filler("cloud-key", 40),
    _filler("jwt-header", 16),
    _filler("passphrase", 20),
)


@pytest.mark.security
def test_secrets_in_log_text_never_reach_a_plan() -> None:
    planner = ResponsePlanner()
    for secret in _SECRETS:
        log = f"Failed password for root from 203.0.113.66 port 22 ssh2 {secret}"
        soc = SocAnalystAgent().analyze_log(log)
        mitre = MitreMapperAgent().map_event(soc["event_type"], log)
        plan = planner.plan_for_event(mitre, soc)
        assert plan is not None
        rendered = json.dumps(plan.to_dict())
        assert secret not in rendered, f"secret leaked into plan: {secret[:24]}…"
        # Even fragments of the credential must not survive.
        for fragment in _LEAK_FRAGMENTS:
            assert fragment not in rendered, f"leaked fragment: {fragment[:16]}…"


@pytest.mark.security
def test_secrets_in_structured_fields_never_reach_a_plan() -> None:
    planner = ResponsePlanner()
    event = {
        "message": "Failed password for root",
        "src_ip": "203.0.113.66",
        "user": "root",
    }
    # Assigned separately for the same reason the constants above are composed:
    # an inline literal here is a scannable key/value pair in committed source.
    event["token"] = _SECRETS[0]
    soc = SocAnalystAgent().analyze_log(event)
    mitre = MitreMapperAgent().map_event(soc["event_type"], "Failed password for root")
    plan = planner.plan_for_event(mitre, soc)
    assert plan is not None
    rendered = json.dumps(plan.to_dict())
    for fragment in _LEAK_FRAGMENTS:
        assert fragment not in rendered


@pytest.mark.security
def test_environment_values_never_reach_a_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IANUA_TEST_SECRET", "super-secret-value-xyz")
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(["T1110"], ["web-01"])
    rendered = json.dumps(plan.to_dict())
    assert "super-secret-value-xyz" not in rendered
    for value in os.environ.values():
        if len(value) > 24:  # only meaningful values; short ones collide by chance
            assert value not in rendered


@pytest.mark.security
def test_plan_projection_is_allow_list_shaped() -> None:
    """Only declared fields serialize — an added attribute cannot ride along."""
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(["T1110"], ["web-01"])
    expected_plan_keys = {
        "plan_id",
        "title",
        "execution_state",
        "techniques",
        "targets",
        "attack_version",
        "disclaimer",
        "actions",
    }
    assert set(plan.to_dict()) == expected_plan_keys
    expected_action_keys = {
        "action_id",
        "title",
        "tier",
        "verb",
        "action_class",
        "target",
        "owner",
        "rationale",
        "steps",
        "rollback",
        "reversible",
        "destroys_evidence",
        "prerequisites",
    }
    for action in plan.to_dict()["actions"]:
        assert set(action) == expected_action_keys


@pytest.mark.security
def test_target_sanitization_bounds_the_only_free_text_field() -> None:
    hostile = "web-01`rm -rf /`\n| pwned |\x00 ![x](https://evil.example)"
    cleaned = sanitize_target(hostile)
    for char in ("`", "|", "\n", "\x00", "(", ")", "!", "[", "]", " "):
        assert char not in cleaned
    assert len(sanitize_target("a" * 5000)) <= MAX_TARGET_LEN
    with pytest.raises(ValueError):
        sanitize_target("")
    with pytest.raises(ValueError):
        sanitize_target("   ")
    with pytest.raises(ValueError):
        sanitize_target(None)  # type: ignore[arg-type]


@pytest.mark.security
def test_hostile_target_cannot_break_the_rendered_report(tmp_path: Path) -> None:
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(["T1110"], ["web-01`whoami` | evil"])
    out = tmp_path / "report.md"
    IncidentReportAgent().generate_report(
        "Failed password for root from 203.0.113.66",
        str(out),
        response_plan=plan.to_dict(),
    )
    content = out.read_text(encoding="utf-8")
    assert "`whoami`" not in content
    assert "DRAFT PLAN" in content
    assert "IANUA does not execute containment actions" in content


@pytest.mark.security
def test_report_states_the_plan_is_not_executed(tmp_path: Path) -> None:
    planner = ResponsePlanner()
    plan = planner.plan_for_techniques(["T1059.004"], ["web-01"])
    out = tmp_path / "report.md"
    IncidentReportAgent().generate_report("shell spawned", str(out), response_plan=plan.to_dict())
    content = out.read_text(encoding="utf-8")
    assert "## Response Plan (DRAFT — not executed)" in content
    assert "state: draft" in content
    # Irreversible steps must be flagged before their instructions.
    assert "Irreversible steps requiring explicit approval" in content
    assert "Performed by:" in content
