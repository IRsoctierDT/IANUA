"""Behavioral detection content stays defensive, synthetic, and honest.

Detection rules necessarily *describe* attacker behavior — that is what makes
them detections. The line this suite enforces (AGENTS.md §5) is that the
corpus describes what a defender observes and never ships anything that
functions as attack tooling: no payloads, no runnable exploitation commands,
no shellcode blobs. It also enforces fixture hygiene (synthetic addresses and
hosts only) and the honesty markers that keep aspirational coverage from
being counted as real.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_BEHAVIORS = _REPO / "detections" / "behaviors"
_INDEX = _REPO / "detections" / "behaviors.index.json"
_FIXTURES = _REPO / "detections" / "fixtures" / "behavior_fixtures.json"

_SHELLCODE_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

#: Fixture addresses must be documentation (RFC 5737) or private (RFC 1918)
#: space. A real routable address in committed content is an accusation.
_ALLOWED_FIXTURE_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    )
]

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _rule_docs() -> list[tuple[Path, dict[str, Any]]]:
    return [
        (path, yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(_BEHAVIORS.glob("*.yml"))
    ]


def _all_strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [s for item in node for s in _all_strings(item)]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _all_strings(value)]
    return []


@pytest.mark.security
def test_no_shellcode_or_payload_blobs() -> None:
    for path, rule in _rule_docs():
        for text in _all_strings(rule):
            assert not _SHELLCODE_HEX.search(text), f"{path.name}: shellcode-shaped hex"
            if len(text) > 256 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
                decodable = True
                try:
                    base64.b64decode(text, validate=True)
                except (ValueError, TypeError):
                    decodable = False
                assert not decodable, f"{path.name}: oversized base64 blob"


@pytest.mark.security
def test_every_rule_is_phrased_as_a_detection() -> None:
    """A detection states what it observes, what it misses, and where it fires."""
    for path, rule in _rule_docs():
        assert rule.get("falsepositives"), f"{path.name}: no stated false positives"
        assert rule.get("detection", {}).get("condition"), f"{path.name}: no condition"
        assert rule.get("logsource"), f"{path.name}: no logsource"
        assert rule.get("references"), f"{path.name}: no ATT&CK reference"
        description = str(rule.get("description", ""))
        assert len(description) > 80, (
            f"{path.name}: description must explain the behavior and why it matters"
        )


@pytest.mark.security
def test_no_runnable_attack_command_lines() -> None:
    """Descriptions and false-positive notes must not read as copy-paste attacks.

    Detection *selections* legitimately contain command fragments — that is
    the matching logic. Prose fields have no such need, so a shell prompt or
    a piped-download idiom there is a smell the corpus is drifting toward
    tooling.
    """
    offensive_idioms = ("| sh", "|sh ", "| bash", "curl -s http", "wget -q http")
    for path, rule in _rule_docs():
        prose = [str(rule.get("description", "")), *map(str, rule.get("falsepositives", []))]
        for text in prose:
            stripped = text.strip()
            assert not stripped.startswith(("$ ", "# ", "C:\\>", "PS>")), (
                f"{path.name}: prose reads as a command prompt line"
            )
            lowered = text.lower()
            for idiom in offensive_idioms:
                assert idiom not in lowered, f"{path.name}: prose carries {idiom!r}"


@pytest.mark.security
def test_fixture_addresses_are_synthetic() -> None:
    fixtures = json.loads(_FIXTURES.read_text(encoding="utf-8"))
    for text in _all_strings(fixtures):
        for candidate in _IPV4_RE.findall(text):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            assert any(address in net for net in _ALLOWED_FIXTURE_NETWORKS), (
                f"fixture uses non-synthetic address {candidate}"
            )


@pytest.mark.security
def test_validation_markers_are_honest() -> None:
    """Rules claiming live telemetry must match what the platform ingests.

    Today the platform ingests syslog-shaped text only. Any rule keyed on
    process-creation fields (parent_image, command_line) therefore cannot
    fire in production and must say so, rather than inflating coverage.
    """
    index = json.loads(_INDEX.read_text(encoding="utf-8"))
    by_name = {entry["name"]: entry for entry in index["behaviors"]}
    process_fields = ("command_line", "parent_image", "image")
    for path, rule in _rule_docs():
        selections = {key: value for key, value in rule["detection"].items() if key != "condition"}
        keys = {
            field.split("|")[0]
            for selection in selections.values()
            if isinstance(selection, dict)
            for field in selection
        }
        needs_endpoint = bool(keys & set(process_fields))
        entry = by_name[str(rule["name"])]
        if needs_endpoint:
            assert entry["validation"] == "telemetry-required", (
                f"{path.name}: keys on endpoint process telemetry the platform does not "
                "ingest, so it must be marked telemetry-required"
            )


@pytest.mark.security
def test_index_is_a_faithful_projection() -> None:
    """The runtime reads the JSON index; it must not diverge from the YAML."""
    index = json.loads(_INDEX.read_text(encoding="utf-8"))
    by_name = {entry["name"]: entry for entry in index["behaviors"]}
    for path, rule in _rule_docs():
        entry = by_name[str(rule["name"])]
        assert entry["id"] == str(rule["id"]), f"{path.name}: id drift"
        assert entry["level"] == str(rule["level"]), f"{path.name}: level drift"
        assert entry["validation"] == str(rule["validation"]), f"{path.name}: marker drift"
        assert entry["file"] == path.name
