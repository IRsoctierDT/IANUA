# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Evaluate committed behavioral rules against typed endpoint telemetry."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.tools.sigma_eval import evaluate
from attack import AttackError, load_pin
from ingest.schema import NormalizedEvent

_INDEX = Path(__file__).resolve().parents[2] / "detections" / "behaviors.index.json"

# Explicit prerequisites for each sensor. Alternate sources must prove the
# same fields; a parser registration or a generic log line proves neither.
SIGNALS = {
    "sysmon-process": ("image", "command_line"),
    "sysmon-lineage": ("image", "parent_image"),
    "auditd-command": ("command_line",),
    "auditd-lifecycle": ("activity",),
    "auditd-syscall": ("activity",),
}


@dataclass(frozen=True, slots=True)
class BehavioralRule:
    """Committed rule, sensor prerequisites and pinned ATT&CK references."""

    name: str
    level: str
    techniques: tuple[str, ...]
    signals: tuple[str, ...]
    definition: dict[str, Any]


@dataclass(frozen=True, slots=True)
class BehavioralRules:
    """Runtime catalog and version used to interpret its technique references."""

    attack_version: str
    rules: tuple[BehavioralRule, ...]

    def evaluate_event(self, event: NormalizedEvent) -> tuple[set[str], tuple[BehavioralRule, ...]]:
        """Return observed signal types and matches, using only eligible records."""
        signals, fields = _project(event)
        return signals, tuple(
            rule
            for rule in self.rules
            if signals.intersection(rule.signals) and evaluate(rule.definition, fields)
        )


def load_behavioral_rules() -> BehavioralRules:
    """Load the repository's generated rule index, refusing stale or unusable data."""
    with _INDEX.open("rb") as handle:
        raw = handle.read(262145)
    if len(raw) > 262144:
        raise ValueError("Behavioral rule index exceeds its size limit.")
    try:
        index = json.loads(raw)
        version = index["attack_version"]
        if index["schema"] != 1 or version != load_pin().attack_version:
            raise ValueError
        rules = tuple(
            BehavioralRule(
                entry["name"],
                entry["level"],
                tuple(entry["techniques"]),
                tuple(entry["signals"]),
                {"detection": entry["detection"]},
            )
            for entry in index["behaviors"]
        )
        if not rules or len({rule.name for rule in rules}) != len(rules):
            raise ValueError
        for rule in rules:
            if not rule.signals or not set(rule.signals) <= SIGNALS.keys():
                raise ValueError
            evaluate(rule.definition, {})
    except (AttackError, KeyError, TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Behavioral rule index is invalid or out of date.") from exc
    return BehavioralRules(version, rules)


def _project(event: NormalizedEvent) -> tuple[set[str], dict[str, Any]]:
    if event.source_type != "endpoint" or event.parse_status == "text":
        return set(), {}
    actor = event.actor
    fields = {
        "image": (actor.process_name or "").replace("\\", "/").rsplit("/", 1)[-1],
        "parent_image": (actor.parent_process_name or "").replace("\\", "/").rsplit("/", 1)[-1],
        "command_line": actor.command_line,
        "activity": event.activity,
    }
    if event.vendor == "sysmon" and event.vendor_event_id == "1":
        return {
            signal
            for signal in ("sysmon-process", "sysmon-lineage")
            if all(fields[field] for field in SIGNALS[signal])
        }, fields
    if event.vendor != "auditd":
        return set(), {}
    kind = event.vendor_event_id
    if kind in {"DAEMON_START", "DAEMON_END", "DAEMON_ABORT"}:
        return {"auditd-lifecycle"}, fields
    if kind in {"EXECVE", "USER_CMD", "SYSCALL"} and actor.command_line:
        signals = {"auditd-command"}
    else:
        signals = set()
    if kind == "SYSCALL" and event.activity in {"exec syscall", "memfd execution"}:
        signals.add("auditd-syscall")
    return signals, fields
