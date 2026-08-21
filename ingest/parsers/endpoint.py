"""Endpoint telemetry: Sysmon (Windows) and auditd (Linux).

These two carry the process-lineage and file/registry detail the behavioral
corpus in ``detections/behaviors/`` is written against. Six of those seven
rules are marked ``telemetry-required`` precisely because nothing was feeding
them; this module is the shape of the feed they were waiting for.

Both parsers are read-only over a decoded record. Neither resolves a path,
opens a file, or executes anything — a command line from a compromised host
is evidence to be carried and rendered, never a string to be run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ingest._coerce import dig, epoch, first, observables, text
from ingest.parsers import Signature
from ingest.schema import Actor, Device, Endpoint, NormalizedEvent

# --------------------------------------------------------------------------
# Sysmon
# --------------------------------------------------------------------------

#: Sysmon event IDs the platform reads, mapped to a stable activity label.
#: An ID outside this table still parses — the activity simply reads as the
#: raw ID, which is honest, rather than being dropped or guessed at.
_SYSMON_ACTIVITY: dict[str, str] = {
    "1": "process creation",
    "2": "file creation time changed",
    "3": "network connection",
    "5": "process terminated",
    "6": "driver loaded",
    "7": "image loaded",
    "8": "create remote thread",
    "10": "process access",
    "11": "file created",
    "12": "registry key created or deleted",
    "13": "registry value set",
    "14": "registry key renamed",
    "15": "file stream created",
    "17": "pipe created",
    "18": "pipe connected",
    "22": "dns query",
    "23": "file deleted",
    "25": "process tampering",
    "26": "file delete detected",
}

#: Sysmon serializes hashes as ``SHA256=...,MD5=...``.
_HASH_PAIR = re.compile(r"\b(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]{32,64})\b")


def _event_data(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Sysmon exports nest fields under ``EventData``; some flatten them."""
    nested = payload.get("EventData")
    if isinstance(nested, Mapping):
        return nested
    return payload


def _recognizes_sysmon(payload: Mapping[str, Any]) -> bool:
    provider = first(
        payload.get("Provider"),
        payload.get("provider_name"),
        payload.get("Channel"),
        payload.get("channel"),
        dig(payload, "System", "Provider", "Name"),
        dig(payload, "System", "Channel"),
    )
    if provider is None or "sysmon" not in provider.lower():
        return False
    return _sysmon_event_id(payload) is not None


def _sysmon_event_id(payload: Mapping[str, Any]) -> str | None:
    return first(
        payload.get("EventID"),
        payload.get("event_id"),
        dig(payload, "System", "EventID"),
    )


def _parse_sysmon(payload: Mapping[str, Any]) -> NormalizedEvent:
    data = _event_data(payload)
    notes: list[str] = []
    event_id = _sysmon_event_id(payload)
    activity = _SYSMON_ACTIVITY.get(event_id or "", f"sysmon event {event_id}")
    if event_id not in _SYSMON_ACTIVITY:
        notes.append(f"unmapped Sysmon event ID {event_id!r}; activity left unlabelled")

    image = first(data.get("Image"), data.get("SourceImage"))
    command_line = text(data.get("CommandLine"))
    parent = first(data.get("ParentImage"), data.get("SourceImage"))
    user = first(data.get("User"), data.get("SubjectUserName"))
    host = first(
        data.get("Computer"),
        payload.get("Computer"),
        dig(payload, "System", "Computer"),
        payload.get("hostname"),
    )
    timestamp = epoch(
        first(
            data.get("UtcTime"),
            payload.get("UtcTime"),
            payload.get("@timestamp"),
            dig(payload, "System", "TimeCreated", "SystemTime"),
        )
    )
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    hashes = tuple(value for _, value in _HASH_PAIR.findall(text(data.get("Hashes")) or ""))
    dst_ip = first(data.get("DestinationIp"), data.get("DestinationIpv6"))
    dst_domain = first(data.get("QueryName"), data.get("DestinationHostname"))

    message = " ".join(
        part
        for part in (
            activity,
            f"image={image}" if image else None,
            f"parent={parent}" if parent else None,
            f"cmd={command_line}" if command_line else None,
            f"query={dst_domain}" if dst_domain else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="endpoint",
        vendor="sysmon",
        vendor_event_id=event_id,
        timestamp=timestamp,
        message=message,
        activity=activity,
        parse_status="partial" if notes else "structured",
        actor=Actor(
            user_name=user,
            process_name=image,
            process_pid=first(data.get("ProcessId"), data.get("SourceProcessId")),
            parent_process_name=parent,
            command_line=command_line,
        ),
        device=Device(hostname=host, os="windows"),
        src_endpoint=Endpoint(ip=first(data.get("SourceIp")), port=first(data.get("SourcePort"))),
        dst_endpoint=Endpoint(
            ip=dst_ip, port=first(data.get("DestinationPort")), domain=dst_domain
        ),
        observables=observables(image, command_line, dst_ip, dst_domain, *hashes),
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------
# auditd
# --------------------------------------------------------------------------

#: auditd record types this parser recognizes. Kept explicit rather than
#: accepting any ``type`` key, because "has a field called type" describes
#: half the telemetry in existence and would claim other vendors' records.
_AUDITD_TYPES = frozenset(
    {
        "SYSCALL",
        "EXECVE",
        "PROCTITLE",
        "PATH",
        "USER_AUTH",
        "USER_ACCT",
        "USER_CMD",
        "USER_LOGIN",
        "USER_START",
        "CRED_ACQ",
        "CRED_REFR",
        "ADD_USER",
        "ADD_GROUP",
        "CONFIG_CHANGE",
        "DAEMON_END",
        "DAEMON_ABORT",
        "SERVICE_START",
        "SERVICE_STOP",
        "SYSTEM_SHUTDOWN",
        "ANOM_ABEND",
    }
)

#: auditd stamps its own clock into ``msg=audit(<epoch>.<ms>:<serial>)``.
_AUDIT_MSG_CLOCK = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
#: EXECVE splits a command line across a0, a1, a2 … in argv order.
_EXECVE_ARG = re.compile(r"^a(\d+)$")


def _recognizes_auditd(payload: Mapping[str, Any]) -> bool:
    record_type = text(payload.get("type"))
    if record_type is None or record_type.upper() not in _AUDITD_TYPES:
        return False
    # A corroborating auditd-specific field. ``type`` alone is too generic.
    return any(
        payload.get(key) is not None
        for key in ("exe", "comm", "syscall", "auid", "ses", "acct", "key", "proctitle", "msg")
    )


def _execve_command(payload: Mapping[str, Any]) -> str | None:
    """Reassemble an EXECVE argv, in index order rather than dict order."""
    args: list[tuple[int, str]] = []
    for key, value in payload.items():
        match = _EXECVE_ARG.match(key)
        coerced = text(value)
        if match and coerced is not None:
            args.append((int(match.group(1)), coerced))
    if not args:
        return None
    return " ".join(value for _, value in sorted(args))


def _parse_auditd(payload: Mapping[str, Any]) -> NormalizedEvent:
    notes: list[str] = []
    record_type = (text(payload.get("type")) or "").upper()

    timestamp = epoch(first(payload.get("@timestamp"), payload.get("timestamp")))
    if timestamp is None:
        clock = _AUDIT_MSG_CLOCK.search(text(payload.get("msg")) or "")
        if clock:
            timestamp = epoch(float(clock.group(1)))
    if timestamp is None:
        notes.append("no usable timestamp on the record")

    command_line = first(payload.get("proctitle"), _execve_command(payload), payload.get("cmd"))
    exe = first(payload.get("exe"), payload.get("comm"))
    user = first(payload.get("acct"), payload.get("auid"), payload.get("uid"))
    host = first(payload.get("node"), payload.get("hostname"))
    result = first(payload.get("res"), payload.get("success"))

    message = " ".join(
        part
        for part in (
            f"auditd {record_type}",
            f"exe={exe}" if exe else None,
            f"cmd={command_line}" if command_line else None,
            f"key={text(payload.get('key'))}" if payload.get("key") else None,
            f"res={result}" if result else None,
        )
        if part
    )

    return NormalizedEvent(
        source_type="endpoint",
        vendor="auditd",
        vendor_event_id=record_type or None,
        timestamp=timestamp,
        message=message,
        activity=record_type.lower() or None,
        parse_status="partial" if notes else "structured",
        actor=Actor(
            user_name=user,
            user_uid=first(payload.get("uid")),
            process_name=exe,
            process_pid=first(payload.get("pid")),
            parent_process_name=first(payload.get("ppid_exe")),
            command_line=command_line,
        ),
        device=Device(hostname=host, os="linux"),
        src_endpoint=Endpoint(ip=first(payload.get("addr"))),
        observables=observables(exe, command_line, payload.get("addr")),
        notes=tuple(notes),
    )


SIGNATURES: tuple[Signature, ...] = (
    Signature("sysmon", "endpoint", _recognizes_sysmon, _parse_sysmon),
    Signature("auditd", "endpoint", _recognizes_auditd, _parse_auditd),
)
