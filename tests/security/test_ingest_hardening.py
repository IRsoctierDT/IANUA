"""Ingest is the platform's largest untrusted-input surface — hold it closed.

Every byte this layer reads came from somewhere the platform does not
control: a hostname is whatever the endpoint claimed, a command line is
whatever the adversary typed, a mail subject is whatever the sender chose.
These tests assert the properties that keep that surface from becoming a
liability:

* bounded — oversized, deeply nested, and huge-field records cannot exhaust
  memory or blow the stack, and none of them silently vanish either;
* inert — nothing from a record reaches a path, a shell, an eval, or the
  network, and the module set proves it by construction;
* non-leaking — email bodies have no field to travel in, and the parser
  modules never read one;
* honest — degraded parses are labelled, so a partial understanding is never
  rendered as a confident analysis.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest
from ingest.parsers.email import FORBIDDEN_CONTENT_FIELDS

from ingest import (
    MAX_FIELD_LEN,
    MAX_NESTING_DEPTH,
    MAX_OBSERVABLES,
    MAX_RAW_BYTES,
    MAX_RAW_EXCERPT,
    normalize,
)

_INGEST_ROOT = Path(__file__).resolve().parents[2] / "ingest"


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------


@pytest.mark.security
def test_oversized_record_is_refused_but_not_dropped() -> None:
    payload = "x" * (MAX_RAW_BYTES + 1024)
    event = normalize(payload)
    assert event.source_type == "unknown"
    assert event.parse_status == "partial"
    assert len(event.raw_excerpt) <= MAX_RAW_EXCERPT
    assert any("ceiling" in note for note in event.notes)


@pytest.mark.security
def test_oversized_field_is_truncated_not_propagated() -> None:
    record = {
        "type": "EXECVE",
        "node": "host",
        "auid": "0",
        "@timestamp": "2026-08-14T00:00:00Z",
        "a0": "A" * (MAX_FIELD_LEN * 20),
    }
    event = normalize(record)
    assert event.actor.command_line is not None
    assert len(event.actor.command_line) <= MAX_FIELD_LEN
    assert len(event.raw_excerpt) <= MAX_RAW_EXCERPT


@pytest.mark.security
def test_deeply_nested_record_is_refused_without_recursing() -> None:
    """A nesting bomb must be rejected by an iterative check, not a crash."""
    deep: object = "leaf"
    for _ in range(MAX_NESTING_DEPTH + 50):
        deep = {"nested": deep}
    event = normalize({"eventSource": "sts.amazonaws.com", "eventName": "X", "deep": deep})
    assert event.source_type == "unknown"
    assert any("nests deeper" in note for note in event.notes)


@pytest.mark.security
def test_deeply_nested_json_string_never_raises() -> None:
    blob = "[" * 200 + "]" * 200
    event = normalize('{"a": ' + blob + "}")
    assert event.source_type == "unknown"


@pytest.mark.security
def test_observable_extraction_is_bounded() -> None:
    many = " ".join(f"10.0.{index // 256}.{index % 256}" for index in range(500))
    event = normalize(many)
    assert len(event.observables) <= MAX_OBSERVABLES


@pytest.mark.security
def test_a_wide_recipient_list_is_bounded() -> None:
    record = {
        "Timestamp": "2026-08-14T00:00:00Z",
        "NetworkMessageId": "abc",
        "SenderFromAddress": "a@example.com",
        "DeliveryAction": "Delivered",
        "RecipientEmailAddress": [f"user{index}@corp.example" for index in range(5000)],
    }
    event = normalize(record)
    assert 0 < len(event.email.recipients) <= 64


# --------------------------------------------------------------------------
# Injection and control characters
# --------------------------------------------------------------------------


@pytest.mark.security
def test_control_characters_and_nuls_never_survive_a_parse() -> None:
    hostile = "web-01\x00\x07\x1b[31mred\x1b[0m\r\ninjected: yes"
    record = {
        "type": "EXECVE",
        "node": hostile,
        "auid": "0",
        "@timestamp": "2026-08-14T00:00:00Z",
        "a0": hostile,
    }
    event = normalize(record)
    rendered = json.dumps(event.to_dict())
    for char in ("\x00", "\x07", "\x1b", "\r"):
        assert char not in rendered, f"control character {char!r} survived"
    # The excerpt is evidence, so it is bounded — and equally scrubbed.
    assert "\x00" not in event.message


@pytest.mark.security
def test_a_hostile_field_cannot_forge_another_field_in_the_match_view() -> None:
    """Match-view keys come from the schema, never from record content."""
    record = {
        "_path": "conn",
        "ts": 1755162700.0,
        "uid": "x",
        "id.orig_h": "10.0.0.1",
        "id.resp_h": '10.0.0.2", "image": "C:\\\\evil.exe',
    }
    view = normalize(record).to_match_view()
    assert "image" not in view
    assert set(view) <= {
        "source_type",
        "vendor",
        "message",
        "activity",
        "user",
        "user_principal",
        "identity",
        "image",
        "parent_image",
        "command_line",
        "host",
        "device_id",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "dst_domain",
        "cloud_provider",
        "cloud_account",
        "cloud_region",
        "cloud_service",
        "email_sender",
        "email_subject",
        "delivery_action",
    }


@pytest.mark.security
def test_serialization_is_an_allow_list_projection() -> None:
    """Only declared fields serialize — nothing from a record rides along."""
    record = dict(_load("cloudtrail_assume_role"))
    record["attackerControlledExtra"] = "should-not-appear"
    event = normalize(record)
    rendered = event.to_dict()
    assert "attackerControlledExtra" not in json.dumps(
        {key: value for key, value in rendered.items() if key != "raw_excerpt"}
    )
    assert set(rendered) == {
        "source_type",
        "vendor",
        "vendor_event_id",
        "timestamp",
        "message",
        "activity",
        "parse_status",
        "actor",
        "device",
        "src_endpoint",
        "dst_endpoint",
        "cloud",
        "email",
        "observables",
        "raw_excerpt",
        "notes",
    }


@pytest.mark.security
def test_a_type_confused_record_degrades_instead_of_raising() -> None:
    """Telemetry that lies about its own schema must not take the pipeline down."""
    hostile: list[dict[str, Any]] = [
        {"eventSource": "sts.amazonaws.com", "eventName": "X", "userIdentity": "not-a-mapping"},
        {"eventSource": ["sts.amazonaws.com"], "eventName": None},
        {"type": {"nested": "not-a-string"}, "exe": 5},
        {"eventType": "user.session.start", "actor": [], "outcome": []},
        {"_path": "conn", "id.orig_h": {"a": 1}, "id.resp_h": [2], "uid": "x"},
        {"event_type": "alert", "src_ip": None, "dest_ip": {}, "alert": "not-a-mapping"},
        {"userPrincipalName": 1234, "appDisplayName": {}, "status": []},
        {"NetworkMessageId": {}, "SenderFromAddress": [], "DeliveryAction": 7},
        {"message_id": None, "rfc2822_message_id": [], "sender_address": {}},
    ]
    for record in hostile:
        event = normalize(record)
        assert event.parse_status in {"structured", "partial", "text"}
        json.dumps(event.to_dict())  # must stay serializable


# --------------------------------------------------------------------------
# Email content never enters the platform
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_ingest_parser_reads_a_message_body() -> None:
    """Structural, not aspirational.

    Asserted over the AST rather than the raw text, so the module's own
    prose about *not* reading bodies cannot be mistaken for reading one —
    and so the check still holds if the field is read some way other than a
    literal ``.get("Body")``.

    Every string a parser passes to a lookup is collected and checked against
    the ban list, across all five domains: an email body must not enter the
    platform through any parser, not merely the email one.
    """
    banned = {field.lower() for field in FORBIDDEN_CONTENT_FIELDS}
    for path in _ingest_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            looked_up = isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "dig"}
            looked_up = looked_up or (
                isinstance(node.func, ast.Name) and node.func.id in {"dig", "first", "strings"}
            )
            if not looked_up:
                continue
            for argument in ast.walk(node):
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    assert argument.value.lower() not in banned, (
                        f"{path.name} reads {argument.value!r} — "
                        "message bodies must never be ingested"
                    )


@pytest.mark.security
def test_the_body_field_ban_list_is_still_declared() -> None:
    """The ban list is the test's input; an emptied list must fail loudly."""
    assert len(FORBIDDEN_CONTENT_FIELDS) >= 5
    assert "Body" in FORBIDDEN_CONTENT_FIELDS


@pytest.mark.security
def test_the_canonical_schema_has_no_body_field() -> None:
    event = normalize(_load("defender_email_phish"))
    email_fields = set(event.to_dict()["email"])
    assert email_fields == {
        "sender",
        "recipients",
        "subject",
        "message_id",
        "delivery_action",
        "urls",
    }


# --------------------------------------------------------------------------
# No ambient authority
# --------------------------------------------------------------------------

_BANNED_IMPORTS = {
    "subprocess",
    "socket",
    "shutil",
    "requests",
    "httpx",
    "urllib",
    "urllib.request",
    "pickle",
    "marshal",
    "ctypes",
    "importlib",
}
_BANNED_CALLS = {"eval", "exec", "compile", "open", "__import__", "input"}


def _ingest_modules() -> list[Path]:
    return sorted(_INGEST_ROOT.rglob("*.py"))


@pytest.mark.security
def test_ingest_imports_nothing_that_could_execute_or_reach_out() -> None:
    for path in _ingest_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {node.module}"


@pytest.mark.security
def test_ingest_calls_no_executor_and_opens_no_file() -> None:
    for path in _ingest_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path}: calls {node.func.id}()"


@pytest.mark.security
def test_ingest_reads_no_clock() -> None:
    """A substituted "now" would fabricate ordering the correlator trusts."""
    for path in _ingest_modules():
        source = path.read_text(encoding="utf-8")
        for forbidden in ("datetime.now(", "time.time(", "utcnow(", "date.today("):
            assert forbidden not in source, f"{path}: reads the clock via {forbidden}"


@pytest.mark.security
def test_ingest_is_importable_without_third_party_packages() -> None:
    """The runtime dependency set stays empty — a load-bearing repo property."""
    import importlib.metadata as metadata

    declared = metadata.requires("ianua") or []
    runtime = [req for req in declared if "extra ==" not in req]
    assert runtime == [], f"ingest must not introduce runtime dependencies: {runtime}"


def _load(name: str) -> dict:
    fixtures = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    record = fixtures[name]["record"]
    assert isinstance(record, dict)
    return record
