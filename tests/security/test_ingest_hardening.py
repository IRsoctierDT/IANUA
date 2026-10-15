# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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
* non-leaking — email bodies have no field to travel in, the parser modules
  never read one, and ``raw_excerpt`` is rebuilt from the paths a signature
  declared rather than copied from the record, so a field nobody modelled
  cannot ride along either;
* honest — degraded parses are labelled, so a partial understanding is never
  rendered as a confident analysis.
"""

from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import json
import re
import sys
import typing
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from ingest import (
    MAX_FIELD_LEN,
    MAX_NESTING_DEPTH,
    MAX_NOTES,
    MAX_OBSERVABLES,
    MAX_RAW_BYTES,
    MAX_RAW_EXCERPT,
    SIGNATURES,
    NormalizedEvent,
    _coerce,
    normalize,
    normalize_many,
)
from ingest._coerce import _DOMAIN, _HASH, _IPV4, _IPV6, _URL, observables, project
from ingest.errors import IngestError, MalformedProjectionError, UnsupportedInputError
from ingest.parsers.email import FORBIDDEN_CONTENT_FIELDS
from store import DEFAULT_FILENAME, EventStore

_REPO_ROOT = Path(__file__).resolve().parents[2]
_INGEST_ROOT = _REPO_ROOT / "ingest"
LAYER = "ingest"


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
def test_an_unrecognized_lines_excerpt_is_scrubbed_like_every_other_field() -> None:
    """``raw_excerpt`` was the one field written without passing ``text()``.

    On the claimed path the test above passed because ``json.dumps`` *escapes*
    a NUL rather than because anything removed it. On the text path nothing
    escaped it: an unrecognized syslog line carrying ``\x00`` or an ANSI
    escape stored those bytes verbatim in the excerpt, which is the field a
    dashboard and a report render. Both paths now coerce through ``text()``.
    """
    hostile = "sshd: auth failure for \x00\x07\x1b[31mroot\x1b[0m from 203.0.113.9"
    event = normalize(hostile)
    assert event.vendor == "unrecognized"
    assert event.parse_status == "text"
    for char in ("\x00", "\x07", "\x1b"):
        assert char not in event.raw_excerpt, f"control character {char!r} survived"
    # Scrubbed, not emptied: the line is still readable evidence.
    assert "203.0.113.9" in event.raw_excerpt
    assert "203.0.113.9" in event.observables


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
    """Only declared fields serialize — nothing from a record rides along.

    ``raw_excerpt`` used to be excluded from this claim, because it was a
    copy of the record and the key *did* appear in it. It is now rebuilt
    from the paths a signature declared, so the claim holds over the whole
    projection and the exclusion is gone.
    """
    record = dict(_load("cloudtrail_assume_role"))
    record["attackerControlledExtra"] = "should-not-appear"
    event = normalize(record)
    rendered = event.to_dict()
    assert "attackerControlledExtra" not in json.dumps(rendered)
    assert "should-not-appear" not in json.dumps(rendered)
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


# --------------------------------------------------------------------------
# The evidence allow-list
#
# The deny-list above says which fields a parser may not *read*. These say
# what a stored event may *contain*, which is the stronger claim and the one
# that holds when a parser stops recognizing its own vendor's records. There
# is no later redaction to fall back on: the store refuses UPDATE and
# ``event_id`` is a digest over the projection, so whatever ingest writes is
# kept for as long as the row is.
# --------------------------------------------------------------------------

#: A token no fixture, parser, or schema field can legitimately produce.
_MARKER = "UNMODELLED-VALUE-7f3a91"


def _stuff(value: Any, key: str) -> Any:
    """Add an un-modelled key to ``value`` and to every mapping inside it."""
    if isinstance(value, dict):
        stuffed = {name: _stuff(child, key) for name, child in value.items()}
        stuffed[key] = _MARKER
        return stuffed
    if isinstance(value, list):
        return [_stuff(child, key) for child in value]
    return value


def _fixture_names() -> list[str]:
    fixtures = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    return sorted(fixtures)


@pytest.mark.security
@pytest.mark.parametrize("name", _fixture_names())
@pytest.mark.parametrize("key", ["attackerChosen", "Body", "notes", "message"])
def test_an_unmodelled_field_reaches_no_part_of_a_stored_event(name: str, key: str) -> None:
    """At every nesting level, under four key names, in all ten formats.

    ``Body`` is the field the charter cares about; ``attackerChosen`` is the
    general case; ``notes`` and ``message`` are named after real event fields,
    because a projection that merged a record's keys with the schema's own
    would be a worse bug than the leak it replaced.
    """
    record = _stuff(_load(name), key)
    event = normalize(record)
    assert _MARKER not in json.dumps(event.to_dict(), default=str), (
        f"{name}: an un-modelled {key!r} reached the stored projection"
    )


@pytest.mark.security
def test_an_unmodelled_field_survives_neither_recognition_nor_its_loss() -> None:
    """The regression path: a vendor renames the key a signature recognizes.

    This is how a body would actually reach a store — not through a parser
    that reads one, but through a record that no longer looks like the format
    it is. The excerpt then comes from the union of every parser's declared
    paths, so the metadata survives and the body does not.
    """
    record = dict(_load("defender_email_phish"))
    record["Body"] = f"wire the funds {_MARKER}"
    recognized = normalize(record)
    assert recognized.vendor == "defender-o365"
    assert _MARKER not in json.dumps(recognized.to_dict(), default=str)

    renamed = {
        ("NetworkMessageIdV2" if k == "NetworkMessageId" else k): v for k, v in record.items()
    }
    unclaimed = normalize(json.dumps(renamed))
    assert unclaimed.vendor == "unrecognized"
    assert _MARKER not in json.dumps(unclaimed.to_dict(), default=str)
    # Degrade visibly: the excerpt still carries what some parser modelled...
    assert str(record["Subject"]) in unclaimed.raw_excerpt
    # ...and the note names the key that was withheld, so an operator can fix
    # the signature rather than wonder why the record went quiet.
    assert any("Body" in note for note in unclaimed.notes)


@pytest.mark.security
def test_a_key_value_line_is_projected_like_any_other_record() -> None:
    """``ingest/keyvalue.py`` decodes auditd text into a mapping; same rule applies."""
    line = (
        'type=USER_AUTH msg=audit(1760000000.1:1) acct="svc-deploy" '
        f"addr=203.0.113.9 res=failed proctitle=sshd secret={_MARKER}"
    )
    event = normalize(line)
    assert event.vendor == "auditd"
    assert _MARKER not in json.dumps(event.to_dict(), default=str)


#: Shapes that reach `_unrecognized` with their text intact, because they
#: never decoded into a mapping and so have nothing to project. Each is a
#: *stated residual* of the allow-list, not an oversight — see AGENTS.md §5's
#: stage-6 amendment, which the first version of this control overstated.
_UNDECODABLE = ("trailing-comma", "json-array", "over-the-size-ceiling")


def _undecodable(shape: str, body: str) -> str:
    record = {
        "Timestamp": "2026-10-15T09:00:00Z",
        "NetworkMessageId": "nmi-1",
        "SenderFromAddress": "payroll@vendor.example",
        "Subject": "Updated bank details",
        "DeliveryAction": "Delivered",
        "Body": body,
    }
    whole = json.dumps(record)
    if shape == "trailing-comma":
        return whole[:-1] + ",}"
    if shape == "json-array":
        return f"[{whole}]"
    return whole + " " + "x" * (MAX_RAW_BYTES + 1)


@pytest.mark.security
@pytest.mark.parametrize("shape", _UNDECODABLE)
def test_a_record_that_never_decodes_to_a_mapping_keeps_its_text(shape: str) -> None:
    """Pins the residual, so the claim and the code cannot drift apart again.

    This asserts a **limitation**, deliberately. The allow-list covers records
    that decode to a mapping; these three do not, so there is no mapping to
    project and the text is carried whole — which means an un-modelled body in
    one of them *does* reach `message` and `raw_excerpt`.

    The charter's first version of this amendment claimed the allow-list left
    "no route into a stored event" without that qualifier, and described the
    residual as "ordinary syslog prose". Both were wrong: a JSON record with a
    trailing comma, a JSON array, and a record over `MAX_RAW_BYTES` all take
    this path, and a line truncated mid-write by log rotation is a realistic
    instance rather than a contrived one. Dropping the text instead would
    manufacture the blind spot rule 2 exists to close, so the behaviour stands
    — and this test exists so that nobody re-reads the amendment and believes
    the stronger claim.
    """
    body = "wire to IBAN GB29NWBK60161331926819"
    event = normalize(_undecodable(shape, body))
    assert event.vendor == "unrecognized"
    rendered = json.dumps(event.to_dict(), default=str)
    assert body in rendered, (
        "the residual documented in AGENTS.md §5 no longer holds — if this is a "
        "deliberate improvement, update the amendment and DESIGN.md boundary 9 with it"
    )


@pytest.mark.security
def test_a_well_formed_record_of_the_same_shape_does_not_keep_its_body() -> None:
    """The control itself, beside the residual, so the difference is visible."""
    body = "wire to IBAN GB29NWBK60161331926819"
    whole = _undecodable("trailing-comma", body)[:-2] + "}"  # repair the comma
    event = normalize(whole)
    assert event.vendor == "defender-o365"
    assert body not in json.dumps(event.to_dict(), default=str)


@pytest.mark.security
def test_the_withheld_note_counts_raw_keys_and_sanitizes_only_for_display() -> None:
    """The note is a diagnostic an operator acts on, so it must not lie.

    Sanitizing before the comparison made it wrong three ways at once: a key
    spelled ``Body\n\x07`` was reported as ``Body``, which the record does not
    contain; a key spelled ``Subject\x00`` sanitized to a name that *is* in the
    projection and so was not reported at all, though its value was withheld;
    and two raw keys collapsing to one name double-counted. Measured, then
    fixed by comparing raw keys and sanitizing afterwards.
    """
    event = normalize(
        {"NetworkMessageId2": "x", "Subject": "s", "Body\n\x07": "leak", "Subject\x00": "dup"}
    )
    note = next(entry for entry in event.notes if "withheld" in entry)
    # Four raw keys, one of which (`Subject`) is modelled and retained.
    assert note.startswith("3 of 4 top-level record keys"), note
    assert event.raw_excerpt == '{"Subject": "s"}'
    # Every withheld key is named, and no control character reaches the note.
    for name in ("Body", "NetworkMessageId2", "Subject"):
        assert name in note
    assert "\x00" not in note
    assert "\x07" not in note


@pytest.mark.security
def test_no_signature_declares_a_content_bearing_field() -> None:
    """The deny-list applies to the declarations too, and an AST walk misses them.

    ``test_no_parser_reads_a_message_body`` looks for body-shaped names inside
    ``.get``/``dig`` calls. A ``fields`` tuple is neither, so without this a
    declared ``("Body",)`` would sail past it and put the body straight back.
    """
    banned = {field.lower() for field in FORBIDDEN_CONTENT_FIELDS}
    for signature in SIGNATURES:
        for path in signature.fields:
            for key in path:
                assert key.lower() not in banned, (
                    f"{signature.vendor} declares {key!r} as retainable evidence"
                )


@pytest.mark.security
def test_the_withheld_key_note_stays_readable_after_it_is_written() -> None:
    """An attacker picks the key names, so the note they produce is untrusted.

    ``from_dict`` validates every note at ``MAX_FIELD_LEN``. A note built from
    two hundred long key names would make the event writable and then
    permanently unreadable — the defect class recorded in ``_unrecognized``,
    reached this time through a field the attacker controls. Asserted by
    round-tripping, not by reading the bound off the same constant.
    """
    record = {f"{'k' * 200}{index}": index for index in range(200)}
    event = normalize(record)
    assert event.vendor == "unrecognized"
    assert all(len(note) <= MAX_FIELD_LEN for note in event.notes)
    assert NormalizedEvent.from_dict(event.to_dict()) == event


@pytest.mark.security
def test_indicators_come_only_from_modelled_content_on_every_path() -> None:
    """The posture this test pins **replaces** the one it used to pin.

    It previously asserted the opposite: that an unclaimed record was scanned
    *in full*, so a URL reachable only through an un-modelled ``Body`` was
    still extracted. That was a deliberate trade — "the indicator survives
    and the sentence does not" — and it did not hold. Fragments of the
    sentence survived too: measured on merged code, an un-modelled ``Body``
    reading "Dear Mr.Jones, please urgently.Reply ... invoice 44.Smith at
    acct-7781.Watson" produced ``raw_excerpt`` of ``{}`` and five
    observables — ``Mr.Jones``, ``urgently.Reply``, ``44.Smith``,
    ``acct-7781.Watson``, ``Ms.Delacroix`` — because ``_DOMAIN`` matches any
    ``word.Word`` with no plausibility check. Those are personal names, in an
    indexed append-only table that only whole-row deletion can clear, and
    they are false correlation join keys besides.

    The owner chose to extract from modelled content only, over adding a
    public-suffix dependency or a hand-kept TLD allow-list. **The cost is
    asserted here rather than left implicit**: an indicator that appears only
    in an un-modelled field is now lost, on both paths. That is a real
    detection cost on the one route §5 cared about — a vendor renaming the key
    a signature matches — and the compensating signal is the withheld-key
    note, which names what was dropped so an operator can write the
    signature.

    That sentence was the *whole* stated cost in the first version of this
    change and it was too narrow, which a reviewer caught: handing the
    serialized projection to ``observables()`` applied a per-field bound to
    the concatenation, so an indicator in a **modelled** field was lost too
    whenever the projection ran past ``MAX_FIELD_LEN`` and that field sorted
    late. Fixed by scanning each projected value, and pinned by
    ``test_a_modelled_field_is_scanned_however_late_it_sorts`` below — the
    narrow claim is true again because the code was corrected, not because the
    claim was.
    """
    record = dict(_load("defender_email_phish"))
    record["Body"] = f"click http://evil.example/x now {_MARKER}"
    renamed = {
        ("NetworkMessageIdV2" if key == "NetworkMessageId" else key): value
        for key, value in record.items()
    }

    unclaimed = normalize(json.dumps(renamed))
    assert unclaimed.vendor == "unrecognized"
    # The cost, named: this used to be `in`.
    assert "http://evil.example/x" not in unclaimed.observables
    assert _MARKER not in json.dumps(unclaimed.to_dict(), default=str)
    # Correlation is not blinded for what *was* modelled: the record's own
    # declared paths still yield their indicators, so an unclaimed record is
    # still joinable on everything the union of signatures covers.
    assert unclaimed.observables, (
        "an unclaimed record lost every indicator, not just the withheld one"
    )
    assert any("partner" in value for value in unclaimed.observables), unclaimed.observables
    # And the operator is still told what was dropped.
    assert any("modelled by no parser" in note for note in unclaimed.notes)

    claimed = normalize(record)
    assert claimed.vendor == "defender-o365"
    assert "http://evil.example/x" not in claimed.observables
    assert _MARKER not in json.dumps(claimed.to_dict(), default=str)


#: The one indicator every record in the position table below carries.
_INDICATOR_URL = "http://indicator.example/p"

#: One record per *position* an indicator can occupy relative to the two
#: bounds that govern this layer — ``MAX_FIELD_LEN`` per value and
#: ``MAX_RAW_EXCERPT`` on the excerpt as a whole.
#:
#: Position is the variable, and that is the whole point of the table. Five
#: review rounds landed on this function's scan source, and every one of them
#: was an indicator at one of these positions being handled as though it were
#: at another. A fixture corpus of well-behaved telemetry exercises only the
#: first row.
#:
#: ``@timestamp``, ``Channel``, ``CommandLine`` and ``Subject`` are all
#: declared paths; ``Body`` is declared by no parser; the renamed provider key
#: is what makes each record unclaimed.
#: ``(id, record, must_be_extracted)``. The third element is the whole point:
#: it is stated per row rather than derived, so neither direction of the
#: property can drift into the other.
_INDICATOR_POSITIONS: tuple[tuple[str, dict[str, object], bool], ...] = (
    # The easy case, first so that a change breaking everything is not read as
    # a change breaking only the hard cases.
    ("first-leaf", {"ProviderV2": "x", "@timestamp": _INDICATOR_URL, "Subject": "s"}, True),
    # Round one (#214): a modelled field sorting after a long one. Retained at
    # index 2085, and the per-value bound had been applied to the
    # concatenation, so it was not scanned.
    (
        "late-sorting",
        {"ProviderV2": "x", "@timestamp": "T" * 2048, "Subject": f"visit {_INDICATOR_URL}"},
        True,
    ),
    # Round five (review of 42aece5): the 4096 slice falls *inside* Subject,
    # whose value begins with the URL. Retained and readable at index 3594,
    # and the walk discarded the cut leaf wholesale rather than the part of it
    # the excerpt still held.
    (
        "in-the-cut-leaf",
        {
            "ProviderV2": "x",
            "@timestamp": "T" * 2048,
            "Channel": "C" * 1500,
            "Subject": _INDICATOR_URL + " " + "P" * 3000,
        },
        # Retained and NOT extracted: the accepted loss. See the docstring.
        False,
    ),
    # Round two (#215): the projection exceeds MAX_RAW_EXCERPT and Subject
    # lands wholly past the cut, so the URL is in no retained field and must
    # not be scanned.
    (
        "past-the-cut",
        {
            "ProviderV2": "x",
            "@timestamp": "T" * 2048,
            "Channel": "C" * 2048,
            "CommandLine": "L" * 2048,
            "Subject": f"visit {_INDICATOR_URL}",
        },
        False,
    ),
    # Stage 6: a field no parser models. Neither retained nor scanned.
    ("un-modelled", {"ProviderV2": "x", "Subject": "s", "Body": f"see {_INDICATOR_URL}"}, False),
)

_POSITION_IDS = [position for position, _, _ in _INDICATOR_POSITIONS]
_POSITION_CASES = [(record, extracted) for _, record, extracted in _INDICATOR_POSITIONS]
_POSITION_RECORDS = [record for _, record, _ in _INDICATOR_POSITIONS]


@pytest.mark.security
@pytest.mark.parametrize(("record", "extractable"), _POSITION_CASES, ids=_POSITION_IDS)
def test_an_indicator_is_extracted_only_when_the_excerpt_retains_it(
    record: dict[str, object], extractable: bool
) -> None:
    """Never extracted unless retained, and extracted where we can attribute it.

    This is the assertion the previous four rounds needed and none of them
    made. Each earlier test said *if* an observable exists *then* something
    retained accounts for it, which an empty ``observables`` tuple satisfies
    in zero iterations. Round five was exactly that: an indicator present and
    readable at index 3594 of a 4096-character excerpt, extracted into
    nothing, with both property tests green. Review found it; the tests could
    not have.

    Stated as an equality in both directions, the whole history collapses into
    one line:

        in excerpt, extracted      first-leaf, late-sorting (round one),
                                   in-the-cut-leaf (round five)
        not in excerpt, not        past-the-cut (round two), un-modelled
        extracted                  (stage 6)

    Either direction failing is a defect, and they are opposite defects: a
    false positive puts an indicator derived from unretained content into an
    append-only index, and a false negative silently loses evidence an
    operator can see with their own eyes. Three of the five fixes closed one
    direction and opened the other, which is why neither half may be asserted
    without the other.
    """
    event = normalize(record)

    assert event.vendor == "unrecognized", "fixture must take the unclaimed path"
    retained = _INDICATOR_URL in event.raw_excerpt
    extracted = _INDICATOR_URL in event.observables

    # Direction one, unconditional: nothing is extracted that the evidence
    # cannot account for. This is the half that must never weaken.
    if extracted:
        assert retained, (
            "indicator was extracted but is in no retained field — a fabricated "
            "join key in an append-only index"
        )
    # Direction two, per row: where the row says the indicator is attributable,
    # it must actually be extracted, so narrowing cannot quietly lose it.
    assert extracted is extractable, (
        f"row expects extracted={extractable} and got {extracted} (retained={retained})"
    )


#: Offsets that walk the 4096-character excerpt cut across a ``Subject``.
#: Both regimes — the indicator retained whole, and the cut landing inside it
#: — have to occur for the sweep to prove anything, which is asserted below
#: rather than assumed. Measured over these 148 offsets:
#:
#:     payload   complete  cut-inside
#:     url             74          21
#:     sha256          39          56
#:     ipv6            64          31
#:     domain          73          22
#:     hexrun          53          42
_CUT_SWEEP = range(1900, 2048)

#: One payload per extractor in :func:`~ingest._coerce.observables`, because a
#: cut can fabricate an indicator from any of them and the first version of
#: this test covered the two that are *least* affected. Measured by reverting
#: the trim, which is how the gap was found — cases produced per payload:
#:
#:     ipv6 28 · domain 23 · url 19 · sha256 2 · hexrun 2
#:
#: ``hexrun`` is the sharpest of the five and the reason "severed" is the wrong
#: word for the whole class. Fifty hex characters match **nothing** — ``_HASH``
#: wants exactly 32, 40 or 64 — so truncating it does not sever a real
#: indicator, it *manufactures* one that was never there.
_CUT_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("url", "http://indicator.example/path"),
    ("sha256", "a" * 63 + "b"),
    ("ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("domain", "deep.sub.indicator.example.com"),
    ("hexrun", "f" * 50),
    # Non-ASCII, added after review found the tail scan fabricating from an
    # escape. `_serialize` renders `é` as `\u00e9` and backslash is an
    # indicator terminator, so the tail matched `http://indicator.example/pay/caf`
    # as a whole URL — 10 of 148 offsets. Every other payload here is pure
    # ASCII, which is why five of them missed it: the same mistake as choosing
    # url and sha256 first, one layer down.
    ("non-ascii-url", "http://indicator.example/pay/caf\u00e9"),
)

_CUT_IDS = [name for name, _ in _CUT_PAYLOADS]
_CUT_VALUES = [payload for _, payload in _CUT_PAYLOADS]


def _cut_at(offset: int, payload: str) -> dict[str, object]:
    """An unclaimed record whose excerpt boundary falls ``offset`` bytes in."""
    return {
        "ProviderV2": "x",
        "@timestamp": "T" * 2048,
        "Channel": "C" * offset,
        "Subject": payload,
    }


@pytest.mark.security
@pytest.mark.parametrize("payload", _CUT_VALUES, ids=_CUT_IDS)
def test_no_observable_is_an_indicator_the_excerpt_slice_cut(payload: str) -> None:
    """A severed indicator is worse than a lost one: it is a *false* join key.

    Round six, and the first defect in this function that **added something
    false** rather than losing something true. Round five's fix handed the
    excerpt's trailing text to ``observables()``, and a hard character slice
    can land inside an indicator, so the severed prefix was extracted as
    though it were whole. Measured on that version across these offsets:

        ipv6 28 · domain 23 · url 19 · sha256 2 · hexrun 2

    offsets per payload, out of 148. The sha256 case is the one review's
    example reached and it is the *rarest*; the first version of this test
    covered url and sha256, the two least-affected of the five. Widening it to
    one payload per extractor was not tidiness — it was finding that the
    chosen coverage was the weakest available.

    The hash case is why this is a security defect and not a precision nit. A
    40-character hex string that never hashed anything is a *plausible* IOC,
    it lands in an indexed append-only column, and
    ``correlation/entities.py`` joins entities on it. A gap in evidence is
    recoverable; a fabricated join key is not, because ``UPDATE`` is refused
    and the row can only be pruned whole.

    The biconditional above does not catch this and cannot: it asks whether
    one exact string is extracted iff retained, and for a cut indicator the
    exact string is neither — ``False == False``. Asking a different question
    is the whole point of this test. Found by review.
    """
    truncated = [
        (offset, observable)
        for offset in _CUT_SWEEP
        for observable in normalize(_cut_at(offset, payload)).observables
        if observable != payload and payload.startswith(observable)
    ]

    assert not truncated, (
        f"{len(truncated)} offset(s) extracted a severed prefix of {payload!r}: {truncated[:4]}"
    )


@pytest.mark.security
@pytest.mark.parametrize("payload", _CUT_VALUES, ids=_CUT_IDS)
def test_that_sweep_actually_walks_the_cut_through_the_indicator(payload: str) -> None:
    """Both regimes must occur, or the sweep above is green over nothing.

    A range that never brought the slice near the payload would satisfy the
    no-severed-prefix assertion trivially — the level-above failure that let
    round five through twice.
    """
    # Compared against the payload as the excerpt actually stores it, not as
    # it was written. `_serialize` renders with `ensure_ascii=True`, so the
    # non-ASCII payload is `...caf\u00e9` in `raw_excerpt` and a literal
    # membership test finds it at zero offsets. This guard caught exactly that
    # when the payload was added — which is what it is for, so the comparison
    # is corrected rather than the payload dropped.
    stored = json.dumps(payload)[1:-1]
    complete = severed = 0
    for offset in _CUT_SWEEP:
        excerpt = normalize(_cut_at(offset, payload)).raw_excerpt
        if stored in excerpt:
            complete += 1
        elif stored[:8] in excerpt:
            severed += 1

    assert complete >= 5, f"no offset retains {payload!r} whole ({complete})"
    assert severed >= 5, f"no offset cuts into {payload!r} ({severed})"


#: Offsets that walk the ``MAX_FIELD_LEN`` bound across a payload on the
#: *carried* path — plain text, which no parser models. Measured regimes over
#: these 70 offsets, bound-after-payload / bound-inside-payload:
#:
#:     url 29/23 · sha256 0/52 · ipv6 19/33 · domain 28/24 · hexrun 8/44
_BOUND_SWEEP = range(1990, 2060)


@pytest.mark.security
@pytest.mark.parametrize("payload", _CUT_VALUES[:5], ids=_CUT_IDS[:5])
def test_the_field_bound_never_fabricates_an_indicator(payload: str) -> None:
    """``MAX_FIELD_LEN`` is a cut like any other, and a cut can forge an IOC.

    Round ten, and the one that located the mechanism rather than another of
    its symptoms. Rounds six and eight guarded an excerpt tail *as it was
    built*; round nine showed ``text()``'s own bound runs afterwards and
    defeats any such guard; this one showed that deleting the tail did not
    help, because the same bound is applied by ``observables()`` to **every**
    value it is given. The carried path is the plain demonstration — it
    handles plain text, malformed JSON and oversized records, i.e. exactly the
    input no parser got to model:

        normalize("P"*2007 + " " + "f"*50 + " tail")
          50-char hex run retained in raw_excerpt : True
          observables                             : ('f'*40,)   <- a sha1

    A 50-character hex run matches no hash pattern at all, so the bound did
    not sever a real indicator — it **manufactured** one. The guard now lives
    in ``observables()`` itself, which applies each value's own cut to that
    value's own matches, so it covers every caller including the ten parsers
    rather than one call site.

    This paragraph said the guard lived in ``_coerce._bounded_for_scan``
    through rounds eleven and twelve, by which point that helper had been
    deleted. A docstring naming code that is gone is the same defect class
    these rounds keep finding, one file over.

    Swept rather than taken at one offset, because three of the four previous
    rounds here were argued from a single case.
    """
    fabricated = [
        (offset, observable)
        for offset in _BOUND_SWEEP
        for observable in normalize("P" * offset + " " + payload + " tail").observables
        if observable != payload and payload.startswith(observable)
    ]

    assert not fabricated, (
        f"{len(fabricated)} offset(s) forged a prefix of {payload!r} at the "
        f"field bound: {fabricated[:4]}"
    )


@pytest.mark.security
@pytest.mark.parametrize("payload", _CUT_VALUES[:5], ids=_CUT_IDS[:5])
def test_that_bound_sweep_actually_walks_the_cut_through_the_payload(
    payload: str,
) -> None:
    """Both regimes must occur or the sweep above is green over nothing."""
    whole = inside = 0
    for offset in _BOUND_SWEEP:
        message = normalize("P" * offset + " " + payload + " tail").message or ""
        if payload in message:
            whole += 1
        elif payload[:6] in message:
            inside += 1

    assert inside >= 5, f"the bound never lands inside {payload!r} ({inside})"
    assert whole + inside >= 20, (
        f"{payload!r} is barely reached by this offset range (whole={whole}, inside={inside})"
    )


@pytest.mark.security
def test_the_field_bound_trim_loses_nothing_at_or_under_the_bound() -> None:
    """The corpus has no value near ``MAX_FIELD_LEN``, so these pin that edge.

    The cut is applied to each match's span rather than to the text, and the
    committed corpus cannot exercise that at all: its longest value is far
    under the bound. So the risk is an indicator dropped that the bound never
    severed — a silent loss on real telemetry — and these are the cases that
    would show it.

    The last row is the one worth keeping. ``_WHITESPACE_RUN`` is
    ``[\t\n\r]+`` and so does **not** collapse spaces; a value of
    space-separated tokens therefore truncates, but when the cut lands on a
    space no token is severed and the trim is correctly a no-op. I had assumed
    spaces collapsed, which made that case look like a truncated value
    escaping the trim.
    """
    url = "http://edge.example/p"

    for label, pad, expected in (
        ("ends one before the bound", MAX_FIELD_LEN - len(url) - 2, True),
        ("ends exactly at the bound", MAX_FIELD_LEN - len(url) - 1, True),
        ("ends one past the bound", MAX_FIELD_LEN - len(url), False),
    ):
        value = "P" * pad + " " + url
        assert (url in observables(value)) is expected, (
            f"{label}: url_extracted={url in observables(value)}, "
            f"expected {expected} (value length {len(value)}, "
            f"bound {MAX_FIELD_LEN})"
        )

    # Asserted through `observables()` rather than against the coercion
    # helper's return shape, which has now changed three times while this
    # behaviour has not. A test coupled to the shape broke on each rename and
    # said nothing about the bound.
    #
    # A value whose indicator sits past the bound yields nothing — that is
    # round two, and it must stay true.
    assert not observables("P" * MAX_FIELD_LEN + " " + url), (
        "an indicator wholly past the bound was extracted"
    )
    # And a value long enough to be cut still yields the indicators that fit.
    assert url in observables(url + " " + "P" * (MAX_FIELD_LEN * 2)), (
        "an indicator wholly inside the bound was dropped from a long value"
    )


#: ``(id, value, must_extract)`` for the two directions the bound has to get
#: right at once. Every row's indicator ends *well* before the cut; what
#: differs is whether a second, severable token follows it.
_BOUND_CASES: tuple[tuple[str, str, bool], ...] = (
    # Complete indicators followed by punctuation `_URL` permits but the
    # narrower extractors terminate on. Round eleven: a trim defined by
    # `_URL`'s class treated these as ONE token and deleted the indicator with
    # the padding, losing telemetry that ends at character 12.
    ("ip-then-comma", "198.51.100.7," + "A" * 3000, True),
    ("ip-then-semicolon", "198.51.100.7;" + "A" * 3000, True),
    ("ip-then-paren", "198.51.100.7)" + "A" * 3000, True),
    ("sha256-then-comma", "a" * 64 + "," + "A" * 3000, True),
    ("domain-then-paren", "evil.example.com)" + "A" * 3000, True),
    # And the fabrications, which must stay closed: a 50-character hex run
    # matches no hash until the bound cuts it to 40, and a 64-character sha256
    # pushed past the bound becomes a sha1.
    ("fifty-hex-run", "P" * 2007 + " " + "f" * 50 + " tail", False),
    # The space is load-bearing and was missing. `_HASH` anchors on `\b`, and
    # `"P" * 2008 + "a" * 63` is one unbroken run of word characters, so no
    # match could start at the hex run under *any* version of this code.
    # Measured against the pre-round-ten slice-then-match shape: the
    # `fifty-hex-run` row above fabricated a sha1 and this one produced `[]`.
    # So the row asserted `not extracted` over something unreachable. Found in
    # round twelve, by planting a shrunken lookahead and noticing this row
    # stayed green when the plant should have reached it.
    ("sha256-cut-at-40", "P" * 2007 + " " + "a" * 63 + "b", False),
)


@pytest.mark.security
@pytest.mark.parametrize(
    ("value", "must_extract"),
    [(value, keep) for _, value, keep in _BOUND_CASES],
    ids=[name for name, _, _ in _BOUND_CASES],
)
def test_the_field_bound_drops_only_what_it_severed(value: str, must_extract: bool) -> None:
    """Both directions of the bound at once, because fixing one broke the other.

    Round ten put the guard at the cut, which was the right place. Round eleven
    showed the guard's *shape* was still wrong: it trimmed a trailing "token",
    and the only character class wide enough to bound every extractor —
    ``_URL``'s — is too wide to delimit one. A comma is legal inside a URL and
    terminates ``_IPV4``, so ``198.51.100.7,`` plus padding was one token and a
    complete IP ending at character 12 was deleted. Measured then:

        ip then comma      -> ()
        sha256 then comma  -> ()
        domain then paren  -> ()
        ip then space      -> extracted   (whitespace was the only survivor)

    So nothing is deleted now. ``observables()`` discards exactly the matches
    whose span *ends at* the cut, which needs no character class: a match
    ending earlier was terminated by a real character, and one ending at the
    boundary is the only one the slice can have severed. Five rounds of
    guessing a class, replaced by a position comparison that cannot be wrong
    about which extractor terminates where.
    """
    extracted = observables(value)

    if must_extract:
        assert extracted, "a complete indicator ending well before the bound was dropped"
    else:
        assert not extracted, f"the bound fabricated {extracted!r}"


#: Inputs built to maximise each extractor's match, from that pattern's own
#: quantifiers, with an over-long variant where one can confirm the quantifier
#: caps the match rather than the input running out. Measured contribution,
#: probe to width:
#:
#:     _IPV4    15  from ipv4 and ipv4-overlong
#:     _IPV6    39  from ipv6 and ipv6-overlong
#:     _HASH    64  from hash only
#:     _URL    264  from url (itself 308 characters, so it caps)
#:     _DOMAIN 408  from domain and domain-overlong
#:
#: ``hash-overlong`` contributes **nothing** and the row is kept to say so:
#: ``_HASH`` anchors on ``\b`` at both ends, so an unbroken 200-character run
#: has no interior boundary and matches at no length. There is therefore no
#: probe here that would catch a *new* ``_HASH`` alternative — only the
#: pattern digest above does, which is why it exists.
_MAXIMAL_FOR: tuple[tuple[str, str], ...] = (
    ("ipv4", "255.255.255.255"),
    ("ipv4-overlong", "255." * 20 + "255"),
    ("ipv6", "aaaa:" * 7 + "aaaa"),
    ("ipv6-overlong", "aaaa:" * 20 + "aaaa"),
    ("hash", "a" * 64),
    ("hash-overlong", "a" * 200),
    ("url", "https://" + "a" * 300),
    ("domain", ("a" + "b" * 61 + "c.") * 6 + "d" * 24),
    # 24 d's, not 60. A `[A-Za-z]{2,24}` TLD followed by more letters can
    # never satisfy its trailing `\b`, so a 60-character tail made this probe
    # match *nothing* and the over-long case contributed no width at all.
    # Measured by planting `{1,6}` -> `{1,60}` in `_DOMAIN`: the full suite
    # stayed green, 217 passed, with a pattern that can match 3864 characters
    # against a 1024-character lookahead.
    ("domain-overlong", ("a" + "b" * 61 + "c.") * 20 + "d" * 24),
)

#: Widest match each extractor can produce, measured over the corpus above.
#: Recorded per pattern rather than as one number so a widening of any single
#: pattern is attributed, and so the margin's headroom is visible.
_WIDEST_MATCH: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("_IPV4", _IPV4, 15),
    ("_IPV6", _IPV6, 39),
    ("_HASH", _HASH, 64),
    ("_URL", _URL, 264),
    ("_DOMAIN", _DOMAIN, 408),
)


#: sha256 over the five extractor patterns, exactly as the measured widths
#: below were taken from them:
#:
#:     _IPV4    \b(?:\d{1,3}\.){3}\d{1,3}\b
#:     _IPV6    \b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b
#:     _HASH    \b(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})\b
#:     _URL     \bhttps?://[^\s\"'<>\\]{3,256}
#:     _DOMAIN  \b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,6}[A-Za-z]{2,24}\b
#:
#: Pinned as a digest rather than as five string literals because the width
#: corpus below is built *from these quantifiers*, so it cannot cover a
#: quantifier that does not exist yet — a new ``_HASH`` alternative would need
#: a probe with the right word boundaries and the committed corpus would stay
#: green. Pinning the source text instead makes any edit to a pattern fail
#: here and send the author back to re-measure. Same shape as the mapping
#: ruleset and intel library digests (AGENTS.md §7 step 6).
_PATTERN_DIGEST = "6df689241f37b388d6c027f8e075284375ddafb9b87a7da35b06517eb09e4244"


def _pattern_digest() -> str:
    """sha256 over the live extractor patterns, named so a diff is readable."""
    joined = "\n".join(f"{name}={pattern.pattern}" for name, pattern, _ in _WIDEST_MATCH)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


@pytest.mark.security
def test_the_extractor_patterns_are_the_ones_the_widths_were_measured_from() -> None:
    """Any edit to a pattern invalidates the lookahead, so pin the sources.

    Not a style check. ``_SCAN_LOOKAHEAD`` is sound only while it exceeds the
    widest match these five can produce, and the widths below are measured
    from inputs built to each pattern's current quantifiers. Widen a
    quantifier and the matching probe silently stops being maximal — measured:
    ``{1,6}`` to ``{1,60}`` in ``_DOMAIN`` left the whole suite green with a
    pattern that can match 3864 characters against a 1024-character lookahead,
    because the over-long domain probe had a 60-character tail and a
    ``[A-Za-z]{2,24}`` TLD followed by more letters can never satisfy its
    trailing ``\\b``. The probe is fixed; this digest is what stops the next
    one from being wrong silently.
    """
    assert _pattern_digest() == _PATTERN_DIGEST, (
        "an extractor pattern changed:\n"
        + "\n".join(f"  {name} = {pattern.pattern}" for name, pattern, _ in _WIDEST_MATCH)
        + f"\nre-measure the widest match each can produce and recheck "
        f"_SCAN_LOOKAHEAD ({_coerce._SCAN_LOOKAHEAD}) against it, then update "
        "_PATTERN_DIGEST and the widths in _WIDEST_MATCH"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    ("name", "pattern", "widest"),
    _WIDEST_MATCH,
    ids=[name for name, _, _ in _WIDEST_MATCH],
)
def test_no_extractor_can_match_wider_than_the_scan_lookahead(
    name: str, pattern: re.Pattern[str], widest: int
) -> None:
    """The lookahead must exceed every match width, or the window severs one.

    ``observables()`` scans ``MAX_FIELD_LEN + _SCAN_LOOKAHEAD`` characters and
    keeps the matches ending at or before ``MAX_FIELD_LEN``. That is equivalent
    to scanning the whole record **only** while no match beginning at or before
    the cut can reach past the window edge — so the lookahead has to be wider
    than the widest match any of these five can produce.

    Measured, not derived from the quantifiers: a derivation from these five
    patterns has been wrong in four of the last six review rounds on this
    function. The expected widths are recorded so a pattern that widens shows
    up as this test failing rather than as an extraction that silently
    disagrees with a full scan.
    """
    measured = max(
        (len(match.group()) for _, probe in _MAXIMAL_FOR for match in pattern.finditer(probe)),
        default=0,
    )
    assert measured == widest, (
        f"{name} now matches up to {measured} characters, not {widest} — "
        f"recheck _SCAN_LOOKAHEAD ({_coerce._SCAN_LOOKAHEAD}) against it"
    )
    assert measured < _coerce._SCAN_LOOKAHEAD, (
        f"{name} can match {measured} characters, which the "
        f"{_coerce._SCAN_LOOKAHEAD}-character lookahead cannot span"
    )


def _straddling_domain(gap_labels: int = 5, tld: int = 24) -> str:
    """A value whose short domain ends at the cut and whose long one runs past.

    This is the shape that makes the window observable at all, and it took
    three attempts to build. The gap between the two matches is label content
    no extractor can *end* on — a ``_DOMAIN`` TLD is letters, so a label
    closing on a digit offers no valid end and a hyphen run offers none either
    — which is what stops the window's own edge from simply terminating a
    match there.

    * short form ``a.bc``, ending exactly at ``MAX_FIELD_LEN``, kept by a
      scan that cannot see past the window;
    * long form ``a.bc------…1.a------…1.…zzz``, 346 characters, which a full
      scan matches instead and then discards for ending past the cut.

    So a window too narrow to hold the long form extracts an indicator the
    record does not contain. Measured: margins 0..319 fabricate ``a.bc``.
    """
    head = "a.bc"
    labels = ["bc" + "-" * 60 + "1"] + ["a" + "-" * 61 + "1"] * (gap_labels - 1)
    tail = "a." + ".".join(labels) + "." + "z" * tld
    start = MAX_FIELD_LEN - len(head)
    return "P" * (start - 1) + " " + tail + " end"


def _ending_at_the_cut(indicator: str, tail: str) -> str:
    """A value whose indicator ends exactly at the cut, with ``tail`` after it.

    The kept side of the window, which the first version of this corpus had
    almost none of: ten of its eleven values were built around an indicator the
    cut discards, so ``test_the_window_corpus_actually_reaches_past_the_window``
    failed on its own corpus. That is the precondition doing its job, and the
    corpus is widened rather than the precondition lowered.
    """
    pad = MAX_FIELD_LEN - len(indicator) - 1
    return "P" * pad + " " + indicator + " " + tail


#: Values whose extraction the scan window could plausibly change: each either
#: runs past the window edge, or places an indicator across the cut, or both.
#: The dot-dense entry is the one review measured — 0.153 s against 0.0069 s —
#: and it is also the entry a benign-padding probe of mine understated: in one
#: run, 101 ms whole-record for dot-dense against 27 ms for the same 256 KB of
#: ``A`` padding, which is the input that benchmark used.
_WINDOW_CORPUS: tuple[tuple[str, str], ...] = (
    # Discarded side: nothing survives the cut, and the window must agree.
    ("dot-dense", "a." * 131072),
    ("straddling-widest-domain", _straddling_domain()),
    ("straddling-narrow-domain", "P" * 2036 + " sub.example" + "-" * 14 + "a.com end"),
    ("url-wholly-past-the-cut", "P" * MAX_FIELD_LEN + " http://late.example/p " + "A" * 5000),
    ("hex-run-crossing-the-cut", "P" * 2000 + "f" * 100000),
    ("ipv6-run-crossing-the-cut", "P" * 2040 + "2001:db8:85a3:0:0:8a2e:370:7334" * 500),
    ("maximal-url-straddling", "P" * 2040 + " https://" + "u" * 400),
    ("non-ascii-across-the-cut", "P" * 2040 + " caf\u00e9.example.com " + "B" * 9000),
    ("exactly-one-window-long", "P" * (MAX_FIELD_LEN + 1024)),
    ("one-past-the-window", "P" * (MAX_FIELD_LEN + 1025)),
    # Kept side: the indicator is inside the cut and must survive the window.
    ("indicators-then-huge-tail", "198.51.100.7 http://a.example/p " + "A" * 200000),
    ("url-ending-at-the-cut", _ending_at_the_cut("http://a.example/p", "A" * 9000)),
    (
        "maximal-url-ending-at-the-cut",
        _ending_at_the_cut("https://" + "u" * 256, "A" * 9000),
    ),
    ("hash-then-dot-dense", _ending_at_the_cut("a" * 64, "a." * 131072)),
    (
        "ipv6-then-huge-tail",
        _ending_at_the_cut("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "A" * 200000),
    ),
    (
        "kept-domain-then-straddling-one",
        "early.indicator.example " + _straddling_domain(),
    ),
)

_WINDOW_IDS = [name for name, _ in _WINDOW_CORPUS]
_WINDOW_VALUES = [value for _, value in _WINDOW_CORPUS]


def _observables_over_the_whole_record(value: str) -> tuple[str, ...]:
    """What ``observables()`` returns with the window opened to the record."""
    original = _coerce._SCAN_LOOKAHEAD
    _coerce._SCAN_LOOKAHEAD = MAX_RAW_BYTES
    try:
        return observables(value)
    finally:
        _coerce._SCAN_LOOKAHEAD = original


@pytest.mark.security
@pytest.mark.parametrize("value", _WINDOW_VALUES, ids=_WINDOW_IDS)
def test_the_scan_window_extracts_exactly_what_the_whole_record_would(value: str) -> None:
    """Round twelve: the window is a cost fix and must not be a behaviour fix.

    Round eleven ended by scanning the **whole** record and keeping the matches
    that fit inside the cut, which is correct and was measured at ~22x the
    previous cost on dot-dense input — ``observables("a." * 131072)`` at
    0.153 s against 0.0069 s, on a path every parser runs for every value and
    reachable by anything that can write a dot-heavy line into a collected log.
    Review asked for the window; the window is only sound if it changes nothing
    but the cost.

    Asserted differentially against the production function with its own
    lookahead widened, rather than against a reference implementation written
    here. A second implementation would drift from the ordering, the dedup and
    the ``MAX_OBSERVABLES`` bound, and would then be testing itself.
    """
    assert observables(value) == _observables_over_the_whole_record(value)


@pytest.mark.security
def test_that_differential_can_see_a_lookahead_too_narrow_to_be_sound() -> None:
    """The test above must have teeth, since the margin is the whole guarantee.

    Everything about this shape rests on one number. If the differential were
    green for any lookahead, it would be pinning nothing and a later "tidy the
    constant down to 64" would pass review. So: shrink the lookahead and the
    corpus must disagree with a full scan.

    Measured on the straddling-domain value — margins 0..319 fabricate
    ``a.bc``, an indicator the record does not contain. 320 is not 408, and the
    gap is honest: a straddling match this test can *build* tops out around
    346 characters, because the gap region has to be content no extractor can
    end on and ``_DOMAIN`` caps at 6 labels. So this pins the margin against
    being shrunk below ~320, and the width test above is what pins it against
    408.
    """
    value = _straddling_domain()
    reference = _observables_over_the_whole_record(value)
    assert reference == (), "the long domain ends past the cut, so nothing is retained"

    original = _coerce._SCAN_LOOKAHEAD
    narrow: list[int] = []
    try:
        for margin in (0, 16, 64, 128, 256, 319):
            _coerce._SCAN_LOOKAHEAD = margin
            if observables(value) != reference:
                narrow.append(margin)
    finally:
        _coerce._SCAN_LOOKAHEAD = original

    assert narrow == [0, 16, 64, 128, 256, 319], (
        f"only {narrow} of the too-narrow lookaheads were detectable — the "
        "differential is weaker than it reads"
    )
    assert _coerce._SCAN_LOOKAHEAD >= 408, (
        f"the shipped lookahead is {_coerce._SCAN_LOOKAHEAD}, under the widest "
        "match _DOMAIN can produce"
    )


@pytest.mark.security
def test_the_window_corpus_actually_reaches_past_the_window() -> None:
    """Or the differential above compares a value with itself.

    Three of the eleven rounds on this function were green-over-nothing at the
    level above the defect, so the precondition is asserted rather than
    assumed: the corpus needs values longer than the window, and it needs at
    least one indicator extracted and at least one discarded, or "the window
    agrees" is a statement about the empty set.
    """
    window = MAX_FIELD_LEN + _coerce._SCAN_LOOKAHEAD
    past = [name for name, value in _WINDOW_CORPUS if len(value) > window]
    assert len(past) >= 6, f"only {past} exceed the {window}-character window"

    yielding = [name for name, value in _WINDOW_CORPUS if observables(value)]
    assert len(yielding) >= 3, f"only {yielding} yield any observable at all"
    empty = [name for name, value in _WINDOW_CORPUS if not observables(value)]
    assert len(empty) >= 3, f"only {empty} yield none, so the discard side is untested"


@pytest.mark.security
def test_the_leaf_walk_tolerates_an_unsorted_declaration() -> None:
    """``sysmon`` declares its fields unsorted, and the forward scan needs the sort.

    Pinned at ``_retained_values``' own level because no end-to-end record
    reaches the branch where it matters, which is exactly why it went
    unnoticed. The three call sites of ``_excerpt_for`` look alike and only
    one of them both consumes ``.values`` *and* passes a signature's own
    (possibly unsorted) field list — the parse-failure branch. That branch is
    reachable and tested for auditd, whose declaration is sorted; for sysmon,
    the one signature whose declaration is not, roughly a thousand hostile
    mutations across all fifteen fixtures produced no record that a signature
    claims and its parser then fails on.

    So this is insurance rather than a live path, and the docstring of
    ``_retained_values`` says so. What makes it worth a test is that the
    earlier docstring claimed the opposite — that ``project`` builds
    projections "in an order the forward scan tolerates" — and that claim is
    measurably false: sysmon's ``fields`` breaks at index 12
    (``provider_name`` before ``CommandLine``) and index 30 (``UtcTime``
    before ``EventData``), insertion order and sorted order disagree, and
    walking in insertion order keeps 4 of 10 leaves instead of 10. Dropping
    six modelled leaves out of the scan source is round one's defect.
    """
    normalize_module = sys.modules["ingest.normalize"]
    signature = next(sig for sig in SIGNATURES if sig.vendor == "sysmon")
    declared = [path[0] if isinstance(path, tuple) else path for path in signature.fields]
    assert declared != sorted(declared), (
        "sysmon's declaration is now sorted, so this test no longer exercises "
        "the divergence it exists for — find another unsorted signature or "
        "retire it deliberately"
    )

    record = {
        "@timestamp": "T" * 900,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": "1",
        "UtcTime": "2026-01-01 00:00:00.000",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "L" * 900,
        "provider_name": "P" * 900,
        "User": "CORP\\alice",
        "Hashes": "SHA256=" + "ab" * 32,
        "ProcessId": "4242",
    }
    projected = project(record, signature.fields)
    assert list(projected) != sorted(projected), (
        "the projection's insertion order now agrees with its sorted order, so "
        "the forward scan cannot be sensitive to the difference here"
    )

    excerpt = normalize_module._excerpt_for(signature.fields, record)
    leaves = list(normalize_module._leaf_values(projected))

    assert len(excerpt.values) == len(leaves), (
        f"the sorted walk kept {len(excerpt.values)} of {len(leaves)} modelled "
        f"leaves; an incomplete scan source is round one's defect"
    )


@pytest.mark.security
def test_the_indicator_position_table_covers_both_sides_of_that_equality() -> None:
    """A table that drifted to one side would make the equality unfalsifiable.

    The failure mode one level up from a vacuous assertion: the assertion is
    sound, and every row happens to exercise the same side of it. Measured on
    the table as committed — three rows retain the indicator, two do not.
    """
    retaining = {
        position
        for position, record, _ in _INDICATOR_POSITIONS
        if _INDICATOR_URL in normalize(record).raw_excerpt
    }
    dropping = set(_POSITION_IDS) - retaining

    assert len(retaining) >= 2, f"no retained-indicator rows left: {sorted(retaining)}"
    assert len(dropping) >= 2, f"no dropped-indicator rows left: {sorted(dropping)}"


#: Members of ``to_dict()`` that are **not** evidence and so may not satisfy
#: the invariant below. Both were found by review, and both arguments for
#: including them were mine and wrong.
#:
#: ``observables`` — ``to_dict()`` serializes it, so every observable matched
#: itself and the assertion could not fail. That was round four.
#:
#: ``notes`` — my stated reason for keeping it was that an unclaimed record's
#: withheld-key note names key *names*, and a key name is modelled content.
#: Both halves are false. ``project()`` excludes the withheld keys **by
#: construction**, so the note's key names are precisely the strings that are
#: in no other retained field, and whoever wrote the record chooses them
#: verbatim. Measured — a record with two indicator-shaped keys nobody models:
#:
#:     raw_excerpt : {"Subject": "ordinary subject"}
#:     notes       : "...their values are withheld from the excerpt (keys:
#:                    evil-keyname.example.com,
#:                    http://planted-keyname.example/x)"
#:     both keys   : in raw_excerpt False · in notes True
#:
#: And notes do not carry only key names: ``ingest/parsers/network.py``'s
#: unrecognized-stream note and ``ingest/parsers/endpoint.py``'s unmapped-event
#: note both interpolate payload *values* (measured: ``"unrecognized Zeek
#: stream 'stream-value.example.com'"``).
#:
#: **What this is and is not, measured rather than assumed.** It is a *latent*
#: masking channel, not a live bypass: on current code neither of those
#: records yields any observable at all — ``observables == ()`` for both — so
#: nothing is masked today, because an un-modelled key's *name* is not
#: scanned. Review's demonstration ran against a plant that made the withheld
#: key names part of the scan source, and that plant left the entire security
#: file green. The plant is a realistic future change, since AGENTS.md §5 says
#: in as many words that a key name is modelled content. So ``notes`` is
#: excluded because the justification for including it was false and because
#: it would hide exactly that regression — not because it hides something now.
#: Excluding it costs nothing on the committed corpus (measured: no test
#: changes outcome), which is the whole argument for doing it pre-emptively.
_NOT_EVIDENCE = frozenset({"observables", "notes"})


@pytest.mark.security
@pytest.mark.parametrize("name", _fixture_names())
@pytest.mark.parametrize("claimed", [True, False], ids=["claimed", "unclaimed"])
def test_every_observable_is_findable_in_the_retained_evidence(
    name: str, claimed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No indicator may exist in the store that its own event cannot account for.

    This is the retention invariant stated as a property rather than reasoned
    about per call site, which is what this layer needed: the scan source has
    now been wrong in **both** directions, narrower than the evidence and then
    wider than it, and each time the argument for correctness was a docstring.

    An observable may be sourced from a *typed* field rather than from
    ``raw_excerpt`` — auditd is the shipped example, where ``a0``/``a1``/``a2``
    drop from the excerpt by declaration while the reassembled argv is
    retained in ``Actor.command_line``, so the URL inside it is accounted for
    even though the excerpt does not show it. That is why the general
    invariant is "somewhere in the retained evidence" and the stricter one
    below is scoped to the unclaimed path.

    **``observables`` is excluded from the haystack, and that is the whole
    test.** The first version of this searched the full ``to_dict()``, which
    serializes ``observables`` itself — so every observable matched itself and
    the assertion could not fail. Measured on the version that shipped in
    #216: an event carrying ``http://in-no-retained-field.example/x`` as its
    only observable, present in no ``message``, no ``raw_excerpt`` and no
    typed field, satisfied it. A test asserting a security invariant that
    cannot fail is worse than no test, because it is cited as proof. Found by
    review; the plant above is now the regression case.

    ``ensure_ascii=False`` is load-bearing and also a review finding.
    ``json.dumps`` defaults to escaping non-ASCII, while ``event.observables``
    holds literal characters — so on the **claimed** path a non-ASCII URL that
    *is* correctly retained in the typed ``email.urls`` field was reported as a
    violation. Measured on the shipped defender parser with
    ``http://partner.example/pay/café``: present in ``email.urls``, found in
    the haystack at ``ensure_ascii=False``, absent at ``ensure_ascii=True``.
    The corpus is pure ASCII so this fires on no committed fixture today; it
    would have fired on the first person to add one, and pointed them at the
    parsers instead of at the dump.

    **What these thirty legs do and do not cover.** An earlier version of this
    paragraph said they "cannot express either direction of rounds one, two,
    five or six" because no fixture truncates, and called their contribution
    breadth of shape rather than of bound. That was wrong twice, and wrong in
    a way worth recording: I wrote an adversarial agent's conclusion into this
    docstring without planting the control the test actually claims. A
    skeptical pass then refuted it, and the refutation measures out.

    They are the **sole** catcher of the control this test does claim — an
    observable accounted for by nothing retained. Planting exactly that on the
    claimed path (``_with_excerpt`` appending
    ``http://in-no-retained-field.example/x``):

        this test              15 of 15 claimed legs RED
        every other test       2033 passed — nothing else in the repo catches it
        round four's haystack  all 30 passed against the same plant

    which is why excluding ``observables`` is the whole test rather than a
    detail of it.

    What they do **not** catch is rounds one, two, five and six — and the
    reason is not the corpus. The assertion is one-directional: it detects an
    observable with no retained source, never an observable that went
    *missing*. A truncating fixture would not change that, measured — a record
    at 4096/4096 with the round-one URL at excerpt index 3500 still passes
    under round one's plant. Those directions are pinned instead by
    ``test_an_unclaimed_records_observables_are_all_inside_its_excerpt[round-two]``
    and ``test_a_modelled_field_is_scanned_however_late_it_sorts``, both of
    which go red.

    Two numbers corrected while re-measuring. The longest ``raw_excerpt`` over
    the corpus is 679 of 4096 (16.6%) on both legs, but ``message`` is 207 of
    2048 (10.1%) only on the *claimed* leg — on the unclaimed leg ``message``
    *is* the rendered projection, so it reaches 679 of 2048 (33.2%). And
    "precisely the input ``_retained_values`` needed coverage on" overstates
    the unclaimed leg: on this corpus its assertion cannot fail, because every
    leaf is kept and a kept leaf's fragment is present in ``rendered`` by
    construction — and ``rendered`` *is* ``raw_excerpt``.

    The unclaimed leg empties the signature registry rather than renaming a
    key, for the same reason. Renaming ``Provider`` unclaimed exactly *one* of
    the fifteen committed fixtures — the other fourteen stayed claimed, so the
    leg labelled ``unclaimed`` ran the claimed path a second time and the
    advertised "both paths" coverage did not exist. ``MODELLED_FIELDS`` is
    computed at import and so is unaffected by the patch, which is what makes
    this work: every fixture keeps its real nested and list shapes and is
    projected through the full 199-path union. Also found by review.
    """
    if not claimed:
        # ``detect_source`` reads this at call time; ``MODELLED_FIELDS`` was
        # frozen at import. Asserted below rather than assumed, so a future
        # change to either cannot quietly return this leg to the claimed path.
        monkeypatch.setattr(sys.modules["ingest.normalize"], "SIGNATURES", ())
    event = normalize(_load(name))

    assert (event.vendor == "unrecognized") is not claimed, (
        f"{name}: the {'claimed' if claimed else 'unclaimed'} leg took the other path"
    )
    retained = json.dumps(
        {key: value for key, value in event.to_dict().items() if key not in _NOT_EVIDENCE},
        default=str,
        ensure_ascii=False,
    )
    for observable in event.observables:
        assert observable in retained, (
            f"{name}: observable {observable!r} appears in no retained field"
        )


@pytest.mark.security
@pytest.mark.parametrize("claimed", [True, False], ids=["claimed", "unclaimed"])
def test_the_fixture_corpus_produces_observables_for_that_property_to_check(
    claimed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Assert the antecedent of the implication above, which it cannot assert itself.

    ``test_every_observable_is_findable_in_the_retained_evidence`` iterates
    ``event.observables``. If the corpus stopped producing any — a signature
    change, a bound tightened, an extractor regressed — it would pass on every
    one of its thirty cases with zero assertions executed and read as proof
    that extraction is sound. That is precisely how round five survived: the
    cut-leaf record yields no observable at all, so the implication held
    vacuously while an indicator sat readable in the excerpt.

    A per-fixture floor would be wrong rather than merely weak: measured,
    ``auditd_daemon_end`` legitimately yields none on both legs, and
    ``auditd_execve`` yields none on the unclaimed leg because its indicators
    live in ``a0``/``a1``/``a2``, which no parser declares. So the floor is
    corpus-wide. Measured on this corpus: 30 observables across 14 of 15
    fixtures claimed, 43 across 13 of 15 unclaimed. The floors below sit well
    under both, so an ordinary fixture edit does not trip them while a
    collapse to nothing does.
    """
    if not claimed:
        monkeypatch.setattr(sys.modules["ingest.normalize"], "SIGNATURES", ())

    counts = {name: len(normalize(_load(name)).observables) for name in _fixture_names()}
    total = sum(counts.values())
    with_any = sum(1 for count in counts.values() if count)

    assert total >= 25, f"corpus yields only {total} observables: {counts}"
    assert with_any >= 12, f"only {with_any} of {len(counts)} fixtures yield any: {counts}"


@pytest.mark.security
@pytest.mark.parametrize("record", _POSITION_RECORDS, ids=_POSITION_IDS)
def test_an_unclaimed_records_observables_are_all_inside_its_excerpt(
    record: dict[str, object],
) -> None:
    """On the unclaimed path the excerpt *is* the evidence, so it must contain them.

    The stricter half of the invariant, scoped to where ``_Excerpt`` governs.
    Both review findings on this function are in the fixture table above: one
    where an indicator inside the bound was not scanned, one where an
    indicator outside it was. A single assertion catches both directions,
    which is the point — the previous two fixes each closed one direction and
    opened the other.
    """
    event = normalize(record)

    assert event.vendor == "unrecognized", "fixture must take the unclaimed path"
    for observable in event.observables:
        assert observable in event.raw_excerpt, (
            f"observable {observable!r} was scanned from outside the retained excerpt"
        )


@pytest.mark.security
def test_a_modelled_field_is_scanned_however_late_it_sorts() -> None:
    """``observables()`` bounds each value, so it must be given values.

    Handing it the serialized projection applied ``MAX_FIELD_LEN`` to the
    *concatenation*, so a modelled field sorting after a long one lost its
    indicator even though the excerpt kept it. Measured before the fix, with
    both fields modelled and ``@timestamp`` sorting first:

        {"ProviderV2": "x", "@timestamp": "T"*2048,
         "Subject": "visit http://modelled.example/path"}

        raw_excerpt : keeps the URL, at index 2085
        observables : (none)

    The asymmetry is the tell — removing the long field brought the indicator
    back, so sort order decided it. Every parser already relies on the
    per-value bound when it calls ``observables(sender_ip, sender, *urls)``;
    only this call site passed one string.

    Asserted with the long field present *and* absent, because the version
    that passes with it absent is exactly the version that shipped broken.
    """
    url = "http://modelled.example/path"
    late = {"ProviderV2": "renamed-upstream", "@timestamp": "T" * 2048, "Subject": f"visit {url}"}

    event = normalize(late)

    assert event.vendor == "unrecognized"
    assert url in event.raw_excerpt, "fixture must retain the URL in the excerpt"
    assert event.raw_excerpt.index(url) > MAX_FIELD_LEN, (
        "fixture must push the URL past the per-field bound"
    )
    assert url in event.observables, "a modelled field was not scanned because it sorted late"

    without = normalize({"ProviderV2": "renamed-upstream", "Subject": f"visit {url}"})
    assert url in without.observables, "the short case must pass too, and did before the fix"


@pytest.mark.security
@pytest.mark.parametrize(
    "indicator",
    [
        pytest.param("tracker.evil-domain.example", id="domain"),
        pytest.param("http://evil-domain.example/pay", id="url"),
        pytest.param("203.0.113.231", id="ipv4"),
        pytest.param("a" * 64, id="sha256"),
        pytest.param("Mr.Jones", id="prose-that-looks-like-a-domain"),
    ],
)
def test_no_extractor_reaches_an_unmodelled_field(indicator: str) -> None:
    """The marker the neighbouring tests plant cannot trigger this.

    ``_MARKER`` is ``UNMODELLED-VALUE-7f3a91`` — no dot, no scheme, not 64 hex
    characters — so no extractor in ``observables()`` can match it, and
    ``test_an_unmodelled_field_reaches_no_part_of_a_stored_event`` asserted
    over the whole of ``to_dict()`` and still could not see the leak. The
    assertion was right and the fixture could not reach it, which is why this
    one plants something each extractor *would* match, one kind at a time.
    """
    event = normalize({"ProviderV2": "renamed-upstream", "Body": f"see {indicator} now"})

    assert event.vendor == "unrecognized"
    dumped = json.dumps(event.to_dict(), default=str)
    assert indicator not in dumped, f"an un-modelled {indicator!r} reached the stored event"
    assert indicator not in event.observables


# --------------------------------------------------------------------------
# Write-side bounds
#
# Every field a parser writes is bounded by ``text()``. ``message`` is not a
# field — it is assembled from several of them — and nothing re-bounded the
# result, while ``from_dict`` validates it like any other. That made an event
# writable and then permanently unreadable, which is worse than a rejected
# one: ``run_cycle`` does not catch ``MalformedProjectionError``, so one such
# record stops every later detection cycle on that store.
# --------------------------------------------------------------------------


def _inflate(value: Any) -> Any:
    """Push every string in a record past the per-field bound."""
    if isinstance(value, str):
        return value + "A" * MAX_FIELD_LEN
    if isinstance(value, dict):
        return {key: _inflate(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_inflate(child) for child in value]
    return value


@pytest.mark.security
@pytest.mark.parametrize("name", _fixture_names())
def test_a_record_of_maximal_fields_still_reads_back(name: str) -> None:
    """Writable-then-unreadable is the failure mode; round-tripping is the test.

    Nine of these fifteen failed before the write-side bound existed, across
    eight of the ten vendors — so this is a property of the layer, not of one
    parser. Asserted by round-tripping rather than by comparing lengths
    against the same constant the code uses, which would pass if both moved.
    """
    event = normalize(_inflate(_load(name)))
    assert NormalizedEvent.from_dict(event.to_dict()) == event


@pytest.mark.security
def test_an_encoded_command_line_does_not_make_a_store_unreadable(tmp_path: Path) -> None:
    """The record that found it, end to end, with nothing hostile about its shape.

    An encoded-PowerShell process creation is the most common malicious
    artifact in endpoint telemetry and the thing the Sysmon parser exists to
    capture. Its command line alone carried ``message`` past the bound.
    """
    encoded = base64.b64encode(("Get-Process; " * 160).encode("utf-16-le")).decode()
    record = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "1",
        "UtcTime": "2026-10-15 09:00:00.000",
        "Computer": "FIN-WS-04",
        "Image": "powershell.exe",
        "ParentImage": "cmd.exe",
        "CommandLine": f"powershell.exe -nop -w hidden -enc {encoded}",
    }
    event = normalize(record)
    assert event.vendor == "sysmon"
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=1_760_000_000.0)
        assert len(store.query()) == 1


@pytest.mark.security
def test_a_truncated_summary_says_so_and_demotes_the_parse() -> None:
    """A cut summary can drop the only copy of a value, so it is never silent.

    A CloudTrail ``mfaAuthenticated`` and a Defender ``ThreatTypes`` appear in
    ``message`` and on no field of the event, so truncating the summary
    silently would lose them without a reader being able to tell.
    """
    record = dict(_load("cloudtrail_assume_role"))
    # ``eventName`` opens the assembled summary, so a long one pushes the
    # whole of it past the bound. A long ``userAgent`` would not: it lands on
    # ``Device.hostname``, which ``text()`` already bounds on its own.
    record["eventName"] = "A" * MAX_FIELD_LEN
    event = normalize(record)
    assert len(event.message) == MAX_FIELD_LEN
    assert event.parse_status == "partial"
    assert any("truncated on write" in note for note in event.notes)
    # An untruncated record keeps its clean status and its empty note list.
    assert normalize(_load("cloudtrail_assume_role")).parse_status == "structured"


def _maximal(annotation: Any) -> Any:
    """Build a value past every bound for one annotated field, by its type."""
    over_long = "A" * (MAX_RAW_EXCERPT * 2)
    if dataclasses.is_dataclass(annotation):
        return _maximal_group(annotation)
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Literal:
        return args[0]
    if origin is tuple:
        return tuple(f"{over_long}{index}" for index in range(MAX_NOTES + MAX_OBSERVABLES + 2))
    if origin is not None and type(None) in args:  # X | None
        inner = next(arg for arg in args if arg is not type(None))
        return 1.0 if inner is float else _maximal(inner)
    if annotation is str:
        return over_long
    if annotation is float:
        return 1.0
    raise AssertionError(f"this test does not know how to overfill {annotation!r}")


def _maximal_group(group: Any) -> Any:
    hints = typing.get_type_hints(group)
    return group(**{field.name: _maximal(hints[field.name]) for field in dataclasses.fields(group)})


@pytest.mark.security
def test_bounded_covers_every_field_from_dict_validates() -> None:
    """Anti-drift: the event is built by reflection, not by a hand-written list.

    ``bounded()`` and ``from_dict`` are a write/read pair, and the way such a
    pair fails is one of them learning about a new field. Adding a field to
    ``NormalizedEvent`` and forgetting to bound it fails here without anyone
    editing this test.
    """
    overfull = _maximal_group(NormalizedEvent)
    with pytest.raises(MalformedProjectionError):
        NormalizedEvent.from_dict(overfull.to_dict())
    bounded = overfull.bounded()
    assert NormalizedEvent.from_dict(bounded.to_dict()) == bounded


@pytest.mark.security
def test_an_unmodelled_field_is_absent_from_the_database_itself(tmp_path: Path) -> None:
    """End to end: not in the projection, and so not in the bytes on disk."""
    record = dict(_load("defender_email_phish"))
    record["Body"] = f"IBAN and auth code {_MARKER}"
    with EventStore.open(tmp_path) as store:
        store.append(normalize(record), ingested_at=1_760_000_000.0)
    # Every file the store wrote, not just the database: SQLite runs in WAL
    # mode here, so a row can still be sitting in a sidecar.
    database = tmp_path / "data" / "events" / DEFAULT_FILENAME
    written = b"".join(
        path.read_bytes() for path in sorted(database.parent.iterdir()) if path.is_file()
    )
    assert _MARKER.encode() not in written
    assert b"defender-o365" in written  # the event itself is there


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
    """The runtime dependency set stays empty — a load-bearing repo property.

    Asserted against ``pyproject.toml`` rather than installed metadata, so it
    runs everywhere. The property is a declaration in a committed file, not a
    fact about the current virtualenv: reading it through
    ``importlib.metadata`` made the test error with ``PackageNotFoundError``
    wherever the package was not pip-installed, which reported an environment
    fact as a security failure. Installed metadata is still checked when it
    happens to be available, because it would also catch a dependency injected
    by the build backend rather than declared here.
    """
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["dependencies"]
    assert declared == [], f"{LAYER} must not introduce runtime dependencies: {declared}"

    import importlib.metadata as metadata

    try:
        installed = metadata.requires("ianua") or []
    except metadata.PackageNotFoundError:
        return  # not installed here; the committed declaration above is the contract
    runtime = [req for req in installed if "extra ==" not in req]
    assert runtime == [], f"installed metadata declares runtime dependencies: {runtime}"


def _load(name: str) -> dict:
    fixtures = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    record = fixtures[name]["record"]
    assert isinstance(record, dict)
    return record


# --------------------------------------------------------------------------
# What is writable must be readable back
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("length", [2049, 2500, 3047, 4096, 5000])
def test_an_unrecognized_line_of_any_length_survives_a_round_trip(
    tmp_path: Path, length: int
) -> None:
    """A line of 2049-4096 chars was writable and then permanently unreadable.

    ``_unrecognized`` bounded ``message`` at ``MAX_RAW_EXCERPT`` (4096) while
    ``from_dict`` validates it at ``MAX_FIELD_LEN`` (2048), so ``append``
    accepted the event and every later ``query`` raised
    ``MalformedProjectionError`` — which ``run_cycle`` does not catch, so
    **every subsequent detection cycle on that store failed**. One long log
    line stopped the SOC. Found by review and reproduced end to end.

    Parametrized across the window and past it, because the failure was only
    in the band between the two constants: 2048 and below always worked, and
    above 4096 the excerpt truncation happened to bring it back under.
    """
    from store import EventStore

    event = normalize("Failed password for " + "u" * length + " from 203.0.113.9 port 22")
    assert len(event.message) <= MAX_FIELD_LEN

    with EventStore.open(tmp_path) as store:
        assert store.append_many((event,), ingested_at=1_000.0) == 1
        # The assertion that actually matters: it reads back.
        assert len(store.query()) == 1


@pytest.mark.security
def test_every_field_the_schema_validates_is_written_within_its_own_bound() -> None:
    """The structural version of the test above, against fixed literals.

    ``message`` is validated at ``MAX_FIELD_LEN`` and only ``raw_excerpt`` at
    ``MAX_RAW_EXCERPT``, so only ``raw_excerpt`` may be written at the wider
    bound. Pinned against the literals rather than the constants, because
    scaling an assertion from the constant under test cannot fail.
    """
    assert MAX_FIELD_LEN == 2048
    assert MAX_RAW_EXCERPT == 4096
    long_line = "x" * 9000
    event = normalize(long_line)
    assert len(event.message) <= 2048, "message was written past the bound from_dict enforces"
    assert len(event.raw_excerpt) <= 4096


@pytest.mark.security
def test_a_poisoned_store_does_not_break_every_later_cycle(tmp_path: Path) -> None:
    """The consequence, asserted through the pipeline rather than argued.

    The defect's blast radius was not one bad event: ``query`` raises for the
    whole result set, so one 3047-character line in ``auth.log`` broke every
    firing of the scheduled cycle from then on.
    """
    from pipeline import cursor_path, load_cursor, run_cycle
    from store import EventStore

    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for svc from 10.0.0.9 port 22 ssh2"), ingested_at=1_000.0
        )
        store.append(
            normalize("Failed password for " + "u" * 3000 + " from 10.0.0.9 port 22"),
            ingested_at=2_000.0,
        )
        result = run_cycle(store, cursor=load_cursor(cursor_path(tmp_path)))
    assert result.events_read == 2, "a long line still breaks the detection cycle"


#: An integer CPython refuses to render. ``str(int)`` is quadratic, so since
#: 3.11 it raises past ``sys.get_int_max_str_digits()`` (4300 by default) — and
#: ``float()`` has no value for one this large either. One number, two
#: exception types, four call sites that each propagated it.
_UNRENDERABLE_DIGITS = 5000
_UNRENDERABLE_INT = 10 ** (_UNRENDERABLE_DIGITS - 1)
_UNRENDERABLE_LITERAL = "9" * _UNRENDERABLE_DIGITS


@pytest.mark.security
def test_the_unrenderable_probe_is_actually_unrenderable_here() -> None:
    """The precondition, or every test below is green over an ordinary number.

    If a future interpreter raises the digit limit past this probe, these
    tests must say so rather than quietly stop testing anything. Both
    refusals are pinned, because the fix had to handle both: ``str`` raises
    ``ValueError`` and ``float`` raises ``OverflowError``, and a guard naming
    one of them leaves the other live.
    """
    limit = sys.get_int_max_str_digits()
    assert limit and limit < _UNRENDERABLE_DIGITS, (
        f"the probe has {_UNRENDERABLE_DIGITS} digits against a limit of "
        f"{limit}; it no longer reaches the condition these tests exist for"
    )
    with pytest.raises(ValueError):
        str(_UNRENDERABLE_INT)
    with pytest.raises(OverflowError):
        float(_UNRENDERABLE_INT)


#: ``(id, record, raised_before_the_fix)`` for every shape by which an
#: unrenderable number can reach this layer. The four JSON rows are the only
#: ones a *collector* can deliver, since it passes log lines as ``str``, and
#: the first is the one measured end to end; the mapping rows arrive through
#: ``normalize``'s declared ``Mapping[str, Any]`` domain.
#:
#: The third field is measured, by reverting all four guards at once and
#: asking each row whether it raises. **Six of the eight do. Two do not**, and
#: they are kept as controls rather than dropped, because what stops them is
#: worth recording: ``mapping-unmodelled-key`` never reaches ``text()`` at all
#: — the evidence allow-list withholds the value before anything renders it —
#: and in ``mapping-nested`` the declared path lands on a *mapping*, which
#: contributes its key names and never its values (``project``'s second rule).
#: So the retention control turns out to block two of the four routes into
#: this layer as a side effect. Stating that is the point; implying all eight
#: were live would be the overclaim.
_UNRENDERABLE_RECORDS: tuple[tuple[str, object, bool], ...] = (
    ("json-top-level-int", '{"EventID": 1, "Counter": ' + _UNRENDERABLE_LITERAL + "}", True),
    ("json-nested-int", '{"EventID": 1, "x": {"y": ' + _UNRENDERABLE_LITERAL + "}}", True),
    ("json-int-in-a-list", '{"EventID": 1, "x": [' + _UNRENDERABLE_LITERAL + "]}", True),
    ("json-as-bytes", ('{"EventID": 1, "n": ' + _UNRENDERABLE_LITERAL + "}").encode(), True),
    ("mapping-modelled-key", {"EventID": _UNRENDERABLE_INT, "Channel": "Security"}, True),
    ("mapping-timestamp", {"EventID": 1, "@timestamp": _UNRENDERABLE_INT}, True),
    ("mapping-unmodelled-key", {"EventID": 1, "Counter": _UNRENDERABLE_INT}, False),
    ("mapping-nested", {"EventID": 1, "Provider": {"Name": _UNRENDERABLE_INT}}, False),
)


@pytest.mark.security
def test_most_of_those_rows_really_did_raise_before_the_fix() -> None:
    """A "must not raise" table whose rows never raised asserts nothing.

    The count is pinned rather than the rows' flags being decoration: if a
    later change makes the allow-list cover a third route, this fails and the
    table gets corrected instead of quietly shrinking to controls.
    """
    live = [name for name, _, raised in _UNRENDERABLE_RECORDS if raised]
    inert = [name for name, _, raised in _UNRENDERABLE_RECORDS if not raised]
    assert len(live) == 6, f"{live} reach the condition, which is not what was measured"
    assert inert == ["mapping-unmodelled-key", "mapping-nested"], inert


@pytest.mark.security
@pytest.mark.parametrize(
    "record",
    [record for _, record, _ in _UNRENDERABLE_RECORDS],
    ids=[name for name, _, _ in _UNRENDERABLE_RECORDS],
)
def test_an_unrenderable_number_degrades_instead_of_raising(record: object) -> None:
    """Rule 2 — nothing a record contains may raise out of ``normalize``.

    The rule was already written, in ``_serialize``'s docstring, and leaked in
    four places at once. One 5000-digit integer:

    * ``json.loads`` raises a bare ``ValueError``, which the decode guard did
      not catch because it named ``json.JSONDecodeError``;
    * ``_coerce.text`` raises from ``str(value)``;
    * ``_coerce.epoch`` raises ``OverflowError`` from ``float(value)``;
    * ``_serialize``'s *fallback* raises from ``str(value)`` — the function
      whose docstring states the rule.

    The consequence was not one lost field. ``normalize_many`` was a list
    comprehension, so the raise discarded the whole batch, and
    ``scripts/run_collector.py`` records a source's cursor only once its
    events are durable — so the source re-read the same window on every pass,
    forever. Measured on a three-line file with one such line, twice in a row:

        exit=1  stored=0  offsets={}  "offsets held"  "[first-run]"

    with the two healthy lines never stored, recoverable only by editing a log
    the collector is licensed to read and never to write.

    Six of these eight rows raised before the fix; the other two were already
    blocked by the evidence allow-list, and the table says which is which.
    """
    event = normalize(record)  # type: ignore[arg-type]
    assert event.parse_status in {"structured", "partial", "text"}
    assert event.raw_excerpt is not None


@pytest.mark.security
def test_every_coercion_helper_is_total_over_an_unrenderable_number() -> None:
    """Pinned at the helpers, because all ten parsers reach them directly.

    ``normalize`` is not the only entry point into these: a parser calls
    ``text``, ``first``, ``strings``, ``epoch`` and ``observables`` on values
    it chose, so a guard that only covered ``normalize`` would leave every
    parser live. Asserted here rather than inferred from the end-to-end tests
    above.
    """
    huge = _UNRENDERABLE_INT
    assert _coerce.text(huge) is None
    assert _coerce.epoch(huge) is None
    assert _coerce.first(huge) is None
    assert _coerce.strings([huge], limit=4) == ()
    assert _coerce.observables(huge) == ()
    # A declared path landing on it renders as present-but-blank rather than
    # omitted: the record *did* carry the key, which is a different claim from
    # not carrying it, and the same distinction `project`'s first rule draws.
    assert _coerce.project({"a": huge}, [("a",)]) == {"a": None}


@pytest.mark.security
def test_a_serializable_number_is_still_rendered() -> None:
    """The other direction, so the guards are not a blanket refusal of ints.

    A 400-digit integer is under the limit and must survive intact, and a
    timestamp that *is* a large float must still parse. Without this, a guard
    that returned ``None`` for every number would pass everything above.
    """
    renderable = 10**400
    assert len(_coerce.text(renderable) or "") == 401
    assert _coerce.epoch(1_760_000_000) == 1_760_000_000.0
    assert _coerce.epoch(1_760_000_000_000) == 1_760_000_000.0
    assert _coerce.observables(f"198.51.100.7 seen {renderable} times") == ("198.51.100.7",)


@pytest.mark.security
def test_one_unparseable_record_does_not_cost_the_batch() -> None:
    """``normalize_many``'s docstring claim, asserted rather than stated.

    It has said "one unparseable record never costs the batch" since it was
    written. A list comprehension holds that only while ``normalize`` is
    total, which it was not — so the claim was false for the one input that
    reached it, and the cost was the whole batch plus the source's cursor.
    """
    healthy_first = (
        "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"
    )
    poison = '{"EventID": 1, "Counter": ' + _UNRENDERABLE_LITERAL + "}"
    healthy_last = json.dumps(
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "eventTime": "2026-10-15T09:00:02Z",
        }
    )

    events = normalize_many([healthy_first, poison, healthy_last])

    assert len(events) == 3, "the poison record cost its neighbours"
    assert events[2].vendor == "aws-cloudtrail", "order was not preserved"
    assert events[0].vendor != "unknown"


@pytest.mark.security
def test_a_record_that_resists_every_rendering_still_degrades() -> None:
    """The second layer, and its own first version had the first layer's hole.

    ``normalize_many`` keeps a blanket guard *as well as* the fixes above,
    because a batch boundary whose contract is "one bad record never costs the
    batch" cannot keep that contract by naming exception types — the next leak
    will be a type nobody listed. This is the case that proves the guard is
    reached and that its fallback rendering cannot itself raise: a ``Mapping``
    whose ``__iter__`` raises defeated the first version, because the
    key-name fallback called ``list(record)`` inside the ``except`` that was
    handling the first raise.
    """

    class RefusesEverything(Mapping[str, object]):
        def __iter__(self) -> Iterator[str]:
            raise RuntimeError("iteration refused")

        def __len__(self) -> int:
            raise RuntimeError("len refused")

        def __getitem__(self, key: str) -> object:
            raise RuntimeError("getitem refused")

    events = normalize_many([RefusesEverything(), "a healthy plain line"])

    assert len(events) == 2
    assert any("raised RuntimeError" in note for note in events[0].notes), (
        f"the degraded event does not say what happened: {events[0].notes}"
    )
    # The note names the exception type and not its message, because a message
    # is often record content and this lands in an append-only store.
    assert not any("iteration refused" in note for note in events[0].notes)


@pytest.mark.security
@pytest.mark.parametrize("bad", [7, 7.5, None, object()], ids=["int", "float", "none", "object"])
def test_a_wrong_python_type_is_still_refused_not_degraded(bad: object) -> None:
    """The blanket guard must not launder the one refusal this layer declares.

    ``ingest/errors.py`` draws the line the whole layer turns on: malformed
    telemetry degrades, and only an input that cannot be telemetry at all
    raises, "because those signal a caller bug rather than a bad log line".
    The first version of the blanket guard swallowed ``UnsupportedInputError``
    — measured, an object with a raising ``__repr__`` came back as a degraded
    event instead of refusing — which would turn one caller bug into a
    thousand plausible-looking events in an append-only store.
    """
    with pytest.raises(UnsupportedInputError):
        normalize_many([bad])  # type: ignore[list-item]
    assert issubclass(UnsupportedInputError, IngestError)
    assert issubclass(MalformedProjectionError, IngestError)


@pytest.mark.security
@pytest.mark.parametrize("name", _fixture_names())
def test_the_blanket_guard_is_not_reached_by_any_committed_fixture(name: str) -> None:
    """A second layer that fires routinely is a first layer that is broken.

    The blanket guard exists for the leak nobody listed, which means its
    firing is information. If a fixture starts reaching it, something changed
    in ``normalize`` and the right response is to fix that rather than to
    accept a degraded event — so this pins that none of them does today.
    """
    fixtures = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    record = fixtures[name]["record"]
    for event in normalize_many([record, json.dumps(record)]):
        assert not any("raised" in note for note in event.notes), (
            f"{name} reaches the blanket guard: {event.notes}"
        )


@pytest.mark.security
def test_the_excerpt_serializer_degrades_to_shape_when_it_cannot_render() -> None:
    """``_serialize``'s third tier, which exists because the second raised.

    Both of its first two tiers are defeated by one value. ``json.dumps``
    consults ``default`` only for types JSON cannot represent, and ``int`` is
    not one, so the encoder calls ``int.__repr__`` and *that* is what refuses;
    then ``str(mapping)`` renders its values and refuses the same way. The
    third tier names keys only — shape, not content, which is
    ``project``'s second rule — and cannot raise, because key names are
    strings and coerce through the now-total ``text``.
    """
    from ingest.normalize import _serialize

    rendered = _serialize({"Counter": _UNRENDERABLE_INT, "Body": "a message body"})

    assert rendered == '["Body", "Counter"]', rendered
    # And the tier is a fallback, not the new behaviour: an ordinary mapping
    # still serializes with its values.
    assert _serialize({"a": "b"}) == '{"a": "b"}'
