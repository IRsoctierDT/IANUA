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
import json
import sys
import typing
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
    normalize,
)
from ingest._coerce import _bounded_for_scan, observables, project, text
from ingest.errors import MalformedProjectionError
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
    in ``_coerce._bounded_for_scan``, immediately around the slice, so it
    covers every caller including the ten parsers rather than one call site.

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

    ``_bounded_for_scan`` detects truncation by coercing at ``MAX_FIELD_LEN +
    1`` and comparing lengths. That is new code on the hot path of all ten
    parsers, and the committed corpus cannot exercise it: its longest value is
    far under the bound. So the risk is a value trimmed that was never
    truncated — a silent loss on real telemetry — and these are the cases that
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

    # Truncated, but the cut lands on a space, so nothing is severed and the
    # trim changes nothing.
    spaced = ("a  " * 900) + " " + url
    assert len(spaced) > MAX_FIELD_LEN, "fixture must exceed the bound"
    assert _bounded_for_scan(spaced) == text(spaced), (
        "the trim altered a value whose cut landed on a terminator"
    )

    # Non-string scalars go through unchanged.
    for scalar in (3.14159, 12345, True):
        assert _bounded_for_scan(scalar) == text(scalar), (
            f"{scalar!r} was altered by a bound it does not reach"
        )


@pytest.mark.security
def test_no_extractor_can_match_across_an_indicator_terminator() -> None:
    """``_bounded_for_scan``'s trim is only sound if this holds.

    It cuts a truncated value back past its last ``_CUT_TOKEN`` character and
    relies on that leaving a string which cannot be ending *inside* a match.
    That holds because every extractor's character class is a subset of
    ``_URL``'s — a claim about five regexes, which is exactly the kind of
    claim this layer has had wrong repeatedly, so it is asserted rather than
    argued.

    This test existed before, was deleted with the excerpt-tail guard it then
    justified, and is back because the same derivation is load-bearing again
    in a place every caller reaches.
    """
    from ingest import _coerce

    patterns = {
        name: getattr(_coerce, name) for name in ("_URL", "_IPV4", "_IPV6", "_HASH", "_DOMAIN")
    }
    # Expanded, not compressed: `_IPV6` has no `::` support, so the probe
    # `2001:db8::1` an earlier version used produced zero matches and that
    # extractor asserted nothing. The guard below is the general form.
    probes = (
        "http://a.example/p",
        "198.51.100.7",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "a" * 64,
        "evil.example.com",
    )
    terminators = sorted(set(" \t\n\r\f\v\"'<>\\"))
    assertions = dict.fromkeys(patterns, 0)
    for terminator in terminators:
        probe = terminator.join(probes)
        for name, pattern in patterns.items():
            for match in pattern.findall(probe):
                found = match if isinstance(match, str) else "".join(match)
                assertions[name] += 1
                assert terminator not in found, (
                    f"{name} matched across {terminator!r}: {found!r} — the "
                    f"trim in _bounded_for_scan is unsound"
                )

    unexercised = sorted(name for name, count in assertions.items() if not count)
    assert not unexercised, (
        f"{unexercised} matched nothing in the probe corpus, so this test "
        f"asserted nothing about them. Add a probe each extractor recognises."
    )
    assert _coerce._CUT_TOKEN.sub("", "keep me http://cut.example/pa") == "keep me ", (
        "_CUT_TOKEN no longer drops exactly the trailing token"
    )


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
