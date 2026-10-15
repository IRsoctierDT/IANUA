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


#: Records that produced the two review findings on this function, kept as
#: fixtures so the property below is exercised against the shapes that broke
#: it rather than only against well-behaved telemetry. ``@timestamp``,
#: ``Channel``, ``CommandLine`` and ``Subject`` are all declared paths; the
#: renamed provider key is what makes the record unclaimed.
_HOSTILE_PROJECTIONS: tuple[dict[str, object], ...] = (
    # Round one: a modelled field sorting after a long one. The URL is inside
    # the excerpt bound, so it must be scanned.
    {"ProviderV2": "x", "@timestamp": "T" * 2048, "Subject": "visit http://a.example/p"},
    # Round two: the projection exceeds MAX_RAW_EXCERPT, so the URL is cut
    # from the excerpt and must therefore NOT be scanned.
    {
        "ProviderV2": "x",
        "@timestamp": "T" * 2048,
        "Channel": "C" * 2048,
        "CommandLine": "L" * 2048,
        "Subject": "visit http://b.example/p",
    },
    # An un-modelled field alongside modelled ones: neither retained nor scanned.
    {"ProviderV2": "x", "Subject": "s", "Body": "Mr.Jones at evil.example.com"},
)


@pytest.mark.security
@pytest.mark.parametrize("name", _fixture_names())
@pytest.mark.parametrize("claimed", [True, False], ids=["claimed", "unclaimed"])
def test_every_observable_is_findable_in_the_stored_event(name: str, claimed: bool) -> None:
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
    invariant is "somewhere in the event" and the stricter one below is
    scoped to the unclaimed path.
    """
    record = _load(name)
    if not claimed:
        record = {
            ("ProviderV2" if key == "Provider" else key): value for key, value in record.items()
        }
        record = {**record, "RenamedUpstream": "breaks recognition"}
    event = normalize(record)

    dumped = json.dumps(event.to_dict(), default=str)
    for observable in event.observables:
        assert observable in dumped, (
            f"{name}: observable {observable!r} appears nowhere in the stored event"
        )


@pytest.mark.security
@pytest.mark.parametrize(
    "record", _HOSTILE_PROJECTIONS, ids=["round-one", "round-two", "unmodelled"]
)
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
