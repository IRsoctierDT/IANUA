# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The decoder's thresholds are the whole control — hold them.

``ingest/keyvalue.py`` turns ``key=value`` log text into a mapping the existing
signatures claim. The risk it introduces is not a crash: it is **manufactured
telemetry**. A prose line that happens to contain an equals sign must not
become a two-field "event", because an event is evidence, and evidence
assembled from a sentence is worse than no event at all — ``unknown``/``text``
is an honest answer and a fabricated endpoint record is not.

So ``MIN_PAIRS`` and ``MIN_COVERAGE`` are security parameters rather than
tuning knobs, and this file is where they are held. The bounds (``MAX_PAIRS``,
``MAX_KEY_LEN``, ``MAX_VALUE_LEN``) matter for the ordinary reason: a single
malformed line from an attacker-influenced log must not exhaust memory.
"""

from __future__ import annotations

import json

import pytest
from ingest.keyvalue import (
    MAX_KEY_LEN,
    MAX_PAIRS,
    MAX_VALUE_LEN,
    MIN_COVERAGE,
    MIN_PAIRS,
    decode,
)

from ingest import normalize

# --------------------------------------------------------------------------
# It must not manufacture telemetry out of prose
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "line",
    [
        "Failed password for svc-deploy from 198.51.100.7 port 22 ssh2",
        "error: giving up after retries=3 because the upstream never answered properly",
        "the operator said count=3 and then later mentioned that limit=9 in passing, at length",
        "Oct 14 10:02:01 web-01 sshd[123]: Connection closed by authenticating user root",
        "a=1",
        "",
        "   ",
        "================================================",
        "see https://example.test/path?a=1&b=2 for the full writeup and further detail",
    ],
)
def test_prose_is_not_decoded_into_an_event(line: str) -> None:
    """``None`` means "carry it as text", which is the honest answer.

    Each line here either has too few pairs or too little coverage. The last
    one is the case worth noting: a URL carries ``a=1`` and ``b=2``, which is
    two pairs, and only the coverage threshold keeps it from becoming a
    two-field event.
    """
    assert decode(line) is None


@pytest.mark.security
@pytest.mark.parametrize(
    "line",
    [
        "Failed password for svc-deploy from 198.51.100.7 port 22 ssh2",
        "error: giving up after retries=3 because the upstream never answered properly",
        "the operator said count=3 and then later mentioned that limit=9 in passing, at length",
    ],
)
def test_prose_still_normalizes_to_unknown_text(line: str) -> None:
    """End to end: the decoder changed nothing about how prose is handled.

    Asserted through ``normalize`` rather than ``decode`` alone, because the
    regression that would matter is a prose line arriving in the store wearing
    a source type it did not earn.
    """
    event = normalize(line)
    assert event.source_type == "unknown"
    assert event.parse_status == "text"
    assert event.actor.user_name is None
    assert event.device.hostname is None


@pytest.mark.security
def test_one_pair_is_never_enough() -> None:
    """``MIN_PAIRS`` is 2 because one pair matches far too much ordinary text.

    A single pair is enough to look like data and never enough to be data.
    Asserted against the constant so loosening it fails here.
    """
    assert MIN_PAIRS >= 2
    assert decode("retries=3") is None


@pytest.mark.security
def test_the_coverage_threshold_is_what_separates_dense_lines_from_prose() -> None:
    """``MIN_PAIRS`` alone cannot: prose can contain two incidental pairs.

    Demonstrated both ways round with the same two pairs, so the only variable
    is how much of the line they account for.
    """
    assert 0 < MIN_COVERAGE <= 1
    dense = "count=3 limit=9"
    sparse = "the operator said count=3 and then much later mentioned limit=9 in passing"
    assert decode(dense) is not None
    assert decode(sparse) is None


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_pathological_line_cannot_create_an_unbounded_mapping() -> None:
    line = " ".join(f"k{index}=v{index}" for index in range(MAX_PAIRS * 4))
    decoded = decode(line)
    assert decoded is not None
    assert len(decoded) <= MAX_PAIRS


@pytest.mark.security
def test_an_over_long_value_is_bounded() -> None:
    line = f"type=SYSCALL comm={'x' * (MAX_VALUE_LEN * 3)}"
    decoded = decode(line)
    assert decoded is not None
    assert len(decoded["comm"]) <= MAX_VALUE_LEN


@pytest.mark.security
def test_an_over_long_key_is_not_claimed() -> None:
    """The key pattern caps length, so a huge key simply is not a pair."""
    huge = "k" * (MAX_KEY_LEN * 3)
    decoded = decode(f"{huge}=1 other=2")
    assert decoded is None or huge not in decoded


@pytest.mark.security
def test_a_key_is_identifier_shaped_so_prose_is_not_dragged_in() -> None:
    """Otherwise "everything before the equals sign" becomes the key.

    ``said the operator count=3`` must yield ``count``, never
    ``said the operator count``.
    """
    decoded = decode("type=SYSCALL node=web-01 the operator said count=3")
    assert decoded is not None
    assert "count" in decoded
    assert not any(" " in key for key in decoded)


# --------------------------------------------------------------------------
# It must not change how structured input is handled
# --------------------------------------------------------------------------


@pytest.mark.security
def test_json_lines_are_unaffected() -> None:
    """The decoder runs only after the JSON branch declines."""
    line = json.dumps(
        {
            "eventVersion": "1.08",
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "eventTime": "2026-10-14T01:00:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "1",
            "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
            "sourceIPAddress": "198.51.100.7",
            "eventID": "e1",
        }
    )
    event = normalize(line)
    assert event.source_type == "cloud"
    assert event.parse_status == "structured"


@pytest.mark.security
def test_malformed_json_is_still_carried_as_text_not_key_value_decoded() -> None:
    """A truncated JSON line must not be scavenged for pairs.

    It would yield a mapping assembled from a fragment, and attributing a
    source type to half a record is exactly the mis-attribution ``ingest/``
    refuses elsewhere.
    """
    event = normalize('{"eventSource": "sts.amazonaws.com", "eventName": "Assume')
    assert event.source_type == "unknown"
    # `partial` rather than `text` because _unrecognized attaches an
    # explanatory note on this path — pre-existing behaviour, not the decoder.
    # The property under test is that the note is the JSON one, which proves
    # the line returned before the decoder was ever consulted.
    assert any("looked like JSON" in note for note in event.notes), (
        "the line was scavenged for key=value pairs instead of being carried as a "
        "failed JSON decode"
    )
    assert event.vendor == "unrecognized"


@pytest.mark.security
def test_auditd_decodes_to_the_mapping_its_parser_already_claimed() -> None:
    """The point of the module: no new signature, no new parser.

    The auditd recognizer was written expecting ``{type, node, auid, comm}``
    and nothing was producing one.
    """
    event = normalize(
        "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"
    )
    assert event.source_type == "endpoint"
    assert event.parse_status == "structured"
    assert event.device.hostname == "web-01"
    assert event.actor.user_name == "svc-deploy"


@pytest.mark.security
def test_a_quoted_value_keeps_its_spaces() -> None:
    """auditd quotes values containing spaces; splitting on space would lose them."""
    decoded = decode('type=SYSCALL comm="sudo -i" exe=/usr/bin/sudo')
    assert decoded is not None
    assert decoded["comm"] == "sudo -i"


@pytest.mark.security
def test_an_unquoted_value_with_punctuation_stays_in_one_piece() -> None:
    """auditd's ``msg=audit(1760000001.200:2)`` must survive parens and colons.

    The endpoint parser reads auditd's own clock out of that value, so losing
    any of it loses the event's timestamp.
    """
    decoded = decode("type=SYSCALL msg=audit(1760000001.200:2): node=web-01 comm=bash")
    assert decoded is not None
    assert decoded["msg"].startswith("audit(1760000001.200:2)")


@pytest.mark.security
def test_a_decoded_line_that_no_signature_claims_is_not_attributed() -> None:
    """Fields visible, domain unclaimed — the honest middle outcome.

    ``parse_status`` reads ``partial`` rather than ``structured`` because the
    record decoded but nothing recognized it, and ``source_type`` stays
    ``unknown`` rather than being guessed from the field names.
    """
    event = normalize('level=error service=api user=svc-deploy msg="auth failed"')
    assert event.source_type == "unknown"
    assert event.parse_status != "structured"
