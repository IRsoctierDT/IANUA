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

from ingest import normalize
from ingest.keyvalue import (
    MAX_KEY_LEN,
    MAX_PAIRS,
    MAX_VALUE_LEN,
    MIN_COVERAGE,
    MIN_PAIRS,
    decode,
)

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
    """Pinned against a fixed input, not one scaled from the constant.

    Scaling the input with the constant under test means raising the constant
    raises the input too, so the bound can be loosened arbitrarily with the
    test still green — found by review. The literals here are the contract.
    """
    assert MAX_PAIRS <= 256, "the pair ceiling was raised; justify it here"
    line = " ".join(f"k{index}=v{index}" for index in range(2_000))
    decoded = decode(line)
    assert decoded is not None
    assert len(decoded) <= 256


@pytest.mark.security
def test_an_over_long_value_is_bounded() -> None:
    """Fixed literals, for the same reason as the pair ceiling."""
    assert MAX_VALUE_LEN <= 4096, "the value ceiling was raised; justify it here"
    line = f"type=SYSCALL comm={'x' * 50_000}"
    decoded = decode(line)
    assert decoded is not None
    assert len(decoded["comm"]) <= 4096


@pytest.mark.security
def test_an_over_long_key_is_not_claimed() -> None:
    """The key pattern caps length, so a huge key simply is not a pair."""
    assert MAX_KEY_LEN <= 64, "the key ceiling was raised; justify it here"
    huge = "k" * 1_000
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


@pytest.mark.security
def test_a_repeated_key_keeps_the_first_occurrence() -> None:
    """Real auditd auth records carry ``msg=`` twice, and last-wins lost the clock.

    ``type=USER_AUTH msg=audit(<epoch>:<serial>): … msg='op=… res=failed'`` —
    last-wins clobbered the clock form, so every authentication and sudo
    record landed undated. Found by review. First-wins is also defensive: a
    later pair cannot restate what the head of the line already declared.
    """
    decoded = decode(
        "type=USER_AUTH msg=audit(1760000000.100:1): user=real msg='op=x' user=attacker"
    )
    assert decoded is not None
    assert decoded["msg"].startswith("audit(1760000000.100:1)")
    assert decoded["user"] == "real", "a later pair overwrote an earlier one"


@pytest.mark.security
def test_a_real_auditd_auth_record_keeps_its_timestamp() -> None:
    """End to end through normalize, because the clock is what was being lost."""
    event = normalize(
        "type=USER_AUTH msg=audit(1760000000.100:1): pid=1 uid=0 auid=svc-deploy "
        "node=web-01 msg='op=PAM:authentication acct=\"svc-deploy\" res=failed'"
    )
    assert event.source_type == "endpoint"
    assert event.timestamp == 1760000000.1, "the auth record landed undated"
    assert event.device.hostname == "web-01"


#: A verbatim auditd failed-password record. Everything an analyst needs is
#: inside the *second*, single-quoted ``msg``, which is how auditd writes
#: USER_AUTH / USER_ACCT / USER_CMD / USER_LOGIN / CRED_* — every SSH
#: authentication and every sudo invocation on a Linux node.
_NESTED_AUTH = (
    "type=USER_AUTH msg=audit(1760000000.123:456): pid=1234 uid=0 auid=4294967295 "
    'ses=4294967295 msg=\'op=PAM:authentication acct="svc-deploy" '
    'exe="/usr/sbin/sshd" hostname=? addr=203.0.113.9 terminal=ssh res=failed\''
)


@pytest.mark.security
def test_the_nested_auditd_payload_is_decoded_not_swallowed() -> None:
    """Without this, collecting audit.log produced events with no actor at all.

    The pattern matches the quoted payload as one value, so ``finditer``
    resumed *after* it and ``acct``/``addr``/``res`` were never produced as
    keys. The record reached the parser with only ``type/msg/pid/uid/auid/ses``,
    so ``user`` fell back to ``auid`` — ``4294967295``, the unset sentinel every
    pre-auth sshd record carries — with no address, no result and no
    observables, while still being stamped ``structured`` with no note. Found
    by review.
    """
    decoded = decode(_NESTED_AUTH)
    assert decoded is not None
    assert decoded["acct"] == "svc-deploy", "the nested payload was swallowed whole"
    assert decoded["addr"] == "203.0.113.9"
    assert decoded["res"] == "failed", "a failed password was indistinguishable from a success"
    # The clock form still wins the `msg` key — first-occurrence-wins, which is
    # what keeps the record dated.
    assert decoded["msg"].startswith("audit(1760000000.123:456)")


@pytest.mark.security
def test_a_nested_auth_record_normalizes_to_an_attributable_event() -> None:
    """End to end: the event must carry an actor and an address, not a sentinel."""
    event = normalize(_NESTED_AUTH)
    assert event.source_type == "endpoint"
    assert event.timestamp == 1760000000.123
    assert event.actor.user_name == "svc-deploy", (
        f"the actor is {event.actor.user_name!r} — the unset auid sentinel rather than "
        "the account that failed to authenticate"
    )
    assert event.src_endpoint.ip == "203.0.113.9"
    assert "203.0.113.9" in event.observables


@pytest.mark.security
def test_a_nested_payload_cannot_overwrite_what_the_record_head_declared() -> None:
    """First-occurrence-wins holds across levels, which is the defensive half.

    A payload an attacker influences must not be able to restate the record's
    own ``type`` or ``exe``. Only keys the head never declared are merged.
    """
    decoded = decode(
        'type=USER_AUTH msg=audit(1760000000.100:1): exe="/usr/sbin/sshd" '
        'msg=\'type=EVIL exe="/bin/evil" acct="real"\''
    )
    assert decoded is not None
    assert decoded["type"] == "USER_AUTH", "a nested pair overwrote the record type"
    assert decoded["exe"] == "/usr/sbin/sshd", "a nested pair overwrote the executable"
    assert decoded["acct"] == "real", "a key the head never declared should still merge"


@pytest.mark.security
@pytest.mark.parametrize(
    "line",
    [
        "the operator said 'count=3 limit=9' during the call at length this morning",
        "error: the config read 'a=1 b=2 c=3' which was not what anyone expected here",
        "note='x=1 y=2'",
    ],
)
def test_nesting_cannot_promote_prose_into_an_event(line: str) -> None:
    """The merge runs only *after* the thresholds pass, so it cannot promote.

    Otherwise a sentence containing a quoted pair run would become a
    multi-field "event" — the manufactured telemetry this module exists to
    refuse. The control stays on the outer line.
    """
    assert decode(line) is None


@pytest.mark.security
def test_only_quoted_values_are_rescanned() -> None:
    """A bare value cannot hold a space, so it cannot hold a second pair.

    Re-scanning bare values would mine a URL's query string for pairs nobody
    wrote: ``url=http://h/?a=1&b=2`` would gain ``a`` and ``b``.
    """
    decoded = decode("type=PROXY node=web-01 url=http://h/p?a=1&b=2 status=200")
    assert decoded is not None
    assert "a" not in decoded and "b" not in decoded, (
        "a bare value's query string was mined for pairs"
    )


@pytest.mark.security
def test_decode_is_not_catastrophic_on_a_crafted_line() -> None:
    """A log line is attacker-influenced input; the pattern must not backtrack.

    Bounded by wall clock rather than by inspection, because a regex's
    behaviour under a crafted input is not obvious from reading it.
    """
    import time

    hostile = "a=" + "=" * 5_000 + " b=" + '"' * 5_000 + " c=1 d=2"
    start = time.monotonic()
    decode(hostile)
    assert time.monotonic() - start < 1.0, "decode() is super-linear on crafted input"


@pytest.mark.security
def test_a_syscall_records_argument_registers_are_not_a_command_line() -> None:
    """On SYSCALL, a0/a1… are syscall argument registers, not argv.

    Reassembling them produced a plausible ``command_line`` out of register
    values on the most frequent auditd record type — fabricated evidence an
    analyst would read as a command that was never run. Reachable for the
    first time once this decoder existed, which is why it is pinned here.
    """
    syscall = normalize(
        "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc comm=bash "
        "a0=7ffd1234 a1=0 a2=1b6"
    )
    assert syscall.actor.command_line is None, (
        f"fabricated a command line from registers: {syscall.actor.command_line!r}"
    )
    execve = normalize('type=EXECVE msg=audit(1760000002.300:3): argc=2 a0="curl" a1="-s"')
    assert execve.actor.command_line == "curl -s", "EXECVE argv reassembly was lost"
