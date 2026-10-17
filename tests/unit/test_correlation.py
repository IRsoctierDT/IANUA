# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of entity resolution and incident assembly.

The tests that matter here are the ones about *not* linking. A missed link
costs an analyst a query; a false link produces a confident incident naming
the wrong principal, and that is the failure mode that ends trust in a SOC.
So most of this file is adversarial: the shapes that would over-merge if a
rule were relaxed, each pinned with the reason.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from correlation import (
    MAX_EVENT_SCORE,
    SCORE_PER_EXTRA_DOMAIN,
    SCORE_PER_EXTRA_ENTITY,
    SCORE_PER_EXTRA_EVENT,
    ThresholdError,
    Thresholds,
    assemble,
    references,
    resolve,
)
from ingest import normalize
from store.events import StoredEvent

_CLOUD = {
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
_IDENTITY = {
    "userPrincipalName": "svc-deploy@corp.example",
    "ipAddress": "198.51.100.7",
    "createdDateTime": "2026-10-14T01:05:00Z",
    "id": "e2",
    "appDisplayName": "Portal",
    "status": {"errorCode": 0},
    "userDisplayName": "Svc Deploy",
}
_ENDPOINT = {"type": "SYSCALL", "node": "web-01", "auid": "svc-deploy", "comm": "bash"}
_NOISE = {"type": "SYSCALL", "node": "unrelated", "auid": "alice", "comm": "ls"}


def _stored(
    records: tuple[str | Mapping[str, Any], ...], *, at: float = 1000.0
) -> tuple[StoredEvent, ...]:
    """Wrap normalized records as stored events without touching a database."""
    return tuple(
        StoredEvent(event_id=f"id{index}", ingested_at=at + index, event=normalize(record))
        for index, record in enumerate(records)
    )


def _of_kind(
    events: tuple[str | Mapping[str, Any], ...], kind: str
) -> list[tuple[str, tuple[str, ...]]]:
    resolved = resolve(tuple(normalize(record) for record in events))
    return [(e.key, e.aliases) for e in resolved if e.kind == kind]


# --------------------------------------------------------------------------
# Reference extraction
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_references_normalize_and_deduplicate() -> None:
    event = normalize({"type": "SYSCALL", "node": "WEB-01.corp.example", "auid": "Alice"})
    found = {(r.kind, r.value) for r in references(event)}
    assert ("host", "web-01") in found, "hostname must casefold and shorten"
    assert ("user", "alice") in found, "username must casefold"


@pytest.mark.unit
@pytest.mark.parametrize("placeholder", ["-", "unknown", "N/A", "localhost", "::1", "null"])
def test_placeholder_values_produce_no_reference(placeholder: str) -> None:
    """Joining on a placeholder links every host that logged one."""
    event = normalize({"type": "SYSCALL", "node": placeholder, "auid": placeholder})
    assert references(event) == ()


@pytest.mark.unit
def test_a_display_name_is_an_alias_but_never_a_join_key() -> None:
    """Two people share "John Smith"; identifiers do not contain spaces.

    Concretely load-bearing: the Entra parser maps ``userDisplayName`` into
    ``actor.user_name``, so that field is not always a login name.
    """
    event = normalize(_IDENTITY)
    refs = {r.value: r.joinable for r in references(event) if r.kind == "user"}
    assert refs["svc deploy"] is False
    assert refs["svc-deploy@corp.example"] is True


# --------------------------------------------------------------------------
# Not linking: the cases that matter
# --------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0", "1000", "S-1-5-18", "root", "administrator", "guest"])
def test_a_host_scoped_principal_never_joins_across_hosts(value: str) -> None:
    """uid 0 is root everywhere; S-1-5-18 is LocalSystem on every Windows host.

    Treating these as globally unique merges every machine's admin account
    into one entity, and from there every event into one incident.
    """
    users = _of_kind(
        (
            {"type": "SYSCALL", "node": "web-01", "auid": value},
            {"type": "SYSCALL", "node": "db-02", "auid": value},
        ),
        "user",
    )
    assert users == [("", (value.casefold(),))], "must be an alias with no join key"


@pytest.mark.unit
def test_the_two_ends_of_a_connection_are_two_addresses() -> None:
    """Regression: merging src and dst collapses every address in a window.

    The intra-event co-occurrence rule is right for ``actor`` (one actor) and
    ``device`` (one device) and catastrophically wrong for endpoints. Merging
    them made every source equal its destination, and transitively turned
    thirteen distinct addresses into one entity — so a single shared gateway
    produced one meaningless window-wide "incident".
    """
    addresses = _of_kind(
        (
            {
                "ts": "2026-10-14T01:00:00Z",
                "uid": "C1",
                "id.orig_h": "203.0.113.1",
                "id.resp_h": "10.0.0.5",
                "id.orig_p": 1,
                "id.resp_p": 443,
                "proto": "tcp",
            },
        ),
        "address",
    )
    assert len(addresses) == 2, f"src and dst must stay distinct, got {addresses}"


@pytest.mark.unit
def test_an_address_is_never_merged_into_a_host() -> None:
    """DHCP and NAT reuse addresses, so an address identifies a host only
    at a moment in time."""
    event = normalize({"type": "SYSCALL", "node": "web-01", "auid": "alice"})
    resolved = resolve((event,))
    kinds = {e.kind for e in resolved}
    for entity in resolved:
        assert not (entity.kind == "host" and any("." in a for a in entity.aliases)), (
            "an address leaked into a host entity"
        )
    assert "host" in kinds


@pytest.mark.unit
def test_unrelated_events_do_not_form_an_incident() -> None:
    assert assemble(_stored((_ENDPOINT, _NOISE))) == ()


# --------------------------------------------------------------------------
# Linking: the rules that should fire
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_uid_links_to_a_username_by_co_occurrence() -> None:
    """Not by resemblance — one event carried both, which is the evidence."""
    users = _of_kind(
        (
            {"type": "SYSCALL", "node": "web-01", "auid": "alice", "uid": "S-1-5-21-7-1105"},
            {"type": "SYSCALL", "node": "db-02", "auid": "S-1-5-21-7-1105"},
        ),
        "user",
    )
    assert len(users) == 1, f"the uid should have linked the two events: {users}"
    assert "alice" in users[0][1]


@pytest.mark.unit
def test_a_user_principal_joins_the_bare_username() -> None:
    users = _of_kind((_CLOUD, _IDENTITY), "user")
    assert len(users) == 1
    key, aliases = users[0]
    assert key == "svc-deploy@corp.example", "the domain-qualified form is canonical"
    assert {"svc-deploy", "svc-deploy@corp.example"} <= set(aliases)


@pytest.mark.unit
def test_a_principal_does_not_join_a_merely_similar_username() -> None:
    """The local part must match outright — no prefix or similarity test."""
    users = _of_kind(
        (
            {"type": "SYSCALL", "node": "web-01", "auid": "svc"},
            {
                "userPrincipalName": "svc-deploy@corp.example",
                "ipAddress": "198.51.100.7",
                "createdDateTime": "2026-10-14T01:05:00Z",
                "id": "x",
                "appDisplayName": "P",
                "status": {"errorCode": 0},
            },
        ),
        "user",
    )
    assert len(users) == 2, f"'svc' must not absorb 'svc-deploy@...': {users}"


@pytest.mark.unit
def test_resolution_is_independent_of_event_order() -> None:
    """Canonical keys must not depend on which event arrived first."""
    forward = resolve(tuple(normalize(r) for r in (_CLOUD, _IDENTITY, _ENDPOINT)))
    backward = resolve(tuple(normalize(r) for r in (_ENDPOINT, _IDENTITY, _CLOUD)))
    assert forward == backward


@pytest.mark.unit
def test_an_address_written_two_ways_is_one_entity() -> None:
    """Exact normalized equality, for addresses as it already is for hosts.

    ``2001:db8:0:0:0:0:0:1`` and ``2001:db8::1`` are one address, and a
    dual-stack socket reports the IPv4 peer ``203.0.113.9`` as
    ``::ffff:203.0.113.9``. Compared as strings each pair was two entities
    that never linked — an honest non-match, but one decided by the sender's
    spelling rather than by the evidence.
    """

    def flow(orig: str, resp: str, index: int) -> dict[str, Any]:
        return {
            "ts": f"2026-10-14T01:{index:02d}:00Z",
            "uid": f"C{index}",
            "id.orig_h": orig,
            "id.resp_h": resp,
            "id.orig_p": 1000 + index,
            "id.resp_p": 443,
            "proto": "tcp",
        }

    addresses = _of_kind(
        (
            flow("2001:db8:0:0:0:0:0:1", "::ffff:203.0.113.9", 1),
            flow("2001:DB8::1", "203.0.113.9", 2),
        ),
        "address",
    )
    assert sorted(key for key, _ in addresses) == ["2001:db8::1", "203.0.113.9"], addresses


@pytest.mark.unit
def test_a_non_address_in_an_address_field_is_kept_for_provenance_only() -> None:
    """The alias survives — an analyst should see what the source wrote — but keys nothing."""
    event = normalize(dict(_CLOUD, sourceIPAddress="ec2.amazonaws.com"))
    refs = [(r.value, r.joinable) for r in references(event) if r.kind == "address"]
    assert refs == [("ec2.amazonaws.com", False)], refs


@pytest.mark.unit
def test_an_ip_named_host_still_links_its_own_events() -> None:
    """Not shortened, but still a host: the same literal on two events is one host."""
    hosts = _of_kind(
        (
            {"type": "SYSCALL", "node": "10.0.0.5", "auid": "alice", "comm": "a"},
            {"type": "SYSCALL", "node": "10.0.0.5", "auid": "bob", "comm": "b"},
        ),
        "host",
    )
    assert hosts == [("10.0.0.5", ("10.0.0.5",))], hosts


@pytest.mark.unit
@pytest.mark.parametrize(
    ("hostname", "short"),
    [
        ("web-01.corp.example", "web-01"),
        ("web-01.corp.example.", "web-01"),
        ("web_01.corp.example", "web_01"),
        ("m\u00fcnchen.corp.example", "m\u00fcnchen"),
        ("desktop-7f3a", "desktop-7f3a"),
    ],
)
def test_a_dns_shaped_name_still_short_forms(hostname: str, short: str) -> None:
    """The shape guard refuses octets and decorations, not names: LDH, underscore, IDN."""
    event = normalize({"type": "SYSCALL", "node": hostname, "auid": "alice", "comm": "a"})
    refs = [(r.value, r.joinable) for r in references(event) if r.kind == "host"]
    assert refs == [(short, True)], refs


@pytest.mark.unit
def test_a_hostname_that_is_neither_a_name_nor_an_address_is_kept_for_provenance() -> None:
    """``10.0.0.5:514`` is what a relay wrote; an analyst sees it, nothing joins on it."""
    event = normalize({"type": "SYSCALL", "node": "10.0.0.5:514", "auid": "alice", "comm": "a"})
    refs = [(r.value, r.joinable) for r in references(event) if r.kind == "host"]
    assert refs == [("10.0.0.5:514", False)], refs


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_cross_domain_story_assembles_into_one_incident() -> None:
    incidents = assemble(_stored((_CLOUD, _IDENTITY, _ENDPOINT, _NOISE)))
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.event_count == 3, "the unrelated event must not be absorbed"
    assert incident.domains == ("cloud", "endpoint", "identity")
    assert incident.first_seen is not None and incident.last_seen is not None
    assert incident.first_seen < incident.last_seen


@pytest.mark.unit
def test_the_score_is_the_documented_arithmetic() -> None:
    """Reproducible from the constants, so a reviewer can check it by hand."""
    incident = assemble(_stored((_CLOUD, _IDENTITY, _ENDPOINT)))[0]
    expected = (
        SCORE_PER_EXTRA_DOMAIN * (len(incident.domains) - 1)
        + SCORE_PER_EXTRA_ENTITY * (len(incident.entities) - 1)
        + min(MAX_EVENT_SCORE, SCORE_PER_EXTRA_EVENT * (incident.event_count - 2))
    )
    assert incident.score == expected
    assert len(incident.reasons) >= 2, "every contribution must be named"


@pytest.mark.unit
def test_an_over_common_entity_is_demoted_to_context_not_dropped() -> None:
    """One shared gateway must not collapse the window, but must still show."""
    shared = [
        {
            "ts": f"2026-10-14T01:{index:02d}:00Z",
            "uid": "C1",
            "id.orig_h": "203.0.113.1",
            "id.resp_h": f"10.0.0.{index}",
            "id.orig_p": 1000 + index,
            "id.resp_p": 443,
            "proto": "tcp",
        }
        for index in range(1, 9)
    ]
    window = _stored(tuple(shared))
    assert len(assemble(window, thresholds=Thresholds(max_entity_fanout=50))) == 1
    assert assemble(window, thresholds=Thresholds(max_entity_fanout=3)) == (), (
        "a demoted gateway leaves nothing to join on, which is the point"
    )


@pytest.mark.unit
def test_min_events_requires_corroboration() -> None:
    window = _stored((_CLOUD, _IDENTITY, _ENDPOINT))
    assert assemble(window, thresholds=Thresholds(min_events=3))[0].event_count == 3
    assert assemble(window, thresholds=Thresholds(min_events=4)) == ()


@pytest.mark.unit
def test_incidents_come_back_highest_score_first() -> None:
    window = _stored((_CLOUD, _IDENTITY, _ENDPOINT, _NOISE, _NOISE))
    incidents = assemble(window)
    scores = [incident.score for incident in incidents]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.unit
def test_an_all_undated_incident_reports_no_window() -> None:
    """``ingest/`` never back-fills "now", so an unknown time stays unknown."""
    pair = (
        {"type": "SYSCALL", "node": "web-01", "auid": "alice", "comm": "bash"},
        {"type": "SYSCALL", "node": "web-01", "auid": "alice", "comm": "ls"},
    )
    assert all(normalize(record).timestamp is None for record in pair)
    incident = assemble(_stored(pair))[0]
    assert incident.first_seen is None and incident.last_seen is None


@pytest.mark.unit
def test_an_empty_window_yields_nothing() -> None:
    assert assemble(()) == ()


@pytest.mark.unit
@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_events": 0},
        {"min_events": 0},
        {"max_entity_fanout": 0},
        {"max_incidents": 0},
        {"min_events": -1},
    ],
)
def test_a_nonsensical_threshold_raises_rather_than_clamping(kwargs: dict[str, int]) -> None:
    """An analyst must be able to trust the reported minimum was the one set."""
    with pytest.raises(ThresholdError):
        assemble(_stored((_CLOUD, _IDENTITY)), thresholds=Thresholds(**kwargs))


@pytest.mark.unit
def test_a_qualified_name_whose_short_form_is_a_placeholder_yields_nothing() -> None:
    """``localhost.corp.example`` shortens to ``localhost``, which links nothing.

    The placeholder check has to run *after* shortening, or a fully-qualified
    loopback name would slip past it and join every host that logged one.
    """
    event = normalize({"type": "SYSCALL", "node": "localhost.corp.example", "auid": "alice"})
    assert [r for r in references(event) if r.kind == "host"] == []


@pytest.mark.unit
def test_repeated_values_in_one_event_produce_one_reference() -> None:
    """A source that repeats a value across fields must not inflate anything."""
    event = normalize(
        {
            "ts": "2026-10-14T01:00:00Z",
            "uid": "C1",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "10.0.0.5",
            "id.orig_p": 1,
            "id.resp_p": 443,
            "proto": "tcp",
        }
    )
    addresses = [r for r in references(event) if r.kind == "address"]
    assert len(addresses) == 1, f"the same address twice is one reference: {addresses}"


@pytest.mark.unit
def test_identity_is_transitive_across_a_chain_of_events() -> None:
    """a→b, b→c, c→d must resolve to one entity, not three.

    Exercises the union's path compression as a side effect, but the property
    is the point: an actor seen under a different alias in each of four events
    is still one actor.
    """
    chain = (
        {"type": "SYSCALL", "node": "h1", "auid": "alice", "uid": "S-1-5-21-7-1"},
        {"type": "SYSCALL", "node": "h2", "auid": "S-1-5-21-7-1", "uid": "S-1-5-21-7-2"},
        {"type": "SYSCALL", "node": "h3", "auid": "S-1-5-21-7-2", "uid": "S-1-5-21-7-3"},
        {"type": "SYSCALL", "node": "h4", "auid": "S-1-5-21-7-3"},
    )
    users = _of_kind(chain, "user")
    assert len(users) == 1, f"the chain should resolve to one actor: {users}"
    assert "alice" in users[0][1]
    assert len(users[0][1]) == 4, "every alias in the chain should be recorded"


@pytest.mark.unit
def test_a_minimal_incident_scores_zero_and_says_why() -> None:
    """Corroborated but unremarkable is a real outcome, not an error.

    Two events on one host for one user span no domain boundary and link one
    entity, so every scoring term is zero. The incident still exists — it was
    corroborated — and carries a reason explaining the score rather than an
    empty list a caller would have to interpret.
    """
    # ``root`` is host-scoped so it never joins, leaving the host as the one
    # linking entity. Two events at the minimum therefore zero every term:
    # no domain crossed, no second entity, no event beyond the minimum.
    pair = (
        {"type": "SYSCALL", "node": "web-01", "auid": "root", "comm": "bash"},
        {"type": "SYSCALL", "node": "web-01", "auid": "root", "comm": "ls"},
    )
    incidents = assemble(_stored(pair), thresholds=Thresholds(min_events=2))
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.domains == ("endpoint",), "single domain"
    assert len(incident.entities) == 1, f"expected one linking entity: {incident.entities}"
    assert incident.score == 0
    assert incident.reasons == ("0: corroborated but single-domain, single-entity",)
