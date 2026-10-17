# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Correlation decides who did what — hold its attribution closed.

Most of this platform's security tests guard against code reaching somewhere
it should not. Correlation's security property is different and less obvious:
**a false merge is a wrong accusation.** If two principals resolve to one
entity, the resulting incident names the wrong person with full confidence,
and every downstream action — a containment plan, an escalation, a report —
inherits that error. Over-merge resistance is therefore tested here, beside
the usual inertness and bounds, not in the behavioural suite alone.

Every field correlation reads is attacker-influenced: a hostname is whatever
the endpoint claimed, a username whatever was typed. The tests below cover the
*generic* over-merge vectors that do not require the attacker to know anything
about the estate — placeholders, built-in principals, and connection endpoints.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from correlation import Thresholds, assemble, references, resolve
from ingest import MAX_RAW_BYTES, normalize
from ingest.schema import MAX_FIELD_LEN
from store.events import StoredEvent

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORRELATION_ROOT = _REPO_ROOT / "correlation"

_BANNED_IMPORTS = {
    "socket",
    "subprocess",
    "requests",
    "urllib",
    "http",
    "smtplib",
    "importlib",
    "pickle",
    "ctypes",
    "sqlite3",
}
_BANNED_CALLS = {"eval", "exec", "compile", "open", "__import__", "input"}
_CLOCK_ATTRS = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}


def _modules() -> list[Path]:
    return sorted(_CORRELATION_ROOT.rglob("*.py"))


def _stored(records: tuple[str | Mapping[str, Any], ...]) -> tuple[StoredEvent, ...]:
    return tuple(
        StoredEvent(event_id=f"id{index}", ingested_at=1000.0 + index, event=normalize(record))
        for index, record in enumerate(records)
    )


def _flow(orig: str, resp: str, index: int) -> dict[str, Any]:
    """A Zeek conn record whose only content of interest is its two endpoints."""
    return {
        "ts": f"2026-10-14T01:{index:02d}:00Z",
        "uid": f"C{index}",
        "id.orig_h": orig,
        "id.resp_h": resp,
        "id.orig_p": 1000 + index,
        "id.resp_p": 443,
        "proto": "tcp",
    }


# --------------------------------------------------------------------------
# Inertness
# --------------------------------------------------------------------------


@pytest.mark.security
def test_correlation_imports_nothing_that_could_reach_out_or_execute() -> None:
    """Pure computation over events a caller already holds.

    ``sqlite3`` is banned too: correlation consumes ``StoredEvent`` values, it
    does not open the database. Keeping the storage driver out means the layer
    that decides attribution cannot also rewrite the evidence.
    """
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {node.module}"


@pytest.mark.security
def test_correlation_calls_no_executor_and_opens_no_file() -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path}: calls {node.func.id}()"


@pytest.mark.security
def test_correlation_reads_no_clock() -> None:
    """The window is whatever the caller selected; incidents must be replayable."""
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in _CLOCK_ATTRS, (
                    f"{path}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_correlation_adds_no_runtime_dependency() -> None:
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["dependencies"]
    assert declared == [], f"correlation must not introduce runtime dependencies: {declared}"


# --------------------------------------------------------------------------
# Over-merge resistance — a false merge is a wrong accusation
# --------------------------------------------------------------------------


@pytest.mark.security
# The literals below are values this layer must REFUSE as identifiers, not
# addresses to bind; the rule reads "0.0.0.0" as a bind host.
@pytest.mark.parametrize(
    "value",
    ["-", "unknown", "N/A", "localhost", "0.0.0.0", "null", "*"],  # noqa: S104
)
def test_a_placeholder_cannot_be_used_to_link_victims(value: str) -> None:
    """A source that logs "-" for every field must not link its events.

    This is the cheapest over-merge vector there is: it needs no knowledge of
    the estate, only a source that emits placeholders.
    """
    window = _stored(
        (
            {"type": "SYSCALL", "node": value, "auid": value, "comm": "a"},
            {"type": "SYSCALL", "node": value, "auid": value, "comm": "b"},
        )
    )
    assert assemble(window) == ()


@pytest.mark.security
@pytest.mark.parametrize("value", ["0", "root", "administrator", "S-1-5-18", "guest"])
def test_a_builtin_principal_cannot_link_two_hosts(value: str) -> None:
    """Every Linux box has uid 0; every Windows box has S-1-5-18.

    Without this, any two hosts that both logged system activity would land in
    one incident attributed to one "user".
    """
    window = _stored(
        (
            {"type": "SYSCALL", "node": "web-01", "auid": value, "comm": "a"},
            {"type": "SYSCALL", "node": "db-02", "auid": value, "comm": "b"},
        )
    )
    assert assemble(window) == ()


@pytest.mark.security
def test_a_shared_gateway_cannot_collapse_a_window_into_one_incident() -> None:
    """The failure that looks most like a finding: one giant false incident."""
    flows = tuple(
        {
            "ts": f"2026-10-14T01:{index:02d}:00Z",
            "uid": "C1",
            "id.orig_h": "203.0.113.1",
            "id.resp_h": f"10.0.0.{index}",
            "id.orig_p": 1000 + index,
            "id.resp_p": 443,
            "proto": "tcp",
        }
        for index in range(1, 13)
    )
    window = _stored(flows)
    incidents = assemble(window, thresholds=Thresholds(max_entity_fanout=4))
    assert incidents == (), "the over-common gateway must be demoted, not joined on"


@pytest.mark.security
def test_connection_endpoints_are_never_merged() -> None:
    """Regression guard for the worst bug this package had.

    Merging ``src_endpoint`` with ``dst_endpoint`` made every source address
    equal its destination and transitively collapsed every address in a window
    into one entity. Pinned as a security test because the consequence is a
    window-wide incident attributed to an address that nothing actually links.
    """
    event = normalize(
        {
            "ts": "2026-10-14T01:00:00Z",
            "uid": "C1",
            "id.orig_h": "203.0.113.1",
            "id.resp_h": "10.0.0.5",
            "id.orig_p": 1,
            "id.resp_p": 443,
            "proto": "tcp",
        }
    )
    addresses = [entity for entity in resolve((event,)) if entity.kind == "address"]
    assert len(addresses) == 2
    assert {entity.key for entity in addresses} == {"203.0.113.1", "10.0.0.5"}


@pytest.mark.security
def test_a_display_name_collision_cannot_merge_two_people() -> None:
    """Two principals sharing a display name must stay two entities."""
    first = {
        "userPrincipalName": "alice.smith@corp.example",
        "ipAddress": "198.51.100.1",
        "createdDateTime": "2026-10-14T01:00:00Z",
        "id": "a",
        "appDisplayName": "P",
        "status": {"errorCode": 0},
        "userDisplayName": "John Smith",
    }
    second = dict(first, userPrincipalName="john.smith@corp.example", id="b")
    users = [e for e in resolve((normalize(first), normalize(second))) if e.kind == "user"]
    keys = {entity.key for entity in users if entity.joinable}
    assert keys == {"alice.smith@corp.example", "john.smith@corp.example"}, (
        f"a shared display name merged two principals: {users}"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    "spelling",
    [
        "127.0.0.1",
        "::1",
        "::",
        "0:0:0:0:0:0:0:1",
        "::ffff:127.0.0.1",
        "127.0.0.2",
        "0000::1",
        "::0",
        "0:0:0:0:0:0:0:0",
    ],
)
def test_a_loopback_or_unspecified_address_is_refused_in_every_spelling(spelling: str) -> None:
    """``NEVER_JOIN`` names four spellings; the refusal must be on the parsed value.

    Measured before the fix, through the Zeek parser: the last six spellings
    here each became a *joinable* address entity, and two flows that shared
    nothing but that placeholder became a two-event incident. The same defect
    class AGENTS.md §5 records for the listener's bind address — a rule written
    as a string that the thing it means to stop can simply spell differently.
    The first three are the string set still doing its job, as defence in depth.
    """
    window = _stored((_flow(spelling, "10.0.0.5", 1), _flow(spelling, "10.0.0.6", 2)))
    assert assemble(window) == (), f"{spelling!r} linked two unrelated flows"
    joinable = {
        entity.key
        for entity in resolve(tuple(item.event for item in window))
        if entity.kind == "address" and entity.joinable
    }
    assert joinable == {"10.0.0.5", "10.0.0.6"}, f"{spelling!r} survived as a join key"


@pytest.mark.security
def test_an_ip_literal_in_the_hostname_field_cannot_merge_two_hosts() -> None:
    """A sender with no name logs its address where its hostname would go.

    Measured before the fix, through the auditd parser: ``node=10.0.0.5`` and
    ``node=10.0.0.7`` were short-formed at the first dot to one host ``10``,
    and two events that shared nothing else assembled into a score-10 incident
    linking both hosts and both their users — the attribution error boundary
    11 exists to prevent, produced by a rule meant for ``web-01.corp.example``.
    """
    window = _stored(
        (
            {"type": "SYSCALL", "node": "10.0.0.5", "auid": "alice", "comm": "a"},
            {"type": "SYSCALL", "node": "10.0.0.7", "auid": "bob", "comm": "b"},
        )
    )
    assert assemble(window) == (), "two IP-named hosts merged into one"
    hosts = {e.key for e in resolve(tuple(item.event for item in window)) if e.kind == "host"}
    assert hosts == {"10.0.0.5", "10.0.0.7"}, hosts


@pytest.mark.security
@pytest.mark.parametrize("spelling", ["127.0.0.1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::"])
def test_a_loopback_literal_in_the_hostname_field_identifies_nothing(spelling: str) -> None:
    """The parsed-value refusal applies to a hostname field too, in every spelling."""
    window = _stored(
        (
            {"type": "SYSCALL", "node": spelling, "auid": "alice", "comm": "a"},
            {"type": "SYSCALL", "node": spelling, "auid": "bob", "comm": "b"},
        )
    )
    assert assemble(window) == (), f"{spelling!r} in a hostname field linked two events"
    hosts = [e for e in resolve(tuple(item.event for item in window)) if e.kind == "host"]
    assert hosts == [], hosts


# --------------------------------------------------------------------------
# Bounds and determinism
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_event_window_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Correlation is superlinear in places; an unbounded window is an outage."""
    window = _stored(
        tuple(
            {"type": "SYSCALL", "node": "web-01", "auid": "alice", "comm": str(index)}
            for index in range(40)
        )
    )
    incident = assemble(window, thresholds=Thresholds(max_events=5))[0]
    assert incident.event_count == 5, "events past max_events must not be considered"


@pytest.mark.security
def test_the_incident_count_is_bounded() -> None:
    pairs: list[str | Mapping[str, Any]] = []
    for index in range(10):
        pairs.append({"type": "SYSCALL", "node": f"h{index}", "auid": f"u{index}", "comm": "a"})
        pairs.append({"type": "SYSCALL", "node": f"h{index}", "auid": f"u{index}", "comm": "b"})
    incidents = assemble(_stored(tuple(pairs)), thresholds=Thresholds(max_incidents=3))
    assert len(incidents) == 3


@pytest.mark.security
def test_an_oversized_field_cannot_grow_an_entity_key() -> None:
    """Bounds are re-asserted: the value came from a system we do not control."""
    event = normalize({"type": "SYSCALL", "node": "h", "auid": "a" * (MAX_FIELD_LEN * 4)})
    for ref in references(event):
        assert len(ref.value) <= MAX_FIELD_LEN, "an unbounded value reached an entity key"


@pytest.mark.security
def test_output_is_identical_under_input_permutation() -> None:
    """Evidence must be reproducible: same events, same incidents, same order."""
    records = (
        {"type": "SYSCALL", "node": "web-01", "auid": "alice", "comm": "bash"},
        {"type": "SYSCALL", "node": "web-01", "auid": "alice", "comm": "curl"},
        {"type": "SYSCALL", "node": "db-02", "auid": "bob", "comm": "psql"},
        {"type": "SYSCALL", "node": "db-02", "auid": "bob", "comm": "ls"},
    )
    # Ids stay bound to their record, so only the ORDER differs between the
    # two runs. Re-numbering by position would change the event_ids themselves,
    # and the score tie-break reads event_ids[0] — that would test the fixture
    # rather than the property.
    window = _stored(records)
    forward = assemble(window)
    shuffled = assemble(tuple(reversed(window)))
    assert [i.event_ids for i in forward] == [i.event_ids for i in shuffled]
    assert [i.score for i in forward] == [i.score for i in shuffled]
    assert [i.domains for i in forward] == [i.domains for i in shuffled]
    assert [tuple(e.key for e in i.entities) for i in forward] == [
        tuple(e.key for e in i.entities) for i in shuffled
    ]


# --------------------------------------------------------------------------
# Placeholder values must never link
# --------------------------------------------------------------------------


def _nested_auth(ip: str, account: str, index: int) -> str:
    """A verbatim auditd failed-password record, payload nested as auditd writes it."""
    return (
        f"type=USER_AUTH msg=audit(17600000{index:02d}.100:{index}): pid={1000 + index} "
        f"uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication "
        f'acct="{account}" exe="/usr/sbin/sshd" hostname=? '
        f"addr={ip} terminal=ssh res=failed'"
    )


@pytest.mark.security
def test_auditds_question_mark_placeholder_never_links() -> None:
    """``hostname=?`` is on every pre-authentication sshd record.

    auditd writes ``?`` for a field it has no value for, so collecting
    ``audit.log`` produces a stream of events all sharing that "host". Joining
    on it merges unrelated hosts' authentication activity into one entity —
    the same failure ``NEVER_JOIN`` already refuses for ``-`` and ``unknown``.

    Reachable only once the nested ``msg=`` payload was decoded, which is why
    it arrives with that fix: before it, ``hostname`` was never extracted at
    all. Measured before the exclusion: two unrelated attacks, on different
    accounts from different addresses, assembled into **one** 12-event
    incident scored 40; after it, two correct 6-event incidents.
    """
    from correlation.entities import NEVER_JOIN

    assert "?" in NEVER_JOIN, "auditd's placeholder host would link every pre-auth record"

    stored = _stored(
        tuple(_nested_auth("203.0.113.9", "svc-deploy", index) for index in range(6))
        + tuple(_nested_auth("198.51.100.4", "backup-svc", index) for index in range(6, 12))
    )
    incidents = assemble(stored)

    assert len(incidents) == 2, (
        f"two unrelated attacks assembled into {len(incidents)} incident(s); they were "
        "merged on a placeholder host"
    )
    for incident in incidents:
        keys = {entity.key for entity in incident.entities}
        assert "?" not in keys
        assert len(incident.event_ids) == 6


@pytest.mark.security
def test_the_placeholder_set_still_lets_a_real_host_link() -> None:
    """A deny set that refuses real hostnames would break correlation instead."""
    stored = _stored(
        tuple(
            _nested_auth("203.0.113.9", "svc-deploy", index).replace(
                "hostname=?", "hostname=web-01"
            )
            for index in range(4)
        )
    )
    incidents = assemble(stored)
    assert len(incidents) == 1
    keys = {entity.key for entity in incidents[0].entities}
    assert "web-01" in keys, "a real hostname stopped linking"


#: ``AGENTS.md`` §5's own worked example of the verbatim-retention residual: five
#: prose fragments ``_DOMAIN`` matches, extracted whenever a record never decodes
#: to a mapping. Duplicated from ``test_ingest_hardening.py`` on purpose — a test
#: module importing from another is a coupling that breaks on collection order.
_PROSE_BODY = (
    "Dear Mr.Jones, please urgently.Reply about invoice 44.Smith "
    "at acct-7781.Watson, cc Ms.Delacroix"
)
_PROSE_NAMES = frozenset(
    {"Mr.Jones", "urgently.Reply", "44.Smith", "acct-7781.Watson", "Ms.Delacroix"}
)

#: The four regimes in which a record is retained verbatim.
_VERBATIM_REGIMES = [
    pytest.param(f'{{"Subject": "hi", "Body": "{_PROSE_BODY}",}}', id="json-with-a-trailing-comma"),
    pytest.param(
        f'[{{"Subject": "hi", "Body": "{_PROSE_BODY}"}}]', id="json-array-rather-than-an-object"
    ),
    pytest.param(_PROSE_BODY, id="never-json-at-all"),
    pytest.param(
        json.dumps({"Subject": "hi", "Body": _PROSE_BODY, "pad": "x" * (MAX_RAW_BYTES + 100)}),
        id="past-the-MAX_RAW_BYTES-ceiling",
    ),
]


@pytest.mark.security
@pytest.mark.parametrize("raw", _VERBATIM_REGIMES)
def test_prose_fragments_from_verbatim_retention_never_become_join_keys(raw: str) -> None:
    """The guard: observables do not reach entity resolution, by construction.

    ``AGENTS.md`` §5 and two test docstrings called the fragments a verbatim
    record yields "false correlation join keys". Measured, they are not:
    :func:`references` builds entity references from typed fields only
    (``actor.*``, ``device.*``, the endpoint addresses) and never reads
    ``observables``, so two unrelated verbatim events sharing every one of the
    five names resolve to **no** entity at all. The fragments' real reach is
    the store's indexed ``observables`` table — a pivot key for
    ``query(observable=...)`` — and the backup attestation, not correlation.

    This test turns that measurement into a guard in two layers. Behaviourally:
    a verbatim event yields no reference and no entity, while a positive
    control proves the resolver *can* join (two auditd events sharing a user
    resolve to one ``user`` entity), so "no entities" is not a broken resolver.
    Structurally (the test below): no module under ``correlation/`` names
    ``observables`` at all. Wiring observables into entity resolution is a
    legitimate future choice — but it makes every ``word.Word`` fragment a join
    key, which is the plausibility question §5 refused to answer with a TLD
    list, and these tests force that question to be answered in the open first.
    """
    event = normalize(raw)
    # Premise, so the guard cannot be vacuous: the fragments really are there.
    assert set(event.observables) >= _PROSE_NAMES, sorted(event.observables)

    # Behavioural, one event: nothing to join on.
    assert references(event) == (), [(r.kind, r.value) for r in references(event)]

    # Behavioural, two events sharing all five fragments: no entity.
    twin = normalize(f"alert from box-7 — {_PROSE_BODY}")
    assert set(twin.observables) >= _PROSE_NAMES
    assert resolve((event, twin)) == (), "verbatim events were joined on something"

    # Positive control: the resolver joins when a TYPED field is shared.
    first = normalize(
        'type=USER_AUTH msg=audit(1760000000.1:1): acct="jones" addr=203.0.113.9 res=failed'
    )
    second = normalize(
        'type=USER_AUTH msg=audit(1760000000.2:1): acct="jones" addr=203.0.113.10 res=failed'
    )
    users = [entity for entity in resolve((first, second)) if entity.kind == "user"]
    assert len(users) == 1 and users[0].key == "jones", [
        (e.kind, e.key) for e in resolve((first, second))
    ]


@pytest.mark.security
def test_correlation_never_reads_observables() -> None:
    """Structural half of the guard above: no name, no attribute, anywhere.

    An AST walk rather than a grep, so a comment mentioning the word does not
    trip it and an access spelled ``getattr(event, "observables")`` does — the
    string constant is checked too. If this goes red, read the test above
    before making it green.
    """
    offenders: list[str] = []
    for path in sorted(Path("correlation").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "observables":
                offenders.append(f"{path}:{node.lineno} attribute")
            elif isinstance(node, ast.Name) and node.id == "observables":
                offenders.append(f"{path}:{node.lineno} name")
            elif isinstance(node, ast.Constant) and node.value == "observables":
                offenders.append(f"{path}:{node.lineno} string constant")
    assert not offenders, (
        "correlation/ reaches for observables; every word.Word fragment a verbatim record "
        f"yields would become a join key — answer AGENTS.md §5's plausibility question "
        f"first: {offenders}"
    )
