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
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from correlation import Thresholds, assemble, references, resolve
from ingest.schema import MAX_FIELD_LEN
from store.events import StoredEvent

from ingest import normalize

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
