# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The egress allow-list's schema and mechanics, without the boundary assertions.

The §5 egress boundary itself — default-deny, every refused address shape, the
authorization basis, "the module that defines the permission cannot egress" — lives
in ``tests/security/test_egress_allowlist.py``, because §6 scopes the independent
Security pass to ``tests/security`` and a boundary assertion filed here would be
invisible to it. What is left over, and belongs here, is the file *schema* and the
small mechanical surface: port bounds, duplicate detection, rendering, ordering.

The one judgement call worth recording: a malformed allow-list is not purely a
schema problem, because an operator whose file will not load has no egress at all.
That half is asserted on the committed file in the security module; what is here is
the shape of the refusals.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from agents.policies.egress import (
    MAX_PORT,
    SUPPORTED_VERSION,
    EgressAllowlist,
    EgressAllowlistError,
    LabHost,
    parse_address,
    parse_port,
)

_BASIS = "lab pair: passive node B pulls node A's health channel; owner approved"


def _write(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "egress.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _host(**overrides: object) -> dict[str, object]:
    return {"address": "127.0.0.1", "port": 9443, "authorization": _BASIS, **overrides}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("payload", "why"),
    [
        ({"hosts": []}, "no version at all"),
        ({"version": 2, "hosts": []}, "a version this loader does not understand"),
        ({"version": "1", "hosts": []}, "a version that is a string"),
        ({"version": 1}, "no hosts key"),
        ({"version": 1, "hosts": {}}, "hosts is not a list"),
        ({"version": 1, "host": []}, "a misspelled hosts key"),
        ({"version": 1, "hosts": [], "extra": True}, "an unknown top-level key"),
        ({"version": 1, "hosts": ["127.0.0.1:9443"]}, "an entry that is not an object"),
    ],
)
def test_the_file_schema_is_refused_rather_than_read_optimistically(
    payload: object, why: str, tmp_path: Path
) -> None:
    """Unknown and missing keys are refused, not defaulted.

    The misspelled-key case is the one with teeth: ``{"version": 1, "host": [...]}``
    would otherwise read as *no* declared hosts and deny everything — fail-closed,
    but silently, leaving the operator certain they had declared a peer. A refusal
    names the key.

    An unknown *version* is refused for the mirror reason: a file written for a later
    schema may mean something narrower than this code would enforce, so reading it
    optimistically is the one direction that can widen a permission by accident.
    """
    with pytest.raises(EgressAllowlistError):
        EgressAllowlist.load(_write(tmp_path, payload))
    assert why  # names the case in a failure


@pytest.mark.unit
def test_an_unknown_entry_key_is_refused(tmp_path: Path) -> None:
    """``adress`` is a typo, and ignoring it leaves the entry without its address."""
    payload = {"version": 1, "hosts": [{"adress": "127.0.0.1", "port": 9443, "authorization": "x"}]}
    with pytest.raises(EgressAllowlistError, match="unknown keys"):
        EgressAllowlist.load(_write(tmp_path, payload))


@pytest.mark.unit
@pytest.mark.parametrize("port", [1, 443, 9443, MAX_PORT])
def test_ports_in_range_are_accepted(port: int) -> None:
    assert parse_port(port) == port


@pytest.mark.unit
@pytest.mark.parametrize("port", [0, -1, MAX_PORT + 1, 10**9])
def test_ports_out_of_range_are_refused(port: int) -> None:
    with pytest.raises(EgressAllowlistError, match="out of range"):
        parse_port(port)


@pytest.mark.unit
@pytest.mark.parametrize("port", [True, False, "443", 443.0, None, [443]])
def test_a_port_that_is_not_an_integer_is_refused(port: object) -> None:
    """``bool`` is refused explicitly: it is an ``int`` subclass, so a JSON ``true``
    would otherwise become port 1 and a ``false`` would be refused only by the range
    check."""
    with pytest.raises(EgressAllowlistError, match="must be an integer"):
        parse_port(port)


@pytest.mark.unit
def test_a_duplicate_destination_is_refused_after_normalization(tmp_path: Path) -> None:
    """``::1`` and ``0:0:0:0:0:0:0:1`` are one entry written twice.

    A list that reads as two destinations and enforces one is a review hazard, and
    the authorization basis that goes unread is the second one. The message names
    both indices, because once parsed the two spellings render identically and
    printing both would print one string twice.
    """
    payload = {
        "version": 1,
        "hosts": [
            _host(address="::1", authorization="first"),
            _host(address="0:0:0:0:0:0:0:1", authorization="second — would go unread"),
        ],
    }
    with pytest.raises(EgressAllowlistError, match=r"hosts\[1\] duplicates hosts\[0\]"):
        EgressAllowlist.load(_write(tmp_path, payload))


@pytest.mark.unit
def test_the_same_address_on_a_different_port_is_not_a_duplicate(tmp_path: Path) -> None:
    """A destination is the pair, so one host on two ports is two destinations."""
    payload = {
        "version": 1,
        "hosts": [_host(address="10.0.0.5", port=9443), _host(address="10.0.0.5", port=9444)],
    }
    allowlist = EgressAllowlist.load(_write(tmp_path, payload))
    assert len(allowlist) == 2
    assert allowlist.permits("10.0.0.5", 9443) and allowlist.permits("10.0.0.5", 9444)
    assert not allowlist.permits("10.0.0.5", 9445)


@pytest.mark.unit
def test_hosts_are_returned_in_file_order() -> None:
    """Order is the reviewer's order, so it is preserved rather than sorted."""
    hosts = [
        LabHost(address=parse_address(address), port=9443, authorization=_BASIS)
        for address in ("10.0.0.9", "10.0.0.1", "10.0.0.5")
    ]
    allowlist = EgressAllowlist(hosts)
    assert [str(host.address) for host in allowlist.hosts] == ["10.0.0.9", "10.0.0.1", "10.0.0.5"]


@pytest.mark.unit
def test_an_ipv6_destination_is_rendered_bracketed() -> None:
    """``[::1]:9443``, because ``::1:9443`` is ambiguous and reads as an address."""
    v6 = LabHost(address=parse_address("::1"), port=9443, authorization=_BASIS)
    v4 = LabHost(address=parse_address("127.0.0.1"), port=9443, authorization=_BASIS)
    assert v6.destination == "[::1]:9443"
    assert v4.destination == "127.0.0.1:9443"


@pytest.mark.unit
def test_a_parsed_address_is_returned_not_a_string() -> None:
    """Callers get the object, so a caller cannot accidentally compare text."""
    assert parse_address("::1") == ipaddress.IPv6Address("::1")
    assert parse_address("0:0:0:0:0:0:0:1") == ipaddress.IPv6Address("::1")
    assert parse_address("127.0.0.1") == ipaddress.IPv4Address("127.0.0.1")
    assert isinstance(parse_address("127.0.0.1"), ipaddress.IPv4Address)


@pytest.mark.unit
def test_a_lab_host_is_frozen() -> None:
    """A declared destination must not be mutable after validation."""
    host = LabHost(address=parse_address("10.0.0.5"), port=9443, authorization=_BASIS)
    with pytest.raises(AttributeError):
        host.port = 9444  # type: ignore[misc]


@pytest.mark.unit
def test_the_supported_version_matches_the_committed_file() -> None:
    """The constant and the shipped file must not drift apart."""
    from agents.policies.egress import DEFAULT_EGRESS_ALLOWLIST_PATH

    data = json.loads(DEFAULT_EGRESS_ALLOWLIST_PATH.read_text(encoding="utf-8"))
    assert data["version"] == SUPPORTED_VERSION
