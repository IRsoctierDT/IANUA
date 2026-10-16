# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""What "lab host" means — a declaration, and the shipped declaration is empty.

AGENTS.md §5 forbids "sending network requests to non-lab hosts" and §5.1 gates
"requests to any non-lab host" — and until this change nothing in the repository
said what a lab host *was*. :mod:`agents.policies.egress` answers it declaratively:
a lab host is one named in the committed allow-list, with an authorization basis
beside it, and nothing else is.

This is a ``tests/security`` module because the property is a §5 boundary: §6.2
requires a security case where one is involved, and §6's role table scopes the
independent Security pass to "the security boundaries (§5) and ``tests/security``".
Putting the egress refusals under ``tests/unit`` would hide them from the one review
pass meant to read them — which review caught on the Scorecard workflow, where
exactly that had happened.

**Every refusal is paired with an acceptance, deliberately.** A check that refuses
everything satisfies every refusal below and is worthless; a check that permits
loopback is one an operator can exercise instead of switching off. So
:func:`test_a_declared_host_is_permitted` and
:func:`test_loopback_and_routable_addresses_are_declarable` are load-bearing, not
decoration.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import socket
from pathlib import Path

import pytest

from agents.policies.egress import (
    DEFAULT_EGRESS_ALLOWLIST_PATH,
    EgressAllowlist,
    EgressAllowlistError,
    EgressDenied,
    LabHost,
    parse_address,
)

_MODULE = Path(__file__).resolve().parents[2] / "agents" / "policies" / "egress.py"

#: A plausible authorization basis, in the shape a real entry would carry.
_BASIS = "lab pair: passive node B pulls node A's health channel; owner approved"

#: The six spellings of the unspecified address, measured with
#: ``ipaddress.ip_address(x).is_unspecified`` — all six are True. The charter
#: amendment's first draft refused the literal string ``"0.0.0.0"``, which is one
#: of them, and ``::`` binds every IPv6 interface.
_UNSPECIFIED = (
    "0.0.0.0",  # noqa: S104 - refused by the control under test, not a bind address
    "::",
    "::0",
    "0:0:0:0:0:0:0:0",
    "0000:0000:0000:0000:0000:0000:0000:0000",
    "::ffff:0.0.0.0",
)

#: Modules that could make this one egress. The module that *defines* the egress
#: permission must never be the module that exercises it.
_BANNED_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncio",
    "subprocess",
    "requests",
}


def _write(tmp_path: Path, payload: object, *, name: str = "egress.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _one_host(address: str = "127.0.0.1", port: int = 9443) -> dict[str, object]:
    return {"address": address, "port": port, "authorization": _BASIS}


# --- the shipped default -------------------------------------------------------


@pytest.mark.security
def test_the_committed_allowlist_is_empty_and_therefore_denies() -> None:
    """The headline: with nothing declared, no destination is a lab host.

    This is the state the charter amendment promises — "a committed host allow-list
    that is **empty by default and therefore denies**". If an operator declares a
    peer in their own fork this test goes red, and that is the control working: an
    edit to the egress allow-list should not pass review unnoticed.
    """
    allowlist = EgressAllowlist.load()
    assert len(allowlist) == 0, (
        f"the committed egress allow-list declares {len(allowlist)} host(s): "
        f"{[host.destination for host in allowlist.hosts]}. Declaring a destination is "
        "a §5.1 external-network decision and needs a recorded human approval"
    )
    for address, port in (("127.0.0.1", 9443), ("10.0.0.5", 443), ("::1", 8443)):
        assert not allowlist.permits(address, port)


@pytest.mark.security
def test_the_committed_allowlist_parses() -> None:
    """A malformed committed file is a fail-closed outage, so it is gated here.

    Everything else in this module proves the loader refuses bad input. This proves
    the *shipped* input is not bad — the one case where a refusal would be a defect
    rather than the control.
    """
    assert DEFAULT_EGRESS_ALLOWLIST_PATH.is_file(), f"{DEFAULT_EGRESS_ALLOWLIST_PATH} is missing"
    data = json.loads(DEFAULT_EGRESS_ALLOWLIST_PATH.read_text(encoding="utf-8"))
    assert data == {"version": 1, "hosts": []}, (
        f"the committed allow-list is not the shipped empty default: {data!r}"
    )


@pytest.mark.security
def test_a_missing_or_malformed_allowlist_refuses_rather_than_permitting(tmp_path: Path) -> None:
    """Fail closed *loudly*: a broken file is not the same as "nothing declared".

    Both outcomes refuse egress, so resolving a missing file to an empty list would
    also be safe. It would also leave an operator believing the file they deleted was
    still being honoured, which is the failure mode that makes a control invisible.
    """
    cases = {
        "absent": tmp_path / "absent.json",
        "not JSON": _write_text(tmp_path, "nope.json", "{"),
        "not an object": _write_text(tmp_path, "array.json", "[]"),
        "empty file": _write_text(tmp_path, "empty.json", ""),
    }
    for label, path in cases.items():
        with pytest.raises(EgressAllowlistError):
            EgressAllowlist.load(path)
        assert label  # names the case in a failure


def _write_text(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.security
def test_one_invalid_entry_rejects_the_whole_file(tmp_path: Path) -> None:
    """Never partially applied — the rule ``bundle.py`` already states and keeps.

    Skipping a bad entry would *narrow* permissions, which is safe in the
    fail-closed sense. It is still wrong: the operator declared two hosts, one was
    dropped, and nothing told them. A refusal names the index.
    """
    path = _write(
        tmp_path,
        {"version": 1, "hosts": [_one_host(), _one_host(address="peer.lab.internal")]},
    )
    with pytest.raises(EgressAllowlistError, match=r"hosts\[1\]"):
        EgressAllowlist.load(path)


@pytest.mark.security
def test_a_file_that_reads_empty_cannot_enforce_a_host(tmp_path: Path) -> None:
    """A duplicate ``hosts`` key would let the file read one way and enforce another.

    Review found this and it defeats the control this module *is*. ``json.loads``
    silently keeps the **last** value for a repeated key, so measured on the version
    before the fix::

        {"hosts": [], "hosts": [<a real host>]}  ->  len=1, ['8.8.8.8:9443']

    The file's first ``hosts`` key is the empty list — which is exactly what the
    shipped default looks like, and exactly what someone skimming for "is this still
    empty?" would see. Every other assertion in this module rests on a reviewer reading
    the committed destination in a diff, so a parse that quietly prefers the key they
    did not read is not a schema nit.

    Asserted here rather than beside the schema cases because the property is
    default-deny, not well-formedness.
    """
    reads_empty = (
        '{"version": 1, "hosts": [], "hosts": [{"address": "8.8.8.8", "port": 9443, '
        f'"authorization": "{_BASIS}"}}]}}'
    )
    path = tmp_path / "egress.json"
    path.write_text(reads_empty, encoding="utf-8")
    with pytest.raises(EgressAllowlistError, match="duplicate key 'hosts'"):
        EgressAllowlist.load(path)

    # And the mirror: the host first, the empty list second. Before the fix this
    # loaded as empty while the file plainly declares a destination — harmless by
    # luck rather than by control, and the refusal covers both orders.
    reads_declared = (
        '{"version": 1, "hosts": [{"address": "8.8.8.8", "port": 9443, '
        f'"authorization": "{_BASIS}"}}], "hosts": []}}'
    )
    path.write_text(reads_declared, encoding="utf-8")
    with pytest.raises(EgressAllowlistError, match="duplicate key 'hosts'"):
        EgressAllowlist.load(path)


@pytest.mark.security
def test_a_duplicate_address_or_basis_within_one_entry_is_refused(tmp_path: Path) -> None:
    """The same mechanism inside an entry: the enforced destination is the unread one.

    Measured before the fix: ``{"address": "10.0.0.5", "address": "8.8.8.8", …}``
    enforced **8.8.8.8** while the first key is where a reader's eye lands, and a
    second ``"authorization"`` replaced a real basis with ``"x"`` — so the §5
    authorization record could be emptied without the diff looking emptied.

    The refusal has to happen at *parse* time: by the time the loader inspects
    ``set(entry)`` the duplicate is already collapsed, so the unknown-key check cannot
    see it.
    """
    for body in (
        '{"version": 1, "hosts": [{"address": "10.0.0.5", "address": "8.8.8.8", '
        f'"port": 9443, "authorization": "{_BASIS}"}}]}}',
        '{"version": 1, "hosts": [{"address": "10.0.0.5", "port": 9443, '
        '"authorization": "owner approved for the lab pair", "authorization": "x"}]}',
    ):
        path = tmp_path / "egress.json"
        path.write_text(body, encoding="utf-8")
        with pytest.raises(EgressAllowlistError, match="duplicate key"):
            EgressAllowlist.load(path)


# --- what cannot be declared ---------------------------------------------------


@pytest.mark.security
def test_a_hostname_cannot_be_declared(tmp_path: Path) -> None:
    """Only IP literals: a name is resolved at connect time, by someone else.

    If the allow-list could hold ``peer.lab.internal`` then it names a *name* while
    the socket goes wherever resolution answers — the SSRF and rebinding class §6.1
    ranks first, plus a time-of-check/time-of-use gap. It is ``collect/``'s
    absolute-paths-only rule with one word changed: a relative path means whatever
    the working directory happens to be; a hostname means whatever the resolver
    happens to say.
    """
    for name in ("peer.lab.internal", "localhost", "node-a", "example.com", ""):
        path = _write(tmp_path, {"version": 1, "hosts": [_one_host(address=name)]})
        with pytest.raises(EgressAllowlistError, match="not an IP literal"):
            EgressAllowlist.load(path)


@pytest.mark.security
@pytest.mark.parametrize("spelling", _UNSPECIFIED, ids=_UNSPECIFIED)
def test_every_spelling_of_unspecified_is_refused(spelling: str, tmp_path: Path) -> None:
    """Six spellings, and a literal-string rule catches one of them.

    This is the finding review raised against the charter amendment, asserted as
    code so it cannot regress into prose again. The refusal reads the **parsed**
    value's ``is_unspecified``, which is why all six fail rather than only the one
    anybody thinks to type.
    """
    assert ipaddress.ip_address(spelling).is_unspecified, (
        f"{spelling} is not actually unspecified — this test's premise is wrong"
    )
    path = _write(tmp_path, {"version": 1, "hosts": [_one_host(address=spelling)]})
    with pytest.raises(EgressAllowlistError, match="unspecified"):
        EgressAllowlist.load(path)


@pytest.mark.security
@pytest.mark.parametrize(
    ("address", "why"),
    [
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("255.255.255.255", "limited-broadcast"),
        ("169.254.169.254", "link-local"),
        ("fe80::1", "link-local"),
        ("::ffff:169.254.169.254", "link-local"),
        ("::ffff:127.0.0.1", "IPv4-mapped"),
        ("::1%eth0", "scope ID"),
    ],
)
def test_shapes_that_cannot_mean_one_peer_are_refused(
    address: str, why: str, tmp_path: Path
) -> None:
    """Each refusal has its own reason, and none is "it looks public".

    Multicast and broadcast reach more than one host, so "a single declared peer" is
    contradicted by construction. ``169.254.169.254`` is the cloud instance-metadata
    address and the canonical SSRF target. The mapped and scoped forms *alias*:
    measured, ``::ffff:127.0.0.1 != 127.0.0.1`` and ``fe80::1%2 != fe80::1``, so
    allowing them would let a declared host silently not match itself.

    Note what a *positive* shape test would do here: measured, ``224.0.0.1`` is
    ``is_multicast`` **and** ``is_global``, so a rule phrased "allow if global"
    would allow multicast. The rules are refusals for that reason.
    """
    path = _write(tmp_path, {"version": 1, "hosts": [_one_host(address=address)]})
    with pytest.raises(EgressAllowlistError):
        EgressAllowlist.load(path)
    assert why  # names the case in a failure


@pytest.mark.security
def test_a_non_string_address_is_refused(tmp_path: Path) -> None:
    """``ip_address`` accepts integers, and JSON carries integers.

    Measured: ``ip_address(2130706433)`` is ``127.0.0.1``, ``ip_address(0)`` is
    ``0.0.0.0``, and because ``bool`` is an ``int`` subclass ``ip_address(True)`` is
    ``0.0.0.1``. So ``{"address": 3232235777}`` would otherwise load as
    ``192.168.1.1`` — a declared destination no reviewer can see in a diff.
    """
    values: tuple[object, ...] = (2130706433, 0, 1, True, None, 3232235777, 1.0, [], {})
    for value in values:
        path = _write(tmp_path, {"version": 1, "hosts": [{**_one_host(), "address": value}]})
        with pytest.raises(EgressAllowlistError, match="must be a string"):
            EgressAllowlist.load(path)


@pytest.mark.security
def test_an_entry_without_an_authorization_basis_is_refused(tmp_path: Path) -> None:
    """§5 says "document the authorization basis". This makes that mechanical.

    A destination without a stated reason is a destination whose approval nobody can
    reconstruct at review time, which is the whole point of a *committed* list.
    """
    for payload in ({"address": "127.0.0.1", "port": 9443}, {**_one_host(), "authorization": "  "}):
        path = _write(tmp_path, {"version": 1, "hosts": [payload]})
        with pytest.raises(EgressAllowlistError):
            EgressAllowlist.load(path)


# --- the control direction -----------------------------------------------------


@pytest.mark.security
def test_a_declared_host_is_permitted(tmp_path: Path) -> None:
    """The gate can also say yes — without this, every refusal above is vacuous."""
    path = _write(tmp_path, {"version": 1, "hosts": [_one_host("10.0.0.5", 9443)]})
    allowlist = EgressAllowlist.load(path)

    assert len(allowlist) == 1
    assert allowlist.permits("10.0.0.5", 9443)
    assert allowlist.require("10.0.0.5", 9443).authorization == _BASIS
    # And only that destination.
    assert not allowlist.permits("10.0.0.6", 9443), "a neighbouring address was permitted"
    assert not allowlist.permits("10.0.0.5", 9444), "a neighbouring port was permitted"


@pytest.mark.security
def test_loopback_and_routable_addresses_are_declarable(tmp_path: Path) -> None:
    """Loopback must work, and a routable address must be allowed to be declared.

    Loopback: a single-box lab and this repository's own tests need it, and a control
    that cannot be exercised is one an operator turns off rather than uses.

    Routable: the definition is *declarative*, not shape-based. A lab VM with a
    public address is still a lab host, so refusing ``is_global`` would contradict
    the definition this module exists to state. What makes it reviewable is the
    ``authorization`` field, not the address class.
    """
    for address in ("127.0.0.1", "::1", "10.0.0.5", "192.0.2.1", "198.51.100.7", "fd00::1"):
        path = _write(tmp_path, {"version": 1, "hosts": [_one_host(address=address)]})
        allowlist = EgressAllowlist.load(path)
        assert allowlist.permits(address, 9443), f"{address} was declared and is not permitted"


@pytest.mark.security
def test_membership_compares_the_parsed_address_not_the_string(tmp_path: Path) -> None:
    """One host, several spellings — the whole lesson of the ``0.0.0.0`` finding.

    ``::1`` and ``0:0:0:0:0:0:0:1`` are the same host written two ways: equal as
    parsed objects, unequal as text. A string comparison here would deny a declared
    peer because the operator expanded the zeros, and a future reader would "fix" it
    by loosening the match.
    """
    path = _write(tmp_path, {"version": 1, "hosts": [_one_host(address="::1")]})
    allowlist = EgressAllowlist.load(path)
    for spelling in ("::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001"):
        assert allowlist.permits(spelling, 9443), f"{spelling} is ::1 and was denied"
        assert allowlist.require(spelling, 9443).address == ipaddress.ip_address("::1")


@pytest.mark.security
def test_permits_answers_false_where_require_explains(tmp_path: Path) -> None:
    """A predicate must not hand its caller an exception in place of an answer.

    ``permits`` is for a health summary or a test; ``require`` is for the path an
    operator reads. Both deny, and only one of them raises.
    """
    allowlist = EgressAllowlist.load(
        _write(tmp_path, {"version": 1, "hosts": [_one_host("10.0.0.5")]})
    )
    unusable: tuple[object, ...] = ("peer.lab.internal", "0.0.0.0", 2130706433)  # noqa: S104
    for address in unusable:
        assert allowlist.permits(address, 9443) is False
        with pytest.raises(EgressDenied):
            allowlist.require(address, 9443)


@pytest.mark.security
def test_an_empty_allowlist_says_so_rather_than_only_denying() -> None:
    """Denied and "nothing is declared yet" are different operator problems.

    The empty list is the shipped state, so the message an operator meets first
    should distinguish "you have declared nothing" from "that is not the host you
    declared".
    """
    with pytest.raises(EgressDenied, match="no hosts are declared"):
        EgressAllowlist().require("10.0.0.5", 9443)


# --- the refusals cannot be bypassed ------------------------------------------


@pytest.mark.security
def test_direct_construction_is_validated_too() -> None:
    """A caller building a ``LabHost`` in code gets the committed file's refusals.

    Validation that lives only in the loader is validation a future caller routes
    around without noticing — so :class:`LabHost` re-checks in ``__post_init__`` and
    :class:`EgressAllowlist` refuses anything that is not one.
    """
    with pytest.raises(EgressAllowlistError):
        LabHost(address=ipaddress.ip_address("0.0.0.0"), port=9443, authorization=_BASIS)  # noqa: S104
    with pytest.raises(EgressAllowlistError):
        LabHost(address=ipaddress.ip_address("224.0.0.1"), port=9443, authorization=_BASIS)
    with pytest.raises(EgressAllowlistError):
        LabHost(address=parse_address("127.0.0.1"), port=9443, authorization="")
    with pytest.raises(EgressAllowlistError):
        LabHost(address=parse_address("127.0.0.1"), port=0, authorization=_BASIS)
    with pytest.raises(EgressAllowlistError, match="not a LabHost"):
        EgressAllowlist(["127.0.0.1:9443"])  # type: ignore[list-item]


@pytest.mark.security
def test_the_module_that_defines_the_permission_imports_no_network_module() -> None:
    """The definition of the boundary must not also be a way across it.

    ``agents/policies/egress.py`` answers "is this destination declared?" and must
    never open a socket to find out. Asserted on the import graph rather than by
    docstring, in the idiom ``tests/security/test_response_no_executor.py`` already
    uses for the containment boundary.

    This is the weaker half of the pair, and it is named that way on purpose: an AST
    walk over one file says nothing about what its imports import.
    :func:`test_loading_and_checking_the_allowlist_opens_no_socket` is the half with
    teeth.
    """
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"), filename=str(_MODULE))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in _BANNED_MODULES, f"egress.py imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in _BANNED_MODULES, f"egress.py imports from {node.module}"


@pytest.mark.security
def test_loading_and_checking_the_allowlist_opens_no_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Runtime proof, not an import-graph argument — the stronger of the pair.

    The AST check above covers one file's own imports and is blind to anything they
    pull in transitively. This denies ``socket.socket`` outright and then exercises
    the whole surface: load the committed file, load one with a declared host, and
    run both the permit and the refuse paths. Nothing here may resolve a name or open
    a connection, and in particular ``permits`` must never be tempted to resolve a
    hostname in order to compare it — the refusal is the point.

    Borrowed from ``tests/security/test_intel_no_egress.py``, which makes the same
    claim about ``intel/`` the same way.
    """
    calls: list[object] = []

    def _deny(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise OSError("socket use is banned in agents/policies/egress.py")

    monkeypatch.setattr(socket, "socket", _deny)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)
    monkeypatch.setattr(socket, "gethostbyname", _deny)

    assert len(EgressAllowlist.load()) == 0
    declared = EgressAllowlist.load(_write(tmp_path, {"version": 1, "hosts": [_one_host()]}))
    assert declared.permits("127.0.0.1", 9443)
    assert declared.require("127.0.0.1", 9443).destination == "127.0.0.1:9443"
    assert not declared.permits("peer.lab.internal", 9443)
    assert not declared.permits("10.0.0.5", 9443)
    with pytest.raises(EgressDenied):
        declared.require("peer.lab.internal", 9443)
    assert calls == [], f"the allow-list reached the network: {calls}"
