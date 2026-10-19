# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""What "lab host" means: a destination an operator declared, and nothing else.

AGENTS.md §5 prohibits "sending network requests to non-lab hosts" and §5.1 gates
"requests to any non-lab host" on human approval with the URL shown in full. Neither
said what makes a host a *lab* host, so the term the whole egress permission turns on
was undefined — and an undefined term in a prohibition is enforced by whoever happens
to be reading it that day.

**No property of an address answers it.** RFC1918 is not a proxy for "lab": a
corporate LAN and a cloud VPC are both private and neither is one. A routable address
is not a disqualifier: a lab VM with a public address is still yours. Reverse DNS is
whatever the other side's operator says it is. So the term can only be *declarative*,
and this module is that declaration — a lab host is one named in the committed
allow-list (:data:`DEFAULT_EGRESS_ALLOWLIST_PATH`), with the authorization basis §5
already demands recorded beside it. Everything else is not a lab host.

That is the control ``collect/`` uses for log sources, and the reasoning transfers
without change: **declared, never discovered.** The list ships **empty**, so the
default answer to "may this node reach that?" is no, and it is no because nothing has
been declared rather than because a rule happened to match.

**Nothing calls this yet, deliberately.** The stage 7 amendment records the build
order — allow-list, then the listener, then the puller — so that no egress code can
be written against a permissive default. What this module answers is one question
(is this destination declared?) and the answer today is always no.

Fails closed throughout: a missing, unreadable, malformed or schema-invalid
allow-list raises :class:`EgressAllowlistError` rather than resolving to "empty, so
deny". Both outcomes refuse egress, but one of them tells the operator their file is
broken instead of silently behaving as though they had declared nothing.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The committed allow-list, shipped empty. Lives beside ``policy.json`` because it
#: is policy: ``policy.json``'s ``allow`` list names the *action* that may egress,
#: this file names the *destination*, and neither alone is sufficient.
DEFAULT_EGRESS_ALLOWLIST_PATH = Path(__file__).with_name("egress.json")

#: The schema version this loader understands. An unknown version is refused rather
#: than read optimistically — a file written for a later schema may mean something
#: narrower than this code would enforce.
SUPPORTED_VERSION = 1

#: Highest valid TCP/UDP port. There is no default port anywhere in this module: the
#: listener binds a declared address *and* port, so a destination is the pair, and a
#: default would be a destination nobody wrote down.
MAX_PORT = 65535

#: The IPv4 limited-broadcast address, refused explicitly below. ``ip_address``
#: exposes no ``is_broadcast``, and ``is_reserved`` cannot stand in for one:
#: measured, ``ipaddress.ip_address("::1").is_reserved`` is **True**, so refusing
#: everything reserved would refuse IPv6 loopback and make a single-box lab
#: undeclarable.
_IPV4_BROADCAST = ipaddress.IPv4Address("255.255.255.255")

_AddressType = ipaddress.IPv4Address | ipaddress.IPv6Address


class EgressAllowlistError(ValueError):
    """Raised when the allow-list is missing, unreadable, or schema-invalid."""


class EgressDenied(ValueError):
    """Raised by :meth:`EgressAllowlist.require` for an undeclared destination."""


def parse_address(value: Any) -> _AddressType:
    """Parse one declared or candidate address, refusing shapes that cannot mean a peer.

    Returns the parsed :class:`~ipaddress.IPv4Address` or
    :class:`~ipaddress.IPv6Address`. Raises :class:`EgressAllowlistError` with a
    reason for anything refused. Every refusal below was measured against
    :mod:`ipaddress` rather than assumed, because the first version of the charter
    amendment refused the *string* ``"0.0.0.0"`` and review found five other
    spellings of it.

    Refused, each for its own reason:

    * **Anything that is not a ``str``.** ``ip_address`` accepts an integer, and
      JSON carries integers: measured, ``ip_address(2130706433)`` is
      ``127.0.0.1``, ``ip_address(0)`` is ``0.0.0.0``, and — because ``bool`` is an
      ``int`` subclass — ``ip_address(True)`` is ``0.0.0.1``. So ``{"address": 0}``
      would parse. It would then hit the unspecified refusal, but
      ``{"address": 3232235777}`` is ``192.168.1.1`` and would pass everything
      while being unreviewable: no one reads that integer in a diff and sees a host.
    * **A hostname.** Only IP literals are accepted. A name is resolved at connect
      time, so the committed file would name a name while the socket goes wherever
      resolution says — the SSRF and rebinding class §6.1 ranks first, and a
      time-of-check/time-of-use gap besides. This is ``collect/``'s
      absolute-paths-only rule with one word changed: a relative path means whatever
      the working directory happens to be, and a hostname means whatever the
      resolver happens to answer. The cost is real and is the trade — an operator
      whose peer moves edits a committed file and has the change reviewed, which is
      the control working rather than failing.
    * **Unspecified, in either family.** Measured, six spellings are unspecified and
      a literal rule catches one: ``0.0.0.0``, ``::``, ``::0``,
      ``0:0:0:0:0:0:0:0``, the fully expanded ``0000:…:0000``, and the IPv4-mapped
      ``::ffff:0.0.0.0``. As a *destination* it is also not a host — on Linux a
      connect to ``0.0.0.0`` reaches loopback, so it reads as "nowhere" and means
      "here".
    * **Multicast.** One send reaches every subscriber, which contradicts "a single
      host" by construction. Note that a positive shape test would not catch it:
      measured, ``224.0.0.1`` is ``is_multicast`` *and* ``is_global``, so a rule
      phrased "allow if global" would allow it. The rules here are refusals.
    * **Limited broadcast.** Same reason as multicast, checked explicitly — see
      :data:`_IPV4_BROADCAST`.
    * **Link-local.** ``169.254.169.254`` is the cloud instance-metadata address and
      the canonical SSRF target; ``fe80::/10`` is its IPv6 counterpart. Neither is
      ever a declared peer, and the mapped form ``::ffff:169.254.169.254`` is
      link-local too (measured), so this catches that spelling as well.
    * **An IPv4-mapped IPv6 address.** It aliases: measured,
      ``ip_address("::ffff:127.0.0.1") == ip_address("127.0.0.1")`` is **False**,
      and the two have different versions. Allowing both spellings would mean a
      declared host silently not matching the same host written the other way.
      Write the native form.
    * **A scope ID.** ``ip_address("::1%eth0")`` parses, and measured,
      ``ip_address("fe80::1%2") == ip_address("fe80::1")`` is **False** with
      unequal hashes. A scoped entry would therefore refuse the same address
      written without the scope, which is a confusing non-match rather than a
      control.

    **Loopback is deliberately allowed.** A single-box lab and this repository's own
    tests need it, and a control that cannot be exercised is one an operator turns
    off. A routable address is allowed too, because the definition above is
    declarative and not shape-based — what makes it reviewable is the
    ``authorization`` field, not the address class.
    """
    if not isinstance(value, str):
        raise EgressAllowlistError(
            f"address must be a string, not {type(value).__name__}: {value!r} — "
            "ipaddress.ip_address() accepts integers (2130706433 is 127.0.0.1, and "
            "bool is an int subclass, so True is 0.0.0.1), and an integer address "
            "cannot be reviewed in a diff"
        )
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EgressAllowlistError(
            f"not an IP literal: {value!r} ({exc}). Hostnames are refused: a name is "
            "resolved at connect time, so the allow-list would name a name while the "
            "socket goes wherever resolution says. Declare the address"
        ) from exc

    # Classified by the IPv4 address an IPv4-mapped form carries, because the
    # stdlib's answer for the mapped form depends on the interpreter. Measured:
    # ip_address("::ffff:0.0.0.0").is_unspecified is True on 3.11.17 and 3.13.16
    # and False on 3.12.3 (Ubuntu 24.04's system Python), and so are is_loopback,
    # is_link_local and is_multicast for their mapped forms. Every mapped form is
    # refused below whichever way, but the reason an operator reads should not
    # depend on the Python that happened to load the file.
    native = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    classified = native if native is not None else address
    if classified.is_unspecified:
        raise EgressAllowlistError(
            f"refused: {value!r} parses as the unspecified address ({address}), which "
            "is not a host — on Linux a connect to it reaches loopback"
        )
    if classified.is_multicast:
        raise EgressAllowlistError(
            f"refused: {value!r} is multicast, so one send reaches every subscriber "
            "rather than the single declared peer"
        )
    if classified == _IPV4_BROADCAST:
        raise EgressAllowlistError(
            f"refused: {value!r} is the limited-broadcast address, not a single host"
        )
    if classified.is_link_local:
        raise EgressAllowlistError(
            f"refused: {value!r} is link-local. 169.254.169.254 is the cloud "
            "instance-metadata address and fe80::/10 is its IPv6 counterpart; "
            "neither is ever a declared peer"
        )
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            raise EgressAllowlistError(
                f"refused: {value!r} is an IPv4-mapped IPv6 address, which does not "
                f"compare equal to {address.ipv4_mapped} — declare the native form"
            )
        if address.scope_id is not None:
            raise EgressAllowlistError(
                f"refused: {value!r} carries a scope ID, which changes equality — "
                "a scoped entry would not match the same address written without it"
            )
    return address


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads`` object hook that refuses a repeated key instead of taking the last.

    Review found this, and it defeats the control this module *is*. ``json.loads``
    silently keeps the last value for a duplicate name, so without this hook a
    committed file could read one way and enforce another — and the whole claim here is
    that a reviewer sees the destination in a diff.

    Measured on the version without the hook, which is why this is a parse-time refusal
    and not a later check:

    * ``{"address": "10.0.0.5", "address": "8.8.8.8", ...}`` loaded and enforced
      **8.8.8.8**, while the first key is what a reader's eye lands on.
    * A second ``"authorization"`` replaced a real basis with ``"x"``.
    * Worst, and the reason this is not cosmetic:
      ``{"hosts": [], "hosts": [<a real host>]}`` loaded as **one declared host** while
      the file's first ``hosts`` key is the empty list — which is exactly what the
      shipped default looks like, and exactly what someone skimming for "is this still
      empty?" would see.

    It also has to be a *parse* hook rather than a key check afterwards: by the time
    :meth:`EgressAllowlist.load` inspects ``set(entry)``, the duplicate is already
    collapsed and the unknown-key check below cannot see it.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise EgressAllowlistError(
                f"duplicate key {key!r} in the egress allow-list. JSON keeps the last "
                "value silently, so the file would read one way and enforce another — "
                "and a reviewer reading the committed diff is this control"
            )
        seen.add(key)
    return dict(pairs)


def parse_port(value: Any) -> int:
    """Parse one declared or candidate port, refusing anything that is not 1..65535.

    ``bool`` is refused explicitly despite being an ``int`` subclass, so a JSON
    ``true`` cannot become port 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise EgressAllowlistError(
            f"port must be an integer, not {type(value).__name__}: {value!r}"
        )
    if not 1 <= value <= MAX_PORT:
        raise EgressAllowlistError(f"port out of range 1..{MAX_PORT}: {value!r}")
    return value


@dataclass(frozen=True)
class LabHost:
    """One declared destination: a parsed address, a port, and why it is authorized.

    Validated in :meth:`__post_init__` rather than only in the loader, so there is no
    construction path that produces a ``LabHost`` the allow-list would have refused —
    a caller building one directly gets the same refusals a committed entry does.
    """

    address: _AddressType
    port: int
    authorization: str

    def __post_init__(self) -> None:
        # Re-run the address refusals against the already-parsed value. Rendering it
        # back to a string is not a round-trip hazard: every refusal below reads a
        # property of the parsed object, and `str(address)` of a parsed address is
        # always a form `ip_address` accepts.
        parse_address(str(self.address))
        parse_port(self.port)
        if not isinstance(self.authorization, str) or not self.authorization.strip():
            raise EgressAllowlistError(
                f"{self.address}:{self.port} has no authorization basis. AGENTS.md §5 "
                "requires one to be documented; recording it in the entry is what "
                "makes the committed diff reviewable"
            )

    @property
    def destination(self) -> str:
        """``address:port`` for a message, with IPv6 bracketed."""
        if isinstance(self.address, ipaddress.IPv6Address):
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


class EgressAllowlist:
    """The committed set of declared lab hosts. Empty means every destination is denied.

    Comparison is on the **parsed** address and the integer port, never on strings,
    which is the whole lesson of the ``0.0.0.0`` finding: ``::1`` and
    ``0:0:0:0:0:0:0:1`` are one host spelled two ways and compare equal as objects
    while comparing unequal as text.
    """

    def __init__(self, hosts: Iterable[LabHost] = ()) -> None:
        declared = tuple(hosts)
        seen: dict[tuple[_AddressType, int], int] = {}
        for index, host in enumerate(declared):
            if not isinstance(host, LabHost):
                raise EgressAllowlistError(
                    f"not a LabHost: {host!r} — the allow-list holds validated entries"
                )
            key = (host.address, host.port)
            if key in seen:
                # Duplicates are refused *after* normalization, because `::1` and
                # `0:0:0:0:0:0:0:1` are one entry written twice: a list that reads
                # as two destinations and enforces one is a review hazard, and the
                # second authorization basis would be the one nobody notices. The
                # earlier index is named because the two spellings render the same
                # once parsed, so printing both would print one string twice.
                raise EgressAllowlistError(
                    f"hosts[{index}] duplicates hosts[{seen[key]}]: both are "
                    f"{host.destination}. Two spellings of one address are one entry, "
                    "and the second authorization basis would go unread"
                )
            seen[key] = index
        self._hosts = declared

    @classmethod
    def load(cls, path: Path | str = DEFAULT_EGRESS_ALLOWLIST_PATH) -> EgressAllowlist:
        """Load the committed allow-list (fail-closed; never partially applied).

        Raises :class:`EgressAllowlistError` on a missing, unreadable or malformed
        file, an unknown schema version, or any invalid entry. One bad entry rejects
        the whole file: skipping it would narrow permissions silently, which is safe
        but leaves an operator believing they declared something they did not.
        """
        allowlist_path = Path(path)
        try:
            raw = allowlist_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise EgressAllowlistError(
                f"egress allow-list not readable: {allowlist_path} ({exc}) — refusing "
                "rather than treating it as empty, so a broken file is visible"
            ) from exc
        try:
            data: Any = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise EgressAllowlistError(
                f"egress allow-list is not valid JSON: {allowlist_path} ({exc})"
            ) from exc
        if not isinstance(data, dict):
            raise EgressAllowlistError("egress allow-list must be a JSON object")
        unknown_top = sorted(set(data) - {"version", "hosts"})
        if unknown_top:
            raise EgressAllowlistError(
                f"egress allow-list has unknown keys: {unknown_top} — refused rather "
                "than ignored, because a misspelled 'hosts' would read as an empty "
                "list and deny everything while looking declared"
            )
        version = data.get("version")
        # The type check is not pedantry and review found it missing: `bool` is an
        # `int` subclass, so `True == 1` and a bare equality accepted
        # `{"version": true}` as schema version 1 — measured. `1.0 == 1` too. This is
        # the *third* place in this module that needs the guard (`parse_address` for
        # the same reason, `parse_port` for the same reason), and the one place it was
        # written twice and then omitted.
        if isinstance(version, bool) or not isinstance(version, int):
            raise EgressAllowlistError(
                f"egress allow-list version must be an integer, not "
                f"{type(version).__name__}: {version!r} — note that bool is an int "
                "subclass, so `true` would otherwise compare equal to version 1"
            )
        if version != SUPPORTED_VERSION:
            raise EgressAllowlistError(
                f"unsupported egress allow-list version {version!r} "
                f"(this loader understands {SUPPORTED_VERSION})"
            )
        if "hosts" not in data:
            # Required, not defaulted to empty: a file that declares a version and
            # nothing else is malformed, and `"hosts": []` says "deliberately none".
            raise EgressAllowlistError("egress allow-list is missing 'hosts'")
        entries = data["hosts"]
        if not isinstance(entries, list):
            raise EgressAllowlistError("'hosts' must be a list")

        hosts: list[LabHost] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise EgressAllowlistError(f"hosts[{index}] must be an object")
            unknown = sorted(set(entry) - {"address", "port", "authorization"})
            if unknown:
                # An unknown key is refused, not ignored: it is most likely a
                # misspelled one, and a silently-ignored `adress` would leave the
                # entry without the field it meant to set.
                raise EgressAllowlistError(f"hosts[{index}] has unknown keys: {unknown}")
            missing = sorted({"address", "port", "authorization"} - set(entry))
            if missing:
                raise EgressAllowlistError(f"hosts[{index}] is missing {missing}")
            try:
                hosts.append(
                    LabHost(
                        address=parse_address(entry["address"]),
                        port=parse_port(entry["port"]),
                        authorization=entry["authorization"],
                    )
                )
            except EgressAllowlistError as exc:
                raise EgressAllowlistError(f"hosts[{index}]: {exc}") from exc
        return cls(hosts)

    @property
    def hosts(self) -> tuple[LabHost, ...]:
        """The declared destinations, in file order."""
        return self._hosts

    def __len__(self) -> int:
        return len(self._hosts)

    def permits(self, address: Any, port: Any) -> bool:
        """Is ``address:port`` a declared lab host?

        Returns ``False`` for an undeclared destination *and* for one this module
        would refuse outright (an unparseable string, a hostname, an integer), so a
        caller asking the question cannot be handed an exception in place of an
        answer. :meth:`require` is the variant that explains itself; use that where
        an operator will read the result.
        """
        try:
            candidate = (parse_address(address), parse_port(port))
        except EgressAllowlistError:
            return False
        return any((host.address, host.port) == candidate for host in self._hosts)

    def require(self, address: Any, port: Any) -> LabHost:
        """Return the declared :class:`LabHost` for ``address:port``, or refuse.

        Raises :class:`EgressDenied` naming what was asked for and which hosts are
        declared, because "denied" and "nothing is declared yet" are different
        operator problems and the empty list is the shipped state.

        **The message names declared destinations, so it is operator-facing only.**
        §5 treats internal hostnames and IPs as sensitive by default. An operator at a
        CLI learns nothing from it that is not already in a committed file they can
        read, which is why it is written this way — a refusal that will not say what
        *is* declared sends them hunting. A **remote** caller is the other case
        entirely: this text must never reach a network response or any record a peer
        can read, since it would disclose the lab topology to exactly the party the
        allow-list exists to constrain. The listener and the puller this module is
        built for therefore render their own refusal, and do not forward this one.
        """
        try:
            candidate = (parse_address(address), parse_port(port))
        except EgressAllowlistError as exc:
            raise EgressDenied(f"not a usable destination: {exc}") from exc
        for host in self._hosts:
            if (host.address, host.port) == candidate:
                return host
        declared = (
            "no hosts are declared, so every destination is denied"
            if not self._hosts
            else f"declared: {', '.join(host.destination for host in self._hosts)}"
        )
        raise EgressDenied(
            f"{candidate[0]}:{candidate[1]} is not a declared lab host — {declared}. "
            "A lab host is one named in the committed egress allow-list (AGENTS.md §5)"
        )
