# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Entity resolution across telemetry domains — recognize, never guess.

The canonical event carries whatever each source happened to know. A
CloudTrail record names ``svc-deploy``; an Entra sign-in for the same actor
names ``svc-deploy@corp.example``; a Sysmon event names a SID. Nothing above
can ask "what else did this actor do" until those are known to be one actor.

This module does that, and the governing rule is the one ``ingest/`` already
set: **a mis-attribution is worse than an honest non-match.** Two references
merge only on a declared, exact rule. There is no fuzzy matching, no edit
distance, and no similarity threshold — a wrongly merged identity produces a
confident incident about the wrong person, which is the failure mode that
destroys trust in a SOC faster than a missed link.

Three decisions worth stating, because each rejects something a naive
implementation would do:

* **An address is not a host.** DHCP and NAT reuse addresses, so
  ``10.0.0.5`` identifies a host only at a moment in time. ``device.ip`` is
  therefore resolved as an *address* entity, never merged into the host
  entity, and the two link events independently.
* **Host-local identifiers never join across events.** POSIX uid ``0`` is
  root on every Linux host, and ``S-1-5-18`` is LocalSystem on every Windows
  one. Treating those as globally unique would merge every machine's system
  account into one entity — so a numeric uid or a well-known SID is kept as
  an alias for provenance but is never used as a join key.
* **Identifiers and names are linked by co-occurrence, not by resemblance.**
  A uid and a username are known to be the same actor because one event
  carried both, not because they look alike. Hence the intra-event merge
  below; across events, only exact normalized equality (plus the one
  user-principal rule) joins.

No clock, no filesystem, no network, no subprocess — asserted over this
package's AST in ``tests/security/test_correlation_hardening.py``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from ingest.schema import MAX_FIELD_LEN, NormalizedEvent

#: The entity kinds this layer resolves. Deliberately three: the pivots an
#: analyst actually follows. A process is not here — a process identity is
#: meaningful only within a host and a time window, and inventing a global one
#: would be exactly the over-merge this module exists to avoid.
EntityKind = Literal["user", "host", "address"]

ENTITY_KINDS: tuple[EntityKind, ...] = ("user", "host", "address")

#: Kinds whose references *within a single event* describe one thing, and may
#: therefore be merged on co-occurrence.
#:
#: ``user`` and ``host`` qualify: the canonical schema's ``actor`` group
#: describes one actor and ``device`` one device, so their fields co-refer —
#: this is what links a uid to a username.
#:
#: ``address`` emphatically does not. ``src_endpoint`` and ``dst_endpoint`` are
#: deliberately the two *ends* of one connection. Merging them would make every
#: source address identical to its destination and then, transitively, collapse
#: every address in a window into a single entity — which is not a subtle
#: failure: one shared gateway turns the whole window into one meaningless
#: "incident".
_CO_REFERRING_KINDS: tuple[EntityKind, ...] = ("user", "host")

#: Values that are structurally present but identify nothing. Joining on these
#: would link every host that ever logged a placeholder. Same spirit as
#: ``intel/never_flag.json``: a small, committed, reviewable deny set.
NEVER_JOIN = frozenset(
    {
        "",
        "-",
        "n/a",
        "na",
        "null",
        "none",
        "nil",
        "unknown",
        # auditd writes "?" for a field it has no value for, and every
        # pre-authentication sshd record carries `hostname=?` and
        # `terminal=?`. Collecting audit.log therefore produces a stream of
        # events all sharing that "host", which would merge unrelated hosts'
        # authentication activity into one entity. Reachable only once the
        # nested `msg=` payload was extracted, which is why it arrives with
        # that fix rather than before it.
        "?",
        "(none)",
        "localhost",
        "localhost.localdomain",
        # Every loopback *name* a default /etc/hosts gives 127.0.0.1 or ::1:
        # Debian's `ip6-localhost ip6-loopback`, and Red Hat's
        # `localhost4 localhost4.localdomain4` and
        # `localhost6 localhost6.localdomain6`. Measured through the auditd
        # parser: `node=ip6-localhost`, and later `node=localhost4` (the
        # IPv4 line of the same file, missed the first time), each linked
        # two unrelated records. Not here: Debian's `ip6-allnodes`,
        # `ip6-allrouters`, `ip6-localnet`, `ip6-mcastprefix` — multicast
        # and prefix names, deferred with multicast (_address_literal).
        "localhost4",
        "localhost4.localdomain4",
        "localhost6",
        "localhost6.localdomain6",
        "ip6-localhost",
        "ip6-loopback",
        "127.0.0.1",
        "::1",
        # Suppression justified: this literal is a value being REFUSED as an
        # identifier, not an address being bound. The rule reads it as a host.
        "0.0.0.0",  # noqa: S104  # nosec B104
        "::",
        "*",
        "system",
    }
)

#: Well-known SIDs that name a built-in principal on *every* Windows host, so
#: they cannot identify one actor across machines. Prefix-matched, because the
#: well-known range is a prefix family (``S-1-5-18``, ``S-1-5-19``, …) while a
#: real domain account is ``S-1-5-21-<domain>-<rid>``.
#: Account names that exist on essentially every host of their platform, so
#: they name a *role*, not an actor. Joining on them would merge every
#: machine's administrative account into one entity — and then every event on
#: every host into one incident. The conservative direction is deliberate: a
#: missed link costs an analyst a query, while a false merge produces a
#: confident incident about the wrong principal.
#:
#: Qualifying these by their host (``root@web-01``) would recover the link
#: safely and is the obvious refinement; it needs host resolution to have
#: already run, so it is noted in correlation/README.md rather than built here.
HOST_LOCAL_PRINCIPALS = frozenset(
    {
        "root",
        "administrator",
        "admin",
        "guest",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sshd",
        "www-data",
        "localsystem",
        "networkservice",
        "localservice",
        "trustedinstaller",
    }
)

_WELL_KNOWN_SID_PREFIXES = ("s-1-0", "s-1-1", "s-1-2", "s-1-3", "s-1-5-18", "s-1-5-19", "s-1-5-20")

#: Vendors (as each parser stamps ``vendor``) whose parser fills
#: ``device.hostname`` from a field that names no host. No check on the value
#: can refuse these, because the values are well-formed hostnames: CloudTrail
#: has no hostname field and its parser maps ``userAgent`` there, so a
#: service-initiated call's ``ec2.amazonaws.com`` short-formed to host ``ec2``;
#: Okta's ``client.device`` is a device *category* (``Computer``, ``Mobile``).
#: Measured: two accounts, or two users, sharing only that value assembled into
#: an incident. Their hostname is an alias, never a join key. The mapping is
#: ingest's to change; this holds whatever it decides. It names these two
#: vendors and nothing else, so a parser that fills the field from some other
#: non-host source is not caught here (see correlation/README.md).
_HOSTNAME_NAMES_NO_HOST = frozenset({"aws-cloudtrail", "okta"})


@dataclass(frozen=True, slots=True)
class EntityRef:
    """One reference to an entity, exactly as a single event carried it."""

    kind: EntityKind
    #: Normalized for comparison: casefolded, trimmed, short-form host.
    value: str
    #: Which event field it came from, kept for provenance in an incident.
    field: str
    #: Whether this value may be used to join events. False for host-local
    #: identifiers and placeholders — they stay as aliases but never link.
    joinable: bool


@dataclass(frozen=True, slots=True)
class Entity:
    """One resolved entity and every alias that resolved to it."""

    kind: EntityKind
    #: Stable canonical key — the lexicographically first joinable alias, so
    #: the same input always produces the same key regardless of event order.
    key: str
    aliases: tuple[str, ...]
    #: The fields this entity was seen in, for "why do you think that".
    fields: tuple[str, ...]

    @property
    def joinable(self) -> bool:
        """Whether this entity can link events at all."""
        return bool(self.key)


def _clean(value: str | None) -> str:
    """Casefold and trim, bounded. Empty when the value identifies nothing."""
    if value is None:
        return ""
    text = value.strip().casefold()[:MAX_FIELD_LEN]
    return "" if text in NEVER_JOIN else text


def _is_ldh(label: str) -> bool:
    """Letters, digits, hyphen and underscore, non-empty — Unicode-aware, so an IDN label passes."""
    return bool(label) and all(character.isalnum() or character in "-_" for character in label)


def _is_host_label(label: str) -> bool:
    """Whether ``label`` could be the leading label of a hostname.

    LDH-shaped (:func:`_is_ldh`: RFC 1123's rule plus the underscore Windows
    names carry) and not a number. A purely numeric label is an IPv4 octet,
    in any script (``str.isnumeric`` catches a fullwidth ``10`` as well as
    ``10``), and so is a ``0x`` hex label: ``inet_aton`` reads ``0x7f000001``
    as 127.0.0.1, and review measured it linking two records as one host.
    A positive shape rather than a list of forbidden characters, because a
    list is the rule the thing it means to stop can spell differently.
    """
    if not _is_ldh(label) or label.isnumeric():
        return False
    digits = label[2:] if label.startswith("0x") else ""
    return not (digits and all(character in "0123456789abcdef" for character in digits))


def _short_host(value: str) -> str | None:
    """``web-01.corp.example`` → ``web-01``; ``None`` when the value is not a name.

    A fully-qualified name and its short form are the same machine, and
    sources disagree about which they report. Only the leading label is taken:
    stripping more would collide ``web-01.a.example`` with ``web-01.b.example``,
    which are not necessarily one host — but in practice the short name is what
    endpoint telemetry carries and what an analyst types.

    The whole value must be DNS-shaped or nothing is returned, and the caller
    carries the value as an alias only: every label LDH-shaped, the leading
    one a hostname label (:func:`_is_host_label`), the last one not all digits
    (no top-level domain is), one trailing dot allowed. An IP literal in the
    hostname field is handled by :func:`_address_literal` first, but review
    measured the fall-through open twice. First a literal ``ipaddress``
    refuses — ``10.0.0.5:514``, ``[10.0.0.5]``, ``010.0.0.5``, ``127.1``,
    ``sensor@10.0.0.5``, fullwidth digits — reached the split, and
    ``10.0.0.5:514`` and ``10.0.0.7:514`` became one host ``10``. Then, with
    only the leading label checked, ``0x7f.0.0.1`` and ``0x7f.0.0.2`` became
    one host ``0x7f``. The cost: a name with a character outside that shape
    anywhere (``web-01.corp.example:8080``) is an alias and does not link.
    """
    labels = (value[:-1] if value.endswith(".") else value).split(".")
    if not _is_host_label(labels[0]) or labels[-1].isnumeric():
        return None
    return labels[0] if all(_is_ldh(label) for label in labels[1:]) else None


def _address_literal(value: str) -> str | None:
    """Canonical spelling of an IP literal; ``""`` if it identifies nothing; ``None`` if not one.

    :data:`NEVER_JOIN` names ``127.0.0.1``, ``::1``, ``0.0.0.0`` and ``::`` as
    strings, and a string rule catches one spelling of each. Measured through
    the Zeek parser: ``0:0:0:0:0:0:0:1``, ``::ffff:127.0.0.1``, ``127.0.0.2``,
    ``0000::1``, ``::0`` and ``0:0:0:0:0:0:0:0`` each became a *joinable*
    address entity, and two flows sharing nothing but that placeholder became
    an incident. So the refusal is on the **parsed** value — AGENTS.md §5
    records this defect class ("six spellings are unspecified and a literal
    rule catches one of them") — and the value that survives is the canonical
    spelling, so one address written two ways is one entity rather than two.
    An IPv4-mapped literal is the IPv4 address it wraps: a dual-stack socket
    reports an IPv4 peer as ``::ffff:a.b.c.d``.

    Only loopback and unspecified are refused — the two kinds the committed
    set already names — as ``ipaddress`` reports them. Link-local and
    multicast are not, and nor is an encoding it does not report as loopback
    (IPv4-compatible ``::127.0.0.1``, NAT64 ``64:ff9b::127.0.0.1``, 6to4
    ``2002:7f00:1::``): each is an ordinary address that joins. Widening the
    set is a deny-list decision for review, not a spelling fix.
    """
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_loopback or parsed.is_unspecified:
        return ""
    return str(parsed)


def _is_display_name(value: str) -> bool:
    """Whether a value is a human label rather than an identifier.

    Identifiers do not contain whitespace. This matters concretely: the Entra
    parser maps ``userDisplayName`` into ``actor.user_name``, so that field is
    not always a login name. Two different people can share "John Smith", and
    joining events on a display name would merge them — so a spaced value is
    kept as an alias for display and never used to link.
    """
    return any(character.isspace() for character in value)


def _is_host_scoped_user(value: str) -> bool:
    """Whether a user value names a built-in principal rather than an actor.

    Judged on the **value**, never on the field that carried it. That
    distinction is load-bearing and was learned the hard way: the auditd
    parser maps ``auid`` into ``actor.user_name``, not ``actor.user_uid``, so
    a field-based rule let POSIX uid ``0`` through as an ordinary username and
    merged root on every Linux host into one entity.

    Three shapes qualify: purely numeric (a POSIX uid — ``0`` is root
    everywhere), a well-known SID prefix (``S-1-5-18`` is LocalSystem on every
    Windows host), and a declared built-in account name
    (:data:`HOST_LOCAL_PRINCIPALS`).
    """
    if value.isdigit():
        return True
    if value in HOST_LOCAL_PRINCIPALS:
        return True
    return any(value.startswith(prefix) for prefix in _WELL_KNOWN_SID_PREFIXES)


def references(event: NormalizedEvent) -> tuple[EntityRef, ...]:
    """Every entity reference one event carries, normalized and deduplicated.

    Pure: reads only the event. Order is deterministic (declaration order),
    which keeps canonical-key selection stable.
    """
    found: list[EntityRef] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: EntityKind, raw: str | None, field: str, *, joinable: bool = True) -> None:
        value = _clean(raw)
        if not value:
            return
        if kind == "host":
            literal = _address_literal(value)
            if literal is None:
                # Not short-formed when already refused: the alias keeps what
                # the source wrote (`console.amazonaws.com`, not `console`).
                short = _short_host(value) if joinable else None
                if short is None:
                    # A value that is neither a name nor an address identifies
                    # no host. An alias for provenance, never a join key — see
                    # _short_host for what reached the split before this.
                    joinable = False
                else:
                    value = short
            elif not literal:
                return
            else:
                # An address in a hostname field: its dots are not label
                # separators. Measured through the auditd parser: `10.0.0.5`
                # and `10.0.0.7` short-formed to one host `10`, which merged
                # two hosts and both their users into one scored incident.
                value = literal
            if not value or value in NEVER_JOIN:
                return
        if kind == "address":
            # Refused on the parsed value and carried in canonical form; the
            # string set above still applies first, as defence in depth.
            literal = _address_literal(value)
            if literal is None:
                # The field is declared to carry an address and this is not
                # one: a service name (CloudTrail writes `ec2.amazonaws.com`
                # as sourceIPAddress for a service-initiated call), a JSON
                # boolean rendered `true`, or a spelling ipaddress refuses
                # (`127.000.000.001`, `127.1`, `[::1]`, `127.0.0.1:443`).
                # Measured: 19 such spellings and 3 such service names each
                # linked two unrelated events as an opaque string. An alias
                # for provenance, never a join key — the fail-closed branch
                # the first version of this check did not have.
                joinable = False
            elif not literal:
                return
            else:
                value = literal
        if (kind, value) in seen:
            return
        seen.add((kind, value))
        linkable = joinable and not _is_display_name(value)
        if kind == "user" and _is_host_scoped_user(value):
            linkable = False
        found.append(EntityRef(kind=kind, value=value, field=field, joinable=linkable))

    add("user", event.actor.user_name, "actor.user_name")
    add("user", event.actor.user_principal, "actor.user_principal")
    add("user", event.actor.identity, "actor.identity")
    add("user", event.actor.user_uid, "actor.user_uid")

    names_a_host = event.vendor not in _HOSTNAME_NAMES_NO_HOST
    add("host", event.device.hostname, "device.hostname", joinable=names_a_host)
    add("host", event.device.device_id, "device.device_id")

    # device.ip is an ADDRESS, not a host — see the module docstring.
    add("address", event.device.ip, "device.ip")
    add("address", event.src_endpoint.ip, "src_endpoint.ip")
    add("address", event.dst_endpoint.ip, "dst_endpoint.ip")
    return tuple(found)


#: A union-find node: the entity kind plus its normalized value. Typed with
#: :data:`EntityKind` rather than a bare ``str`` so the kind survives the
#: round trip through the union and no cast is needed when entities are built.
_Node = tuple[EntityKind, str]


class _Union:
    """Minimal union-find over hashable nodes. Stdlib only, by design."""

    __slots__ = ("_parent",)

    def __init__(self) -> None:
        self._parent: dict[_Node, _Node] = {}

    def add(self, node: _Node) -> None:
        self._parent.setdefault(node, node)

    def find(self, node: _Node) -> _Node:
        self.add(node)
        root = node
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression, iterative (no recursion limit to trip).
        while self._parent[node] != root:
            self._parent[node], node = root, self._parent[node]
        return root

    def union(self, left: _Node, right: _Node) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            # Deterministic: the lexicographically smaller root wins, so the
            # result never depends on the order events arrived in.
            low, high = sorted((a, b))
            self._parent[high] = low

    def classes(self) -> dict[_Node, list[_Node]]:
        grouped: dict[_Node, list[_Node]] = {}
        for node in self._parent:
            grouped.setdefault(self.find(node), []).append(node)
        return grouped


def resolve(events: tuple[NormalizedEvent, ...]) -> tuple[Entity, ...]:
    """Resolve every reference across ``events`` into distinct entities.

    Two rules, and only two:

    1. **Intra-event** — *joinable* references of a co-referring kind within
       one event describe the same entity, because the canonical schema's
       ``actor`` group describes one actor and ``device`` one device. This is
       what links a uid to a username: co-occurrence, not resemblance.
       Addresses are excluded (:data:`_CO_REFERRING_KINDS`), since the two
       endpoints of a connection are two different addresses.
    2. **Inter-event** — joinable references join on exact normalized
       equality, plus one rule for user principals:
       ``alice@corp.example`` joins ``alice`` when both appear in the corpus.
       That rule is exact (the local part must equal a seen username
       outright), not a prefix or similarity test.

    **A non-joinable reference never participates in a union.** It is attached
    as an alias of whatever entity its event *did* resolve, and otherwise
    stands alone. This is stricter than it first appears and the distinction
    is load-bearing: when two sign-ins for different principals shared the
    display name "John Smith", unioning through that shared value bridged
    their two entities into one — a false merge produced by a value that was
    already marked unusable for joining. Excluding non-joinable values from
    the union is what actually enforces the rule.
    """
    union = _Union()
    fields: dict[_Node, set[str]] = {}
    joinable_nodes: set[_Node] = set()
    bare_usernames: set[str] = set()
    per_event: list[tuple[EntityRef, ...]] = []

    for event in events:
        refs = references(event)
        per_event.append(refs)
        for ref in refs:
            node = (ref.kind, ref.value)
            fields.setdefault(node, set()).add(ref.field)
            if ref.joinable:
                union.add(node)
                joinable_nodes.add(node)
                if ref.kind == "user" and "@" not in ref.value:
                    bare_usernames.add(ref.value)
        # Rule 1, over joinable references only.
        for kind in _CO_REFERRING_KINDS:
            same = [ref.value for ref in refs if ref.kind == kind and ref.joinable]
            for other in same[1:]:
                union.union((kind, same[0]), (kind, other))

    # Rule 2: a user principal joins the bare username it is built from.
    for kind, value in sorted(joinable_nodes):
        if kind == "user" and "@" in value:
            local = value.split("@", 1)[0]
            if local in bare_usernames:
                union.union((kind, value), (kind, local))

    classes = union.classes()
    root_of = {member: root for root, members in classes.items() for member in members}

    # Attach each event's non-joinable values to the entity that event did
    # resolve for the same co-referring kind; otherwise they stand alone.
    extra: dict[_Node, set[str]] = {}
    alone: set[_Node] = set()
    for refs in per_event:
        for kind in ENTITY_KINDS:
            unusable = [ref.value for ref in refs if ref.kind == kind and not ref.joinable]
            if not unusable:
                continue
            anchors = [ref.value for ref in refs if ref.kind == kind and ref.joinable]
            if anchors and kind in _CO_REFERRING_KINDS:
                root = root_of[(kind, anchors[0])]
                extra.setdefault(root, set()).update(unusable)
            else:
                alone.update((kind, value) for value in unusable)

    def key_rank(kind: str, value: str) -> tuple[int, str]:
        """Rank candidate canonical keys: most globally scoped form first.

        A user principal (``alice@corp.example``) is domain-qualified and
        unambiguous; a bare username is not. Picking merely the
        lexicographically first alias would sometimes canonicalize an entity
        under a less specific name, which reads wrong in an incident even
        though it is stable.
        """
        if kind == "user" and "@" in value:
            return (0, value)
        return (1, value)

    entities: list[Entity] = []
    for root, members in classes.items():
        kind = root[0]
        attached = extra.get(root, set())
        aliases = sorted({value for _, value in members} | attached)
        joinable = sorted((value for _, value in members), key=lambda v: key_rank(kind, v))
        seen = {f for member in members for f in fields.get(member, set())}
        seen |= {f for value in attached for f in fields.get((kind, value), set())}
        entities.append(
            Entity(
                kind=kind,
                key=joinable[0],
                aliases=tuple(aliases),
                fields=tuple(sorted(seen)),
            )
        )
    for kind, value in alone:
        entities.append(
            Entity(
                kind=kind,
                key="",
                aliases=(value,),
                fields=tuple(sorted(fields.get((kind, value), set()))),
            )
        )
    # Deterministic output: by kind, then key, then first alias.
    return tuple(sorted(entities, key=lambda e: (e.kind, e.key, e.aliases[0])))
