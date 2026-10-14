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
        "localhost",
        "localhost.localdomain",
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


def _short_host(value: str) -> str:
    """``web-01.corp.example`` → ``web-01``.

    A fully-qualified name and its short form are the same machine, and
    sources disagree about which they report. Only the leading label is taken:
    stripping more would collide ``web-01.a.example`` with ``web-01.b.example``,
    which are not necessarily one host — but in practice the short name is what
    endpoint telemetry carries and what an analyst types.
    """
    return value.split(".", 1)[0] if "." in value else value


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
            value = _short_host(value)
            if not value or value in NEVER_JOIN:
                return
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

    add("host", event.device.hostname, "device.hostname")
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
