# `correlation/` — entity resolution and incident assembly

**Purpose** · Turn normalized events into incidents by deciding which
references across telemetry domains name the same actor, host, or address.
**Risk level** · High — this layer decides *attribution*. A false merge names
the wrong principal with full confidence.
**Skill level required** · Python; the domain judgment is documented below.
**Deployment complexity** · None. Pure computation over events a caller holds.

---

## The governing rule

**A mis-attribution is worse than an honest non-match.** A missed link costs
an analyst one more query. A false link produces a confident incident about
the wrong person, and every downstream artifact — a containment plan, an
escalation, a report — inherits that error.

So two references merge only on a declared, exact rule. There is no fuzzy
matching, no edit distance, no similarity threshold.

## What merges

| Rule | Example |
|---|---|
| **Intra-event co-occurrence** (co-referring kinds only) | One event carrying `auid=alice` and `uid=S-1-5-21-7-1105` links the two: the schema's `actor` group describes one actor. |
| **Exact normalized equality** | `WEB-01.corp.example` and `web-01` are one host (casefolded, short form). |
| **Exact normalized equality** (addresses) | `2001:db8:0:0:0:0:0:1` and `2001:db8::1` are one address; `::ffff:203.0.113.9` is `203.0.113.9`. Compared as parsed addresses, never as strings. |
| **User principal ↔ bare username** | `svc-deploy@corp.example` joins `svc-deploy` — the local part must match *outright*. |

## What deliberately does not merge

Each of these is a vector that would over-merge, and each cost real debugging:

**Connection endpoints are two addresses.** `src_endpoint` and `dst_endpoint`
are the two *ends* of one flow. The intra-event co-occurrence rule is right
for `actor` and `device` and catastrophically wrong here: merging them made
every source equal its destination and transitively collapsed thirteen
distinct addresses into one entity, so a single shared gateway produced one
meaningless window-wide "incident".

**An address is not a host.** DHCP and NAT reuse addresses, so `10.0.0.5`
identifies a host only at a moment in time. `device.ip` resolves as an
*address* entity; the two link events independently.

**Built-in principals are host-scoped.** POSIX uid `0` is root on every Linux
host; `S-1-5-18` is LocalSystem on every Windows one; `root`,
`administrator` and `guest` exist everywhere. Judged on the **value**, never
the field — the auditd parser maps `auid` into `actor.user_name`, so a
field-based rule let uid `0` through as an ordinary username and merged root
on every host into one entity.

**Display names are not identifiers.** Two people share "John Smith". The
Entra parser maps `userDisplayName` into `actor.user_name`, so that field is
not always a login name; a value containing whitespace is never a join key.

**A non-joinable value never bridges.** Marking a value unusable for joining
is not enough on its own — it must also be excluded from the union. Two
sign-ins for different principals sharing the display name "John Smith"
merged into one entity *through* that shared value until this was enforced.

**An address in a hostname field is not shortened.** A sender with no name
logs its address where its hostname would go, and the short-form rule took the
"leading label" of `10.0.0.5` — so `10.0.0.5` and `10.0.0.7` became one host
`10`, merging two hosts and both their users into one scored incident
(measured through the auditd parser). An IP literal is kept whole; it still
links its own events on exact equality. That rule was enforced by `ipaddress`
parsing the value, and review measured its fall-through open: a literal the
parser refuses — `10.0.0.5:514`, `[10.0.0.5]`, `10.0.0.5.`, `010.0.0.5`,
`10.0.0.5/32`, `127.1`, `sensor@10.0.0.5`, fullwidth digits (11 spellings) —
still reached the split and collapsed two hosts to `10`. A check on the
leading label alone was then measured open the same way: `0x7f.0.0.1` and
`0x7f.0.0.2` (the hex form `inet_aton` reads) became one host `0x7f`, and
`web.10.0.0.5` and `web.10.0.0.7` one host `web`. So the short form is taken
only from a value that is DNS-shaped as a whole: every label letters, digits,
hyphen or underscore; the leading one not a number (all digits, or `0x` and
hex digits — `0x7f000001` is 127.0.0.1); the last one not all digits; one
trailing dot allowed. A value that is neither such a name nor a parsed address
is an alias that joins nothing. The cost: a host whose leading label is a
number (`01.corp.example`, `0xbeef`) or whose name carries a character outside
that shape anywhere (`web-01.corp.example:8080`) is kept for provenance and does
not link.

**A loopback or unspecified address is judged on its parsed value, not its
spelling.** `NEVER_JOIN` names `127.0.0.1`, `::1`, `0.0.0.0` and `::` as
strings. Measured through the Zeek parser, `0:0:0:0:0:0:0:1`,
`::ffff:127.0.0.1`, `127.0.0.2`, `0000::1`, `::0` and `0:0:0:0:0:0:0:0` each
linked two unrelated flows into an incident. An address is therefore refused
when `ipaddress` reports the parsed value loopback or unspecified (an
IPv4-mapped one unwrapped first); the string set stays as defence in depth. A
spelling `ipaddress` refuses never joins either (the sections either side of
this one). What that does not cover, so "every spelling" is not claimed: an
encoding `ipaddress` parses and does *not* report as loopback —
IPv4-compatible `::127.0.0.1`, NAT64 `64:ff9b::127.0.0.1`, 6to4
`2002:7f00:1::` — is an ordinary address and joins, as do `0.0.0.1`,
`255.255.255.255`, link-local and multicast; widening to those is a decision
for review, not a spelling fix. And a placeholder *name* is refused only when
`NEVER_JOIN` lists it: a list is a list, so `undefined` or `127-0-0-1` is a
name and joins as one.

**A value in an address field that is not an address never joins.** The
parsed-value rule above had a fall-through, and review measured it open: a
spelling `ipaddress` refuses (`127.000.000.001`, `127.1`, `0x7f000001`, `[::1]`,
`127.0.0.1:443`, `::1/128`, a trailing dot, a zero-width space — 19 in all) was
carried as an opaque string and linked two flows on it, and so were two
documented non-address values: CloudTrail's `sourceIPAddress` is a service name
such as `ec2.amazonaws.com` for a service-initiated call, which linked two
accounts' events, and a JSON boolean in a Zeek address field is rendered
`true`. Such a value is kept as an alias for provenance and is never a join
key. The cost is a missed link for an address written in a form the parser
does not accept; the alternative is a confident incident about the wrong
source. `NEVER_JOIN` also names every loopback *name* a default Debian or
Red Hat `/etc/hosts` gives `127.0.0.1` or `::1` (`ip6-localhost`,
`ip6-loopback`, `localhost4`, `localhost4.localdomain4`, `localhost6`,
`localhost6.localdomain6`), each measured linking two auditd records as one
host — the IPv4 pair only after review found the first fix had covered one line
of the file. Debian's multicast and prefix names (`ip6-allnodes`,
`ip6-allrouters`, `ip6-localnet`, `ip6-mcastprefix`) are not in the set: a list
of names is a list, and those wait on the same decision as multicast addresses.

**A hostname a parser fills from a field that names no host never joins.** No
check on the value can see this, because the values are well-formed hostnames.
CloudTrail has no hostname field and its parser maps `userAgent` into
`device.hostname`, so the service names refused above in `sourceIPAddress`
arrived one field over as hosts `ec2`, `cloudformation`, `console`; Okta's
`client.device` is a device category (`Computer`, `Mobile`). Measured: two
accounts, or two users, from two addresses, sharing only that value formed an
incident. `_HOSTNAME_NAMES_NO_HOST` names those two vendors, and their hostname
is kept whole as an alias. What it does not cover: it is a list of vendors, so
a parser that fills the field from another non-host source is not detected;
Entra's `deviceDetail.displayName` stays joinable, since a registered device's
display name is its name, so two users who both kept a default label such as
`iPhone` still link; and the parser mappings themselves are ingest's to change.

## Fan-out suppression

Grouping transitively on any shared entity merges everything the moment one
entity is common: a default gateway, a jump host, a CI service account. An
entity appearing in more events than `Thresholds.max_entity_fanout` is
demoted to `context_entities` — still reported on the incidents it touches,
never used to join them. Reported rather than dropped, because hiding the
demotion would make the grouping inexplicable.

The default (50) is a starting point, not a truth: the right value depends on
window length and estate size.

## Scoring

Arithmetic from named constants, with every contribution recorded in
`incident.reasons`:

| Contribution | Weight | Why |
|---|---|---|
| Each domain beyond the first | +20 | Cross-source corroboration is the whole premise |
| Each linked entity beyond the first | +5 | Wider blast radius, but an attacker and an admin script look alike on this axis |
| Each event beyond the minimum | +2, capped at +20 | Volume is weak signal; uncapped, one chatty source would outrank real cross-domain evidence |

No learned weights. The detection plan rejected ML confidence scoring as
"non-reproducible, unreviewable in a diff, breaks hermetic CI", and that
verdict applies here.

## Use

```python
from correlation import assemble, Thresholds
from store import EventStore, Query

with EventStore.open(Path(".")) as events:
    window = events.query(Query(since=start, until=end, limit=5_000))

for incident in assemble(window, thresholds=Thresholds(max_entity_fanout=25)):
    print(incident.score, incident.domains, incident.reasons)
```

## What is not here

**ATT&CK stamping** — that is P7 in `docs/DETECTION_INTELLIGENCE_PLAN.md` and
belongs to the mapping engine, which already resolves against the pinned
corpus. A second mapping path here would be unreviewed.

**Host-qualified principals** — `root@web-01` would recover the links the
host-scoping rule conservatively drops. It needs host resolution to have run
first, so it is deliberately deferred rather than approximated.

**Statistical correlation** — beaconing and exfil analytics need flow
telemetry no parser here produces; the detection plan calls building the math
without the sensor "coverage theater".

See `DESIGN.md` §5 boundary 11 for the trust argument.
