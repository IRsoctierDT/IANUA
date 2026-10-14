# Production SOC Plan

> Program doc for turning IANUA from a lab-scoped analysis platform into a
> **deployable own-infrastructure SOC**. Scope and charter posture were set by
> the repository owner on 2026-10-14; this file records the staging, the
> charter crossing each stage requires, and live status.

---

## Executive Summary

IANUA's analysis layers are strong and its operational layers are absent. It
normalizes ten telemetry formats, maps events to a pinned ATT&CK corpus,
matches a reference-gated behavioral corpus, ages threat intel, and plans
containment — all to a standard a reviewer can check. What it has never had
is a *running system*: nothing collects telemetry, nothing stores it, nothing
resolves entities across sources, nothing runs on a schedule, and nothing
knows who is asking.

This program builds those, in dependency order, and amends the charter as
each stage crosses a boundary rather than relaxing it up front.

## Objectives

1. Collect real telemetry continuously from hosts the operator owns.
2. Persist it durably, with retention, so history is queryable.
3. Resolve entities across domains and assemble incidents.
4. Run detection on a schedule rather than on demand.
5. Know who is asking, so access and approval can be decided per caller.
6. Deploy and operate it as a service, with its own health visible.

**Non-objective:** a client-facing or multi-tenant managed SOC. That collides
with `AGENTS.md` §5's client-information prohibition, and the binding work is
not code — data-processing agreements, an actual SOC 2 audit rather than this
repository's deliberately *indicative* mapping, data residency, and staffing.
If that is ever the goal, it starts as a business decision, not a commit.

## The honest starting position

Assessed 2026-10-14 against `DESIGN.md`, the Decision Log, and the tree.

| Subsystem | State | Evidence |
|---|---|---|
| Normalization | **Built** | `ingest/`: 10 parsers, 5 domains, fail-closed recognition, OCSF classification |
| ATT&CK corpus | **Built** | `attack/`: pinned, hash-verified, revocation-aware |
| Detection content | **Built** | Sigma base + behavioral TTP corpus, reference-gated |
| Threat intel | **Built** | `intel/`: expiring, decaying, corroboration-capped |
| Containment | **Built (direct-invocation)** | `agents/tools/containment.py`, policy-gated per call, audited |
| Policy + audit | **Built** | `agents/policies/`: default-deny, hash-chained |
| Compliance | **Built** | `compliance/` + published trust page |
| **Persistence** | **Stage 1 — this program** | Postgres provisioned in compose but "not yet used by application code"; zero DB imports repo-wide |
| **Correlation** | Absent | `correlation/` planned as XDR-2, blocking P7 |
| **Collection** | Absent | `ingest/` takes records from a caller; no forwarder, listener, or poller exists |
| **Scheduling** | Absent | No scheduler in `agents/`, `ingest/`, `dashboard/`, `mcp/` |
| **Identity** | Absent | Decision Log, 2026-08-21: "the repository has no caller identity at all" |
| **Case management** | Partial | `dashboard/escalations.py` reads the Agent Trust Broker queue — read-only by design |
| **Operational envelope** | Absent | Single-node compose, loopback-only, no HA/backup/DR, no self-monitoring |

## Stages

Ordered by dependency, not by appetite. Stages 1–4 cross **no** `AGENTS.md` §5
boundary, which is why they come first: the foundation can be built, reviewed
and run against lab telemetry before any charter amendment is argued.

| # | Stage | Charter crossing required | Status |
|---|---|---|---|
| 1 | **`store/`** — durable append-only event store | None (lab data under gitignored `data/`) | **DONE** — this PR |
| 2 | **`correlation/`** — entity resolution across domains, incident assembly (XDR-2) | None | Planned |
| 3 | **Caller identity** — a principal on every request; authz decided per caller; approval bound to a person | None to build; unblocks Stage 7 | Planned |
| 4 | **Scheduled execution** — continuous detection over the store rather than on demand | None | Planned |
| 5 | **Collection** — agents/forwarders shipping real telemetry | **Yes**: `ingest/`'s no-network invariant stays (collection is a separate package); default-deny egress must admit collection endpoints (`DESIGN.md` Decision Log, initial) | Planned |
| 6 | **Real telemetry + retention policy** | **Yes**: §5 treats logs and client info as sensitive by default and `data/` as lab-only; real logs carry usernames, addresses, hostnames. Needs a stated PII posture, not a silent reclassification | Planned |
| 7 | **Authenticated multi-user access** | **Yes**: `dashboard/`'s "local-only backends" invariant and loopback-only binding | Planned |
| 8 | **Response execution** (plan → act) | **Yes**: `agents/response/` ships no executor and security tests enforce that. The 2026-08-21 containment decision is the template for doing this properly — a dedicated action class decided and audited per invocation, not an allow-list standing grant | Planned |
| 9 | **Operational envelope** — HA, backup/DR, self-monitoring, SLOs | None in §5; deployment remains human-gated per §5.1 | Planned |

### Why this order

Stage 1 before everything because correlation, scheduling and case history all
need somewhere to read from. Stage 3 before Stage 8 because per-invocation
human approval is impossible without a caller to bind it to — the exact reason
the 2026-08-21 decision gave for keeping the plan→execution boundary closed.
Stage 5 before Stage 6 so the collection path is reviewed while it is still
carrying lab data. Stage 8 last, because it is the only stage that can cause
an outage on the operator's own infrastructure.

## Risks

| Risk | Mitigation |
|---|---|
| Charter becomes aspirational — documents a posture the code left behind | Amend per crossing, in the PR that crosses it (owner's decision, 2026-10-14). No stage ships against a charter that does not yet describe it. |
| A half-built SOC is trusted as a whole one | Each stage states what it does **not** do, in its own README. The platform's existing habit — telemetry-required detections declaring themselves aspirational — is the standard to hold. |
| Real telemetry arrives before the PII posture is written | Stage 6 is explicitly gated on that posture, and Stage 5 carries lab data only. |
| Response execution causes an outage | Restrict-only verbs, reversible primitives, per-invocation approval bound to a caller identity, rollback stated per action — the controls the containment decision already established. |
| Scope drifts toward multi-tenant | Recorded above as a non-objective with its reason. |

## Cost Considerations

Stages 1–4 and 9 are engineering time only; the stack stays local-first and
open-source, and Stage 1 added no dependency. Stages 5–7 may introduce the
first runtime dependency in the repository's history, which is a §5.1 gate
with its own review — `dependencies = []` is load-bearing, and stdlib
alternatives are preferred where one exists (Stage 1 used `sqlite3` rather
than a database driver for exactly this reason).

## Future Enhancements

- Replace the content-addressed integrity check with a hash-chained one, so
  deletion is detectable and not merely counted.
- A self-description gate (`docs/PATH_RECONCILIATION_AUDIT.md` §7.1), which
  would keep this file's status table honest automatically.
