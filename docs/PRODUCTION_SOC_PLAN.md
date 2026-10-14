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
| Persistence | **Stage 1 — done** | `store/`: append-only, content-addressed, tamper-evident |
| Correlation | **Stage 2 — done** | `correlation/`: declared-exact entity merges, fan-out suppression, explainable scoring |
| **Collection** | Absent | `ingest/` takes records from a caller; no forwarder, listener, or poller exists |
| Scheduling | **Stage 4 — done** | `pipeline/` + `scripts/run_pipeline.py`: one at-least-once cycle per invocation with a trailing correlation window, driven by cron or a systemd timer |
| Identity | **Stage 3 — done** | `agents/policies/principal.py`: rides in the hashed `actor` field; no ambient path to an identity |
| **Case management** | Partial | `dashboard/escalations.py` reads the Agent Trust Broker queue — read-only by design |
| **Operational envelope** | Absent | Single-node compose, loopback-only, no HA/backup/DR, no self-monitoring |

## Stages

Ordered by dependency, not by appetite. Stages 1–4 cross **no** `AGENTS.md` §5
boundary, which is why they come first: the foundation can be built, reviewed
and run against lab telemetry before any charter amendment is argued.

| # | Stage | Charter crossing required | Status |
|---|---|---|---|
| 1 | **`store/`** — durable append-only event store | None (lab data under gitignored `data/`) | **DONE** |
| 2 | **`correlation/`** — entity resolution across domains, incident assembly (XDR-2) | None | **DONE** |
| 3 | **Caller identity** — a principal on every request, carried in the audit chain | None | **DONE** (the three gated paths) |
| 4 | **Scheduled execution** — continuous detection over the store rather than on demand | None (lab data; no new egress, no new dependency) | **DONE** |
| 5 | **Collection** — agents/forwarders shipping real telemetry | **Yes**: `ingest/`'s no-network invariant stays (collection is a separate package); default-deny egress must admit collection endpoints (`DESIGN.md` Decision Log, initial) | Planned |
| 6 | **Real telemetry + retention policy** | **Yes**: §5 treats logs and client info as sensitive by default and `data/` as lab-only; real logs carry usernames, addresses, hostnames. Needs a stated PII posture, not a silent reclassification | Planned |
| 7 | **Authenticated multi-user access** | **Yes**: `dashboard/`'s "local-only backends" invariant and loopback-only binding | Planned |
| 8 | **Response execution** (plan → act) | **Yes**: `agents/response/` ships no executor and security tests enforce that. The 2026-08-21 containment decision is the template for doing this properly — a dedicated action class decided and audited per invocation, not an allow-list standing grant | Planned |
| 9 | **Operational envelope** — HA, backup/DR, self-monitoring, SLOs | None in §5; deployment remains human-gated per §5.1 | Planned |

### Running Stage 4 (the scheduled cycle)

One cycle per invocation; the process exits. There is no daemon to supervise.

**The correlation window.** A cycle advances its cursor over the events since
the last one, but *correlates* those alongside a trailing `--lookback` of
already-consumed history (default 900s = three firings of the five-minute
timer). Without that overlap the cursor partitions the event stream, and
cross-domain correlation is windowed rather than partitioned — an attack
landing at 10:02, 10:07 and 10:12 would be three one-event cycles that each
assemble nothing, with no later cycle able to recover it.

Two consequences worth knowing before you read the output:

- **Incidents are reported as they grow.** The 10:02/10:07/10:12 attack above
  surfaces first as a two-domain score-25 incident, then as the three-domain
  score-52 one, with a different `reference` each time because the membership
  changed. That is an escalation series, not a duplicate — it is what seeing an
  attack develop looks like.
- **An incident spanning longer than the lookback is still cut.** Inherent to
  any stateless window. Raising `--lookback` widens the reach at the cost of
  re-correlating more history each cycle; the real fix is persisted, mergeable
  incidents, which is stage 9 work. Pick a lookback longer than the dwell time
  you expect to catch, not longer than you can afford to re-read.

```bash
# on demand, with attribution
python scripts/run_pipeline.py --root /srv/ianua --caller soc-timer

# widen the correlation reach to an hour
python scripts/run_pipeline.py --root /srv/ianua --lookback 3600

# see what a cycle would do without advancing the cursor
python scripts/run_pipeline.py --root /srv/ianua --dry-run

# machine-readable, for a log shipper
python scripts/run_pipeline.py --root /srv/ianua --json
```

**cron** — simplest, adequate for a single node:

```cron
*/5 * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python \
    scripts/run_pipeline.py --root /srv/ianua --caller soc-timer \
    >> /srv/ianua/data/pipeline/run.log 2>&1
```

The redirect target lives in a directory the pipeline creates on its first
run — but the shell opens the redirect *before* the program runs, so on a
fresh deployment the very first firing dies with "No such file or directory"
and never gets the chance to create it. Create it once, owned by the account
that will run the cycle:

```bash
install -d -m 700 -o ianua -g ianua /srv/ianua/data/pipeline
```

**systemd** — preferred, and not only for tidiness. `Persistent=true` runs a
window missed while the host was down, which cron drops silently; and the unit
is where the pipeline's least-privilege posture is actually expressed, since
nothing in the Python can stop itself from being run as root:

```ini
# /etc/systemd/system/ianua-pipeline.service
[Unit]
Description=IANUA detection cycle
[Service]
Type=oneshot
User=ianua
WorkingDirectory=/srv/ianua
ExecStart=/srv/ianua/.venv/bin/python scripts/run_pipeline.py \
    --root /srv/ianua --caller soc-timer
# Least privilege (AGENTS.md §3): the cycle reads the event store and writes
# one cursor plus one audit record. Nothing else needs to be reachable.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
# Must already exist: under ProtectSystem=strict a ReadWritePaths entry that
# is missing makes the unit fail to start rather than creating it. The
# StateDirectory= directive is the systemd-native alternative if you move the
# data root under /var/lib.
ReadWritePaths=/srv/ianua/data
# The cycle makes no outbound connection; the AST tests assert the package
# cannot, and this makes the kernel agree. Note this also cuts off loopback,
# so do not add anything to this unit that talks to a local model or database
# over a socket — give that its own unit instead.
PrivateNetwork=true

# /etc/systemd/system/ianua-pipeline.timer
[Unit]
Description=Run the IANUA detection cycle every five minutes
[Timer]
OnCalendar=*:0/5
Persistent=true
[Install]
WantedBy=timers.target
```

Before enabling the timer, create the data root with the ownership the unit's
`User=` expects (`install -d -m 700 -o ianua -g ianua /srv/ianua/data`), and
confirm that account can read the checkout. Both were verified by reading the
unit against the code rather than assumed: a `ReadWritePaths` entry that does
not exist is a start failure, not an auto-create.

**Exit codes**, which are the whole interface a scheduler sees: `0` the cycle
ran (including the common idle case — a non-zero exit for "nothing new" would
page someone nightly), `1` the cycle or a persisted cursor failed, `2` bad
arguments, `3` blocked by policy.

**What to watch.** `data/pipeline/audit.log` gets two records per cycle: the
gate decision and the outcome. A run that dies mid-cycle therefore leaves a
permitted attempt with no outcome, which is the signal worth alerting on. A
corrupt cursor exits `1` and stops the pipeline rather than reprocessing all
of history or silently skipping it — that is deliberate, and it needs an
operator.

A cycle holds an exclusive lock (`data/pipeline/cycle.lock`) for its whole
run. If the timer fires while one is still going, the new invocation prints
`skipped: another cycle holds the lock` and exits `0`. Occasional skips are
the schedule being tighter than the work; *persistent* skips mean a cycle is
taking longer than the interval, and the batch size or the interval needs
changing. The lock is not tidiness — two cycles appending to the hash-chained
audit log at once fork the chain and break `verify()` permanently, which would
put a false positive into a tamper detector.

**Known limitation — ingestion order.** The cursor is a keyset over
`ingested_at`, so a collector that stamps an *earlier* `ingested_at` than the
cursor has already passed will have those events skipped permanently. Nothing
writes events yet (collection is Stage 5), so this is a contract on whatever
does: `ingested_at` must be non-decreasing across calls. Making it
unconditionally safe needs a monotonic sequence column, which is a schema
change and belongs to Stage 5 when the collector lands.

### Why this order

Stage 1 before everything because correlation, scheduling and case history all
need somewhere to read from. Stage 3 before Stage 8 because per-invocation
human approval is impossible without a caller to bind it to — the exact reason
the 2026-08-21 decision gave for keeping the plan→execution boundary closed.
Stage 5 before Stage 6 so the collection path is reviewed while it is still
carrying lab data. Stage 8 last, because it is the only stage that can cause
an outage on the operator's own infrastructure.

## Found during Stage 3, not yet addressed

The Stage 3 survey established that **the repository's actual shipped call path is
ungated and unaudited**: `cli/run_incident.py` → `agents/orchestrator_agent.py` →
the ten `agents/*_agent.py` modules → `agents/tools/llm.py`, which performs real
`urllib` egress (`llm.py:68`) and imports no policy engine, no `enforce`, and no
`AuditLogger`. Only three `enforce()` call sites exist outside tests
(`containment.py:161`, `guarded.py:90`, `mcp/server.py:103`), and `guarded.enforce`'s
own docstring describing itself as the shared chokepoint is true only of the
containment toolkit and the MCP registry.

Stage 3 deliberately did not change this. Adding identity to a path with no gate
would put a principal in a log line without putting a decision behind it — the
appearance of control rather than control. Closing it is **enforcement** work:
deciding the action class for local-LLM egress, choosing whether a loopback call is
gated at all, and threading the policy engine into the agent pipeline. That belongs
in its own stage with its own review, and is not a prerequisite for Stages 4–9.

Also outside every gate: `cli/` is in no scope — not `packages.find.include`, not
mypy, not coverage, not bandit — and `tests/unit/test_gate_scope_parity.py` asserted
the canonical set against each config surface but never asserted that every top-level
directory containing `.py` is *in* that set. So `cli/` was ungated by omission rather
than by decision.

**Half-closed in Stage 4.** The parity test now asserts that every top-level
directory holding Python is either in a gate scope or in a named `UNGATED` set with
its reason, so a new package cannot repeat this silently — that was the mechanism
by which `pipeline/` could have been forgotten the same way. `cli/` is listed there
pointing at the enforcement stage above. The omission is now a recorded decision;
the two modules are still untyped (`def main():`) and still reach `llm.py`'s egress
with no gate behind it, which is the part that stays open.

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
