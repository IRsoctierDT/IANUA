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
| Collection | **Stage 5 — done (local)** | `collect/` + `scripts/run_collector.py`: declared local log files, read-only, no network. A forwarder/listener for other hosts remains a later stage |
| Scheduling | **Stage 4 — done** | `pipeline/` + `scripts/run_pipeline.py`: one at-least-once cycle per invocation with a trailing correlation window, driven by cron or a systemd timer |
| Identity | **Stage 3 — done** | `agents/policies/principal.py`: rides in the hashed `actor` field; no ambient path to an identity |
| **Case management** | Partial | `dashboard/escalations.py` reads the Agent Trust Broker queue — read-only by design |
| **Operational envelope** | **Partial** | Backup/DR done: `scripts/run_backup.py` + `docs/RESTORE.md`, with a completeness attestation and a drill test. Retention done: `scripts/run_retention.py` + `docs/RETENTION.md`. Self-monitoring and SLOs done: `sli/` + `scripts/report_sli.py`, summarised into `compliance/` as AUD-03. HA is **decided but deliberately not built**: `DESIGN.md` §11 records the approved active/passive-with-a-replicated-store decision, what it gives up, the four candidate fences and the two charter amendments it waits on — egress to a declared peer and, for automatic promotion, an inbound listener. Of its four requirements three are already stdlib and in the tree (`Connection.backup` for the consistency point, the backup manifest for the expectation, `quick_check` for the structural check); only the verify-on-promotion gate is being written, and the fence is **absent and measured to be absent** — `flock` keys on an inode, so two roots both take the single-instance lock (`tests/security/test_ha_fence_is_local.py`). Single-node compose, loopback-only |

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
| 5 | **Collection (local)** — this node's own log files into the store | **Yes, amended**: filesystem reach beyond the project, read-only and declared-only (`AGENTS.md` §5, `DESIGN.md` §5 boundary 14). `ingest/`'s no-network invariant is untouched — collection is a separate package — and **default-deny egress is NOT amended** | **DONE** |
| 5b | **Collection (remote)** — forwarders or a listener for other hosts | **Yes**: an inbound listening socket with forwarder authentication, which no boundary currently describes. Not egress, so it does not reopen the default-deny argument | Planned |
| 6 | **Real telemetry + retention policy** | **Yes, amended** (both halves have landed). The retention half is `scripts/run_retention.py` — reporting by default, deleting only on an exact-match grant; runbook at `docs/RETENTION.md`. The PII posture half is the charter crossing and is now stated: §5's stage-6 amendment makes it *what `ingest/` writes*, an allow-list rather than a later handling policy, because redaction after the fact is structurally foreclosed — `event_id` is `sha256(projection)` and both tables carry append-only triggers, so only whole-row deletion works | **DONE** |
| 7 | **Authenticated multi-user access** | **Yes**, but narrower than this row used to claim — see "What stage 7 actually crosses" below. The dashboard authenticates no one and now binds loopback only (pinned, control CFG-02) | Planned |
| 8 | **Response execution** (plan → act) | **Yes**: `agents/response/` ships no executor and security tests enforce that. The 2026-08-21 containment decision is the template for doing this properly — a dedicated action class decided and audited per invocation, not an allow-list standing grant | Planned |
| 9 | **Operational envelope** — HA, backup/DR, self-monitoring, SLOs | Backup/DR and self-monitoring cross nothing: a second copy inside the gitignored lab root is permitted today (off-node copies are left to an operator under §5.1's external-network gate), and `sli/` measures the platform from its own on-disk state with no new reach. HA as chosen (active/passive with a replicated store) **does** cross §5.1's dependency-addition row and retires `dependencies = []` | **Backup/DR, self-monitoring and SLOs done**; HA planned |

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
- **After raising `--lookback`, run once with `--include-seen`.** By default a
  cycle reports only incidents involving events it had not already consumed.
  That is a *proxy* for "not reported before", and it is wrong in exactly this
  case: a wider window can assemble a story entirely from already-consumed
  events, which the proxy then suppresses even though no cycle ever reported
  it. `--include-seen` emits everything the window assembled, so the
  remediation actually surfaces what you widened the window to find. Expect
  duplicates of things you have already seen — that is the trade for not
  persisting a reported-reference set.
- **After raising `--lookback`, raise `--lookback-margin` on the retention pass
  to match.** The retention pass holds back that many seconds of processed
  history behind the cursor precisely because this window reads back into it;
  the two defaults are the same number for that reason. Nothing detects a
  mismatch — the pipeline's flag is not recorded anywhere the retention pass
  can read it — and the failure is quiet: measured, a story straddling the
  retention boundary was reported at score 52 over three domains before a pass
  and score 30 over two after it. A smaller incident is not an error message.
- **`--batch` is capped at half the correlation ceiling while a lookback is in
  effect.** Both windows share one ceiling (`assemble` truncates at
  `max_events`), and the context half is now reserved before the progress
  window can spend it. Raising `--batch` past the cap buys nothing; it used to
  buy *less than nothing*, since a batch at the ceiling left the overlap a
  budget of zero and lost a straddling incident while still exiting 0. If a
  cycle reports `context_limited`, the lookback window holds more events than
  the reserve — lower `--batch` to buy more context per cycle.

```bash
# on demand, with attribution
python scripts/run_pipeline.py --root /srv/ianua --caller soc-timer

# widen the correlation reach to an hour — and tell retention about it
python scripts/run_pipeline.py --root /srv/ianua --lookback 3600
python scripts/run_retention.py --root /srv/ianua --lookback-margin 3600

# see what a cycle would do without advancing the cursor
python scripts/run_pipeline.py --root /srv/ianua --dry-run

# machine-readable, for a log shipper
python scripts/run_pipeline.py --root /srv/ianua --json
```

The retention pass that pairs with this cycle has its own runbook — `docs/RETENTION.md`,
which covers the grants, the margin interlock above, what a prune does and does not return,
and why a green `scripts/report_sli.py` is not evidence that a pass behaved.

**cron** — simplest, adequate for a single node:

```cron
# One line. A crontab entry is five schedule fields followed by a command that
# runs to the end of the line; the backslash continuations used in the systemd
# units below are a unit-file convention and do not carry over here. Wrapping a
# cron command across lines does not do what it looks like it does.
*/5 * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python scripts/run_pipeline.py --root /srv/ianua --caller soc-timer >> /srv/ianua/data/pipeline/run.log 2>&1
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

**`--root` must already exist.** The pipeline creates `data/events/` and
`data/pipeline/` beneath the root but never the root itself, and that asymmetry
is deliberate: a mistyped root in a cron line would otherwise build a complete
shadow data tree, find an empty store, print `idle: no new events` and exit `0`
forever — every signal reading healthy while the SOC sees nothing. A missing
root now exits `2`. Create it as part of deployment, not by running the
pipeline.

An `is_dir()` check was not enough, and the gap was the likeliest
misconfiguration there is. `Path("") == Path(".")`, and the working directory
is always a directory, so `--root "$IANUA_ROOT"` with the variable unset passed
the check and built exactly the shadow tree described above — measured on all
four scheduled CLIs (pipeline, collector, retention, backup), one of which
stored events into it, and retention had no root check at all.

**The root must now be absolute**, through one shared
`store.paths.validated_root` rather than a copy per CLI. That is the rule §5 of
the charter already applies to `collect/`'s log sources, for the same reason in
the same words: *a relative path means whatever the scheduler's working
directory happens to be.* An empty, `.`, or any other relative root exits `2`
with a message quoting what was passed, and a refused startup creates nothing —
not the shadow tree, not the root, not its own lock file.

**Existence is tested on the path as supplied, before it is resolved**, and
that ordering is the control rather than a detail. `Path.resolve()` does not
merely normalize: with `strict=False` it collapses `..` lexically against
components that *do not exist*, so `missing/..` becomes the working directory
and `/srv/absent/..` becomes `/srv`. The first version of this fix resolved
first and tested afterwards, which **regressed** the per-CLI guards it
replaced — those had stated `args.root.is_dir()` on the unresolved path, where
the kernel refuses to walk `..` out of a component that is not there, so they
rejected a spelling the shared guard accepted. Measured: `--root missing/..`
exited `0` with "idle: no new events" after writing
`data/events/events.sqlite3` into the working directory. Found by the automated
reviewer on the pull request, against the enumeration of spellings that pull
request had asked it to break — the enumeration was wrong, and asking was what
caught it.

A `..` that survives both rules is *not* refused: every component on the way to
it exists, so nothing was invented and the operator named a real directory the
long way round. That non-refusal has its own test, so over-tightening it into a
blanket `..` ban shows up as a failing test rather than as a refused
deployment.

**The filesystem root is refused**, and it is the only absolute path with a
rule of its own, because it is the only one a misconfiguration produces by
accident. With the variable unset, `--root "$IANUA_ROOT"` is `""` and refused
as relative — but `--root "$IANUA_ROOT/"`, the same line with an ordinary
trailing slash, is exactly `/`, which is absolute and *is* a directory. That
puts the event store at `/data` with every signal reading healthy: one
character from the original hole, in the same catastrophic class. `//`, `/.`,
`/..` and `/proc/self/root` all resolve there too, so the test is on the
resolved path. What it still cannot catch is `--root "$IANUA_ROOT/data"`, which
yields `/data` — an absolute path to a plausible root, indistinguishable from
an operator who meant it. **Name the root in the unit or crontab literally, not
through a variable**, and the whole class goes away.

Pinned for all four CLIs by `tests/security/test_cli_startup_failclosed.py`,
which also fails if a fifth scheduled CLI is added without a row in it.

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

### Running Stage 5 (local log collection)

One pass per invocation; the process exits. Sources are **declared**, never discovered —
there is no glob and no directory walk, because a collector that searches for logs
eventually finds one nobody meant it to read, and everything it reads becomes stored
evidence.

```bash
# on demand, with attribution
python scripts/run_collector.py --root /srv/ianua --caller soc-collector \
    --source /var/log/audit/audit.log --source /var/log/suricata/eve.json

# see what a source would yield without storing or advancing
python scripts/run_collector.py --root /srv/ianua --source /var/log/auth.log --dry-run
```

**What parses today.** Measured, not assumed:

| Source shape | Result |
|---|---|
| JSON lines — Suricata EVE, Zeek, CloudTrail, Azure, Entra, Okta, Defender, Workspace | fully parsed, correlated |
| auditd `type=SYSCALL … comm=bash` | fully parsed via `ingest/keyvalue.py` |
| logfmt app logs (`level=error service=api …`) | fields decoded, domain unclaimed (`unknown`/`partial`) |
| freeform syslog (`Failed password for x from y`) | carried as `unknown`/`text`, **no fields** |

Freeform syslog is deliberately out of scope: extracting it means regex patterns against
unversioned vendor message strings, which is the most defect-prone code in any log pipeline.
If you need `/var/log/auth.log` correlated, the honest options today are to configure the
service to log JSON, or to treat that parser as its own reviewed change.

**cron** — note the cadence:

```cron
# Every minute. Not tidiness: the tail of a file rotated away BETWEEN runs is
# unreachable by name, because a one-shot process holds no descriptor across
# invocations. Running often is what bounds that gap.
#
# One line, as above — no backslash continuations in a crontab.
* * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python scripts/run_collector.py --root /srv/ianua --caller soc-collector --source /var/log/audit/audit.log >> /srv/ianua/data/collect/run.log 2>&1
```

As with the pipeline, create the directory first — the shell opens the redirect before the
program runs, so on a fresh deployment the first firing would die before it could create it:

```bash
install -d -m 700 -o ianua -g ianua /srv/ianua/data/collect
```

**systemd** — preferred, and the unit is where least privilege is actually expressed:

```ini
# /etc/systemd/system/ianua-collector.service
[Unit]
Description=IANUA local log collection
[Service]
Type=oneshot
User=ianua
WorkingDirectory=/srv/ianua
ExecStart=/srv/ianua/.venv/bin/python scripts/run_collector.py \
    --root /srv/ianua --caller soc-collector \
    --source /var/log/audit/audit.log
# Read the logs, write only the lab-data root.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/srv/ianua/data
ReadOnlyPaths=/var/log
# The collector makes no outbound connection; the AST tests assert the package
# cannot, and this makes the kernel agree.
PrivateNetwork=true
# The account needs read access to the sources. Prefer adding it to the group
# that owns them (often `adm` for /var/log on Debian) over running as root.
SupplementaryGroups=adm
```

Both `ReadWritePaths` and `ReadOnlyPaths` must already exist: under `ProtectSystem=strict` a
missing entry makes the unit fail to start rather than creating it.

**Exit codes**, which are the whole interface a scheduler sees: `0` a pass ran (including
nothing-new, and including a skip because another pass held the lock — the output
distinguishes them), `1` a source was unreadable or the store/audit/offsets write failed
(nothing consumed; the next pass re-reads), `2` bad arguments, `3` blocked by policy.

**What to watch.** `data/collect/audit.log` gets two records per pass: the gate decision and
the outcome. A pass that dies mid-run leaves a permitted attempt with no outcome, which is
the signal worth alerting on. Persistent `skipped: another pass holds the lock` means a pass
is taking longer than the interval — raise `--max-bytes` or lengthen the schedule. A `reset`
of `rotated` is routine; `truncated` usually is not, and means something emptied the log.
`replaced` means the bytes at the stored offset are not the bytes that were read there
before — `logrotate copytruncate`, a log cleared with `>`, or an inode reused after a
delete-and-recreate — and the source was re-read from the beginning, so expect duplicates
(harmless: the store is content-addressed) rather than a gap.

**`--max-bytes` has a floor worth respecting.** A value below the 64 KiB line cap means a
single longer line cannot fit in one read. That no longer wedges the source — the read is
extended just far enough to hold one legal line — but every such line then costs an
over-budget read. Leave the flag alone unless a backlog is genuinely not draining.

**A record longer than the line cap arrives as several records, not one.** When a read
finds no newline inside its budget and already holds more than `MAX_LINE_BYTES`, it emits
the first 64 KiB, counts it in `truncated`, and advances by **exactly what it emitted**.
So a 200 KiB single-line record becomes four truncated records rather than one sample, and
the run report says `truncated: 4`. That is deliberate: advancing by the whole read instead
discarded everything past the first 64 KiB of each window — up to 8 MiB minus 64 KiB per
pass — while reporting `truncated: 1`, indistinguishable from an ordinary backlog
(measured at 4505 of 5410 bytes lost). The trade is visible noise over silent loss. If a
pathological source is inflating your event count, fix the source or raise the line cap;
do not read the inflation as separate events on the host.

**One `ingested_at` per source, not per pass.** Each source's batch is stamped immediately
before its own commit, because `append_many` is one transaction per call and the pipeline
holds a *different* lock from the collector — so a cycle can fire between two of a pass's
commits. With one stamp shared across the pass, that cycle saved a cursor inside the tie
group and every later-source event whose content hash sorted below it was behind a cursor
that had already passed: never read, by any cycle. Reproduced at 30 of 60 collected events
permanently invisible with the pipeline reporting `events_read: 0`. Per-commit stamping
means a cursor can only land *between* tie groups. Nothing to configure; it is noted here
because the symptom — a pipeline that reports idle while the store grows — is otherwise
very hard to read.

**Known limitation — a forward clock jump is permanent.** `ingested_at` comes from
`EventStore.next_stamp(time.time())`, which returns a value strictly after the store's
high-water mark whenever the clock is at or behind it. A clock that steps *backwards*
therefore clamps harmlessly and `occurred_at` still carries the source's own time. A clock
that jumps *forward* raises the mark permanently, which delays retention for everything
stored afterwards. Fixing that needs a monotonic sequence column rather than a timestamp,
which is a schema change. (Strictly after, not `max(now, mark)`: the pipeline's keyset
cursor is strictly after `(ingested_at, event_id)`, so an event written at *exactly* the
mark with a lower event id would sit behind a cursor that had already passed it and never
be read — four stored, three ever seen, measured before the fix.)

### What stage 7 actually crosses

This row used to say stage 7 crosses "`dashboard/`'s 'local-only backends' invariant and
loopback-only binding". Establishing the ground truth before planning showed both halves
were wrong, so the row is corrected above and the reasoning recorded here.

**"Local-only backends" is an egress property, not an access-control one.** The phrase
appears in `SECURITY.md` and `dashboard/kb_search.py`, and both use it to mean the services
the dashboard *calls out to* — Ollama on loopback, Qdrant on loopback, or the in-process
lexical fallback. Letting more people in does not touch it.

**Loopback-only binding was not an invariant.** `.streamlit/config.toml` pinned
`fileWatcherType` and `maxUploadSize` and said nothing about the address, and the documented
launch is a bare `streamlit run dashboard/app.py`. So the bind address was whatever the
installed Streamlit defaulted to, with `uv.lock` pinning `streamlit >= 1.65.0` and no upper
bound — not a property this repository controlled, while this plan described it as one. It
is pinned to `127.0.0.1` now and asserted by compliance control **CFG-02**, which fails
closed on an unset address as well as a reachable one. Pinning it also makes the default
irrelevant, which is better than documenting what the default is believed to be.

**There is no authentication in `dashboard/` at all** — not a session, not a password, not a
token. That is the honest starting point for this stage, and it is why the bind address
matters so much: the dashboard renders stored event content, so anywhere it is reachable, it
publishes hostnames, accounts, addresses and raw log messages to whoever reaches the port.

**The chosen model keeps that true.** Access goes behind an authenticating reverse proxy
(nginx or Caddy terminating OIDC or basic auth) while the dashboard stays loopback-bound.
The consequence worth noting is that **IANUA's own reach does not change**, so this stage may
need no `AGENTS.md` §5 amendment at all — unlike stages 5 and 6, what changes is the runbook
and a fail-closed guard, not the platform's boundary. Two things still need deciding before
it is built, and neither is a documentation question:

- **Whether the dashboard consumes a proxy-supplied identity.** A proxy puts the
  authenticated user in a request header, and trusting that header is exactly the
  unauthenticated claim stage 3 refused for `IANUA_PRINCIPAL` — a header is caller-supplied
  unless the path from the proxy is itself authenticated. Per-caller audit and authz are
  worth having, and `agents/policies/principal.py` already provides the vocabulary, but the
  trust argument has to be made rather than assumed.
- **Whether the dashboard refuses to serve when bound non-loopback.** A config file is not a
  control if a flag overrides it, and `--server.address` on the command line does. A startup
  check that fails closed unless an explicit acknowledgement is set would make the posture
  enforceable rather than merely configured.

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
