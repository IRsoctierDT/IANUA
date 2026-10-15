# Event retention runbook

**Purpose** · Bound what the event store holds, without destroying evidence nobody has
analysed and without believing a number the platform did not measure.
**Risk level** · High. A report changes nothing. `--apply` deletes evidence irreversibly,
and re-collection does not recover it on its own — the recovery path below exists, but it
is bounded by what the source logs still hold and it costs you the store's reclaimability.
**Skill level required** · Operator who holds the policy-bundle grant and understands what
the detection cursor is for.
**Deployment complexity** · Low. One stdlib CLI, no service, no new dependency.

---

## Executive Summary

Two different things in this repository are called retention. This runbook is about the
**event store**: `scripts/run_retention.py`, which calls `EventStore.prune`. Audit-log
retention is a separate subsystem (`agents/policies/audit.py::apply_retention`,
`scripts/audit_maintenance.py`), it is not driven by this CLI, and §"Bounding the audit
chains" below says what to do about it instead.

Three measured facts shape everything here, and the first is the one that surprises people:

1. **A prune returns no disk.** `DELETE` moves pages onto SQLite's free list; it does not
   truncate the file. Measured through the shipped CLI with the destructive grant: a store
   of 20,889,600 bytes, `events_removed: 10200` of 12000, exit 0 — and the file was
   **20,889,600 bytes afterwards**, same inode, `page_count` unchanged at 5100, with
   `freelist_count` 0 → 4247. The JSON report has no byte, size or disk field, so nothing
   in the output hints at this. Four independent scales agree (5k / 12k / 30k / 75k events).
2. **What a prune buys is a plateau, not a reclaim.** Freed pages are reused by later
   appends, and the file grows only when they run out — measured: after a prune to 1,800
   rows, appending 5,000 then 10,000 more events moved the file not one byte while the free
   list drained 4,325 → 2,240 → 87, and the file grew exactly when it hit 0. So the store
   settles at the **peak** live set it has ever held. Returning bytes to the filesystem is a
   separate, manual `VACUUM` which this repository does not ship: `grep -rni vacuum .`
   returns zero matches, `EventStore` exposes no vacuum method, and its connection is
   private (`__slots__ = ("_conn", "_path")`). §"Reclaiming disk" is the procedure.
3. **The platform cannot see a prune.** Measured on a node with a real collector, a real
   cycle and a real backup: `scripts/report_sli.py` read `met=8 breached=0 unknown=0
   healthy=True`, **exit 0**, both before and after a pass removed **120 of 120** events —
   the status map byte-identical, with `ingest-freshness` reporting "newest event stored 1s
   ago" over zero rows. That is deliberate and test-pinned, not a bug (see §"Verifying a
   pass"), which is exactly why the verification step has to be yours.

## Objectives

- A window an operator can defend, chosen against a measured per-event cost rather than a
  guess.
- Deletion that stays an authorized act: report by default, delete on a standing grant that
  is a reviewable line in a committed file.
- No pass that destroys evidence the detection cycle has not read, and no pass that
  quietly narrows an incident the cycle has not finished assembling.
- A verification step the operator runs, because the one the platform offers reads green on
  an emptied store.

## Process

### Reporting, which is the default and needs no grant

```bash
python scripts/run_retention.py --root /srv/ianua --caller soc-timer --json
```

Reports what a pass *would* remove and deletes nothing. Writes two audit records. Safe on a
timer, and the sane thing to leave running: the report is how you find out that the cursor
is lost, the clock has stepped, or collection stopped.

Read four fields before anything else:

| Field | What it tells you |
|---|---|
| `events_matching` | What the effective threshold selects **at that instant** (see the warning below) |
| `effective_threshold` | The window after clamping to the cursor and the correlation margin |
| `cursor_state` | `present`, `absent`, `ahead-of-store`, each also with ` (override)` |
| `events_withheld_unprocessed` | Held back because the cycle has not reached them — **read §"The withheld count over-reports" first** |

The report has 14 JSON fields; `elapsed_seconds` appears only under `--json`. `keep_days`
is an **int when the flag is defaulted (`90`) and a float when supplied (`90.0`)**, so a
consumer must accept both. `events_removed` is `null` on every report and an int on every
applied pass. `cursor_ingested_at` and `effective_threshold` are both `null` exactly when
`cursor_state` is `absent` or `ahead-of-store` without the override.

### Granting deletion

The grant is an edit to the `"allow"` list of `agents/policies/policy.json`. **That edit is
the human approval** AGENTS.md §5.1 requires for a destructive action; nothing prompts at
run time, by the 2026-08-21 decision that `guarded.enforce()` cannot express one.

| Flag | Required label | Notes |
|---|---|---|
| `--apply` | `retain_events:apply` | Deletes processed events older than the window |
| `--apply --include-unprocessed` | `retain_events:apply-unprocessed` | Deletes evidence the cycle has **never read** |

Grants are **exact string matches**, in both directions. Measured over a 12-cell matrix:
`retain_events`, `retain_events:*` and `retain_events:dry-run` all leave `--apply` blocked
at exit 3, and holding `retain_events:apply` does **not** confer
`retain_events:apply-unprocessed` or the reverse. `--include-unprocessed` without `--apply`
needs no grant at all. **Never add both labels in the same edit** — the second one is the
one that deletes unanalysed evidence, and it deserves its own decision.

Two things weaken the gate and a reviewer should look for both. A bundle that sets
`"destructive": "allow"` in its policy map deletes with an empty allow list — the
exact-match property is on the label, not on the class (tracked). And `--policy` points at
any file the invoking account can read, so the gate is only as strong as control over that
path (tracked). On the deny list winning: when a label is on both lists the pass exits 3
with reason `deny` and still prints a hint telling you to add it to `allow`, where it
already is.

### Applying a pass

```bash
# 1. Verify the newest backup FIRST. This is the only thing that distinguishes a
#    partial copy from a small store, and after the prune it is your only second copy.
python scripts/run_backup.py --root /srv/ianua --verify /srv/ianua/data/backups/backup-<ts> --caller soc-op --json

# 2. Report, and read it. Do not skip this even though step 3 may not match it.
python scripts/run_retention.py --root /srv/ianua --caller soc-op --json

# 3. Apply. Same command plus --apply, with the grant in place.
python scripts/run_retention.py --root /srv/ianua --caller soc-op --apply --json

# 4. Verify the pass yourself — report_sli will not do it for you (§"Verifying a pass").
```

> **The report does not predict the delete.** The predicate is identical but the threshold
> is re-derived from `time.time()` on every invocation, so it sweeps forward between the two
> commands. Measured with no concurrency and no unusual flag, on events arriving one second
> apart across the boundary: the report said `events_matching: 7`, and the `--apply` **six
> seconds later** removed **12**. Threshold moved by 6.13 s. The control — the same two-step
> sequence on events 200 days from the boundary — gave 12 and 12, so this is arrival density
> times delay, not noise. Read the report for `cursor_state`, the withheld counts and
> whether the pass is sane at all; do not treat `events_matching` as the number that will be
> deleted.

### Scheduling

Offset the retention timer from the cycle and the backup. The four entry points take four
**different** locks (`data/collect/collect.lock`, `data/pipeline/cycle.lock`,
`data/events/retention.lock`, `data/backups/backup.lock`) and do not exclude each other:
measured, with `cycle.lock` held, a retention pass ran normally and reported "would remove 9
of 35 event(s)". **Do not add a shared lock** — `AGENTS.md` §5 records that framing as
refuted by measurement; the `--lookback-margin` is the safety property. Offsetting is for
cost and legibility, not safety: a prune colliding with an in-flight backup roughly doubled
the backup's duration (1.81 s → 3.39 s on a 205 MB store), and the backup was still correct
(manifest attestation matched the pages actually copied, digests equal, integrity ok).

Backup **before** prune, never after. A backup taken after a pass captured the emptied store
and reported `{"events": 0}` with exit 0. Your recovery window is bounded by the **oldest
retained** backup, so keep at least one older than one retention window — nothing prunes old
backups.

### Reclaiming disk

Only `VACUUM` returns bytes, and the operator runs it against the database directly because
no code path in this repository does.

```bash
# After the retention pass has released data/events/retention.lock, with no writer
# in a transaction. Stop the timers first.
systemctl --user stop ianua-pipeline.timer ianua-collector.timer
sqlite3 /srv/ianua/data/events/events.sqlite3 'VACUUM;'
systemctl --user start ianua-pipeline.timer ianua-collector.timer
```

Measured on a freshly pruned 12,000-event store (1,800 rows left):

| Property | Measurement |
|---|---|
| Payoff | 20,889,600 → 3,149,824 bytes, **-84.9 %**, in 21.9 ms |
| On an **unpruned** store | 20,877,312 → 20,512,768, **-1.7 %**, in 232.8 ms — defragmentation only, and ten times slower |
| Inode | preserved (2360735 → 2360735), so it rewrites in place and cannot drop the mode |
| Mode | `0o600` preserved |
| `attest()` digest | bit-identical |
| Rows, `event_id`s, `meta`, high-water mark | unchanged |
| 11 indexes, both append-only triggers | preserved; the trigger still refuses an `UPDATE` |
| `PRAGMA quick_check` / `verify_integrity()` | `ok` / passes |

So `VACUUM` pays in proportion to the free list: run it **after** a prune, never instead of
one. Three operational caveats, each measured:

- **Its scratch copy lands in `/var/tmp`, not in the lab root.** Observed via
  `/proc/self/fd`: `/var/tmp/etilqs_e6896c221ab3f273 (deleted)`, mode `0o600`, `nlink=0`,
  sized like the *live* data (3,149,824 B). `TMPDIR` and `SQLITE_TMPDIR` are both unset by
  default; set one if `/var/tmp` is a small separate volume. It is unlinked and owner-only,
  but it is a full copy of the evidence database.
- **It takes none of this repository's locks**, so nothing serialises it against a pass or
  a cycle. It succeeds against an idle open store and against an open read cursor, and fails
  with `OperationalError: database is locked` against an open write transaction.
- **It is not validated against the backup/restore drill.** The invariants above are
  measured; a restore drill against a vacuumed store is not. Run one in a lab before
  adopting this on a node you care about.

`PRAGMA auto_vacuum=FULL` (one pragma, then one `VACUUM` to convert) makes every prune
shrink the file inline, and measured conversions preserved inode, mode, digest and
`EventStore.open()`. It is **not free**: replicated timing over three runs per arm put
prunes at `auto_vacuum=FULL` **~9 % slower** than at `NONE` (mean 248.0 ms vs 226.8 ms,
every FULL replicate slower than every NONE replicate). Treat it as measured-promising, not
validated — the repository ships `auto_vacuum=0` and no migration exists.

### Bounding the audit chains

Retention does not touch them. `grep -cE 'apply_retention|max_bytes|retain_segments'
scripts/run_retention.py` is 0, and the only non-test caller of `apply_retention` is
`scripts/audit_maintenance.py`, whose limit flags default to `None` — run with no flags it
reported `{"verified": true, "rotated": false, "archives": 0}` and the log did not change
size. Bounding a chain is a **separate** scheduled task that must pass **both**
`--max-bytes` and `--retain-segments`, once per chain under `data/{collect,events,pipeline,compliance}/audit.log`.

Report-only passes grow the chain too: **two entries per pass**, measured exactly (40
entries over 20 passes). The per-pass byte figure is *not* a constant — the audit `reason`
interpolates thresholds, cursor state and both withheld counts — so size the chain from the
entry count and your own measured average, not from a quoted bytes-per-pass number.

## Verifying a pass

`scripts/report_sli.py` cannot see a prune, and this is **documented and test-pinned
behaviour**, not an oversight: `sli/indicators.py` states it ("an emptied store beneath a
live cursor reads `met` and should: `high_water_mark` is a stored mark rather than a `MAX`
over the rows, so it outlives them"), `tests/unit/test_sli.py::test_a_retention_pass_that_empties_the_store_still_measures_met`
asserts it, and `DESIGN.md`'s decision log records why ("refusing it would have invented a
breach out of retention working"). **Do not "harden" it** — you would be inventing a false
alarm and breaking a named test. Verify by hand instead:

1. **Read the pass's own `events_removed`** against the `events_total` in the same report.
2. **Compare `store.attestation.events` across two successive backup manifests.** This is
   the one check in the platform that does see a prune — measured 120 → 0 across a pass.
   Nothing makes this comparison for you.
3. **Do not treat a green `report_sli` as evidence.** The status map was byte-identical
   across a pass that removed every event; the only field that moved was the clock-derived
   freshness value, and it moved in the *healthy* direction.

> **This also reaches compliance.** Control `AUD-03` ("Service-level objectives met on the
> deployed node") tells the attesting operator, in its own `attestation_hint`, to run
> `scripts/report_sli.py --root <lab root> --json` and "attest with that output as
> evidence", where "Exit 0 means every objective is met". Measured: exit 0 and `healthy:
> true` on a node whose entire store had just been pruned to zero rows. Following the
> control as written therefore records a passing HIGH-severity attestation for a node with
> no evidence left. Until that is fixed (tracked), pair any `AUD-03` attestation with the
> manifest comparison above.

## Recovery, and what it costs

The CLI says pruned content "cannot be re-collected", and that is true of the documented
invocation — measured: a collector re-run against a source still holding all 300 lines
reported `events_stored: 0, lines_read: 0` and exit 0, having recovered nothing, because
offsets are never rewound. There is a path, it is not in the CLI's output, and it has
consequences:

```bash
# 1. Stop the collector timer.
systemctl --user stop ianua-collector.timer

# 2. Drop the offsets. This is the step that makes re-collection possible at all.
rm /srv/ianua/data/collect/offsets.json

# 3. Re-run the exact collector invocation for each declared source.
python scripts/run_collector.py --root /srv/ianua --source /var/log/auth.log --caller soc-op --json

# 4. Run the detection cycle so a cursor exists again.
python scripts/run_pipeline.py --root /srv/ianua --caller soc-op --json
```

Measured: 120 of 120 recovered after a total prune (`lines_read: 120, events_stored: 120`),
and on a partially pruned store the survivors deduplicate by `event_id` — 80 lines read, 40
stored, count back to 80. **Three costs, all measured, none optional:**

- **It is bounded by the source.** After a rotation truncated the log in place, the same
  procedure reported `events_stored: 0, lines_read: 0` and exit 0 — a clean success that
  recovered nothing. Past rotation, a prune is genuinely final.
- **It re-dates the evidence.** Recovered rows get a fresh `ingested_at`. Retention is keyed
  on arrival, so recovered old evidence becomes the *last* thing a `--keep-days` pass
  reclaims, and ingestion order is now inverted against occurrence order.
- **It makes the store un-reclaimable under the first grant.** Re-collection re-ingests
  everything in **one** `append_many`, so all rows share one `ingested_at` — measured, 120
  rows, 1 distinct stamp. With the cycle then caught up (`events_read: 120,
  cursor_advancing: true`), a granted `--keep-days 0 --apply` removed **0 of 120** and
  printed "120 event(s) matched the window and were withheld as not yet processed by the
  detection cycle", blaming a cycle that had just read all 120. Reclaiming it needs
  `--include-unprocessed`, which is the second grant.

Note the recovery in your operations log. And note what a **restore** does to the record of
a prune: measured, `data/events/audit.log` went from 4 entries to 1 across a restore, the
"removed 120 of 120" record was gone, and `audit_verify` reported `intact: true` with exit 0
— `signature: "valid"` with `AUDIT_HMAC_KEY` configured, because the backup carries the
`.sig` sidecar. Later passes reuse the freed sequence numbers, so there is no gap to notice.
**Copy the live audit logs aside before restoring**; they are the only evidence of what the
prune did.

## Reading the report correctly

### The withheld count over-reports, by a whole collector batch

`prune` and `count_before` use a strict `ingested_at < ?` with no `event_id` tie-break, so
**every row sharing the cursor's own timestamp** falls into `events_withheld_unprocessed`
and is described as "not yet processed by the detection cycle". It is not a flag-only
curiosity, and it is not off-by-one in practice:

| Regime | Ground truth (by SQL) | Report says |
|---|---|---|
| 35 events, distinct stamps, cursor on the 10th oldest, **shipped `--keep-days 90`** | 20 unprocessed in window | **21** |
| 35 events written in `append_many` batches of 10, cursor inside a batch | 20 | **30**, with `events_matching: 0` |
| 40 events in **one** collector batch, cycle fully caught up | **0** | **40** |

The third row is the operational one. `store/events.py` states that "`append_many` stamps
one time across a whole batch", and both production writers (`collect/__init__.py`,
`scripts/run_collector.py`) use `append_many` — so on a real node the inflation is the size
of the batch the cursor sits in, and the report's suggested remedy is
`--include-unprocessed`, which on that node would have destroyed the whole store. **Check
`detection-backlog` before acting on this sentence.** A caught-up node showing a withheld
count equal to your last batch size is normal; a *growing* one is a stalled cycle. (Tracked
as a defect in the message, not in the clamp — the clamp is right to refuse the cursor's own
commit.)

### The cursor clamp, and an absent cursor clamping to nothing

A pass never deletes at or past the pipeline cursor. An **absent** cursor and a cursor
**ahead of** the newest stored event both clamp to *nothing*: `events_matching: 0`,
`effective_threshold: null`, exit 0. `docs/RESTORE.md` step 3 deletes the cursor by design,
so **after a restore no pass reclaims anything until the cycle has run** and recorded a
position. That is the safe direction — before the clamp existed, the restore procedure left
no cursor and the next pass destroyed 1500 of 1500 restored events. Run the cycle; do not
reach for `--include-unprocessed` to "fix" a post-restore pass that reclaims nothing.

### The correlation margin, and the mismatch nothing can detect

A pass stops `--lookback-margin` seconds **short** of the cursor, defaulting to
`pipeline.DEFAULT_LOOKBACK` (900 s, imported rather than restated so the two cannot drift).
The cycle re-reads processed events as correlation context, and pruning inside that window
degrades an incident instead of erroring: `AGENTS.md` §5 records score 52 over three domains
before a documented pass and 30 over two after it.

**If you raise the pipeline's `--lookback`, raise this to match, and nothing will remind
you.** Measured with the cycle at `--lookback 7200` and retention at the default margin: an
ordinary pass reported "removed 6 of 9 event(s)", exit 0, with **no margin note at all**,
and the incident fell from score 19 over 9 events to 7 over 3 — and its reference changed,
so it re-keys rather than merely shrinking. The cycle's flag is persisted nowhere the pass
can read, so the mismatch is undetectable by design rather than by omission. The paired
commands are in `docs/PRODUCTION_SOC_PLAN.md`:

```bash
python scripts/run_pipeline.py --root /srv/ianua --lookback 3600
python scripts/run_retention.py --root /srv/ianua --lookback-margin 3600
```

Setting `--lookback-margin 0` removes the warning along with the protection: measured, at
the default margin the pass printed the full margin explanation, and at `0` a grep for
"margin" over the text report returned **zero** matches. There is no "you have disabled the
correlation margin" note.

### Exit codes, and the two the documented set does not cover

| Code | Meaning |
|---|---|
| `0` | A pass ran — reported, applied, **or skipped because another pass holds the lock** |
| `1` | The store failed to open or verify, a schema mismatch, an audit write failed, the report could not be written — **or mere SQLite contention** |
| `2` | Bad arguments, an unreadable pipeline cursor, a lock path that is a directory, or the whole-store refusal |
| `3` | Blocked by policy (an ungranted `--apply`) |

Two things a scheduler must handle that the taxonomy above hides:

- **Exit 1 is not always damage.** A concurrent writer holding SQLite's write lock past the
  5.0 s default busy timeout gives exit 1 "error: database is locked" with nothing broken
  and every event still present — retry, do not page. The four separate locks make this
  reachable in normal operation on a busy node.
- **The lock skip is invisible to a scheduler.** A second pass prints "skipped: another
  retention pass holds the lock; this invocation did nothing." on **stdout** and exits 0 —
  measured, including under `--json` (so a JSON log shipper must tolerate that line) and
  including for an **ungranted `--apply`**, which returns 0 instead of 3 because the skip
  precedes the gate. No audit record is written for a skip.
- **A `retention.lock` that is a FIFO hangs forever.** Measured: `timeout 10` returned 124,
  no message, no audit record, no flock taken — so every subsequent scheduled pass blocks
  identically and retention stalls silently. Controls discriminate: a regular file exits 0
  and a directory exits 2. Put a timeout on the scheduler unit (tracked).

The **whole-store refusal** is the guard worth knowing by heart: when the window reaches
past every event in the store, the pass exits 2 rather than deleting everything, naming
either a forward clock step or stopped collection. `--json`, `--include-unprocessed` and
holding the grant do **not** exempt it; only `--keep-days 0` does. Treat exit 2 here as a
fault to investigate, **not** as a pass to force.

## Risks

- **Deletion is irreversible in a way nothing else here is.** The store refuses `UPDATE` and
  `event_id` is a sha256 over the projection, so a stored event cannot be edited — only
  whole rows go. There is no later redaction pass, and no code should assume one.
- **`--include-unprocessed` destroys unanalysed evidence by design.** It is not a repair for
  an inconvenient report. It is the flag where an operator says they mean it, and nothing
  bounds the disk during a detection stall except that choice.
- **A pass can degrade an in-flight incident silently** when `--lookback-margin` is below
  the cycle's `--lookback`. The operator sees a smaller incident, which is indistinguishable
  from a quieter attack.
- **The grant is standing.** Adding `retain_events:apply` permits every future pass, not the
  one you were about to run. Removing it again is the only revocation.
- **A forward clock step raises the store's high-water mark permanently** and delays
  retention for everything after it; the whole-store refusal is what keeps that from
  becoming a total purge.
- **A store file truncated to zero bytes reports a clean pass.** Measured: "nothing to
  remove: no event was ingested more than 90 day(s) ago (0 held)", exit 0, with a
  chain-valid audit record about a store that held 10 events, because SQLite re-creates an
  empty schema and `quick_check` returns ok. Pair every pass with the backup manifest check;
  do not rely on this CLI's exit code to notice evidence loss.
- **A report is not filesystem-read-only.** On a fresh or mistyped `--root` it creates
  `data/events/` with the store, the audit log and two lock files, and exits 0. The `--root`
  checks refuse a relative path, `""`, `.`, `/` and a non-existent path; they cannot refuse
  an existing but wrong directory.
- **`argparse` prefix abbreviation is on**, including for the destructive flag: `--a` is
  `--apply`. Write scheduler lines in full, and treat an abbreviated flag in a unit file as
  a review finding. `--keep-days 1_0` is silently 10.0 days, because Python's `float()`
  accepts underscores.

## Cost Considerations

The store grows at **~1.8 KB per event** — `docs/RESTORE.md` records the measured band
(1761–1885 bytes across runs) and that figure is the one to size against. Independent
marginal measurements here landed at 1740–1778 B/event for a single-line auditd-shaped
record, inside or just under that band; a richer record shape with more observables will
move it, so re-measure before committing to a volume. The `~1.7 KB/event` in `DESIGN.md`'s
decision log and the `~1.8 KB` elsewhere are the **same** byte measurement under two
conventions (1767 B is 1.767 kB decimal and 1.726 KiB binary), not a disagreement.

At the documented collector and `*/5` cycle cadence that is ~507 MB/day and ~15 GB/month, so
a 90-day window is ~45 GB of store. **Choose `--keep-days` against that, then size the
volume for the peak**, because of fact 2 in the summary: the file never falls below the
largest live set it has ever held until someone runs a `VACUUM`.

Two numbers for sizing the pass itself, both measured at 12,000 events:

- **A prune needs transient free space for its WAL, proportional to what it deletes — not
  to the database size.** Peak `-wal` as a fraction of the same-size database: 5.3 % at
  0.83 % of rows deleted, 20.6 % at 10 %, 56.5 % at 50 %, 87.5 % at 85 %. As a multiple of
  the bytes deleted it converges toward 1.0× (630 %, 206 %, 113 %, 103 %). A routine
  scheduled pass at a 90-day window deletes roughly one day — about 1 % — so the routine
  requirement is at the bottom of that range. **You still cannot prune your way out of a
  full disk**, but for fact 1's reason, not this one.
- **Prune time scales with rows deleted**: 7.4 ms for 100 rows, 46.3 ms for 1,200, 183.4 ms
  for 6,000, 329.4 ms for 10,200.

Everything in this section was measured at 12,000–75,000 events (up to ~127 MiB). The
repository's own figures project ~45 GB at a 90-day window, and **`VACUUM` duration and
lock-hold time at that scale are not measured** — two points are not a curve. Do not
extrapolate them into a maintenance window.

## Future Enhancements

- **A disk-usage or retention-freshness SLI.** None of the eight objectives covers store
  size or when retention last ran, so nothing monitors the bound this document calls an
  operational requirement.
- **A byte figure in the report.** `events_removed` with no size field is what makes fact 1
  surprising; reporting `page_count`, `freelist_count` and the file size before and after
  would make it self-evident.
- **A `--vacuum` step, or `auto_vacuum=FULL` as the shipped default**, once the restore
  drill and the cycle have been run against a converted store and the prune-latency cost
  above is accepted.
- **A scheduler artifact.** Every schedule here, including this one, exists only as prose in
  `docs/PRODUCTION_SOC_PLAN.md`; no `.service`, `.timer` or crontab is committed.
- **Backup retention**, in the gated shape this CLI established — nothing prunes old
  backups today, and the recovery window depends on the oldest one.
