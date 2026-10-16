# Backup and restore runbook

**Purpose** · Take a verifiable copy of the lab-data state, and recover from its loss
without losing telemetry.
**Risk level** · Moderate. Taking a backup changes nothing. Restoring one replaces the
SOC's memory, and doing it in the wrong order loses data silently — step 3 is the one that
matters.
**Skill level required** · Operator comfortable with a shell and a scheduler.
**Deployment complexity** · Low. One stdlib CLI, no service, no new dependency.

---

## Executive Summary

Until this existed, every irreplaceable artifact the platform produces — the event store,
the hash-chained audit logs, the compliance evidence trail, the incident reports — lived in
exactly one place on one node with no second copy, and `docs/PRODUCTION_SOC_PLAN.md` said
so. `scripts/run_backup.py` is the mechanism. This document is the procedure, and it is the
half that matters more: the recovery path below needs **no new code**, and the one way to
get it wrong is an ordering mistake that reads as success.

Three facts shape everything here, and each was measured rather than assumed:

1. **A file copy of the event store is not a backup.** While a writer holds the store open,
   the main `.sqlite3` file carried 4 KiB of a 548 KiB database and the rest sat in the
   `-wal` sidecar. A copy of the main file alone passes `PRAGMA integrity_check`, opens
   through `EventStore.open()` without raising, and reports a plausible count — 353 of 400
   events in one measurement. The loss is invisible. The CLI uses SQLite's online backup
   API instead, which is correct whatever the WAL holds.
2. **Nothing else can tell a partial copy from a small store.** Deleting 100 of 400 rows
   leaves `integrity_check`, `count()`, `query()` and `high_water_mark()` all silent,
   because content addressing proves each row is what was written and says nothing about
   whether all of them are there. `EventStore.attest()` digests every `event_id` with the
   row count; the manifest carries that digest, and `--verify` checks it.
3. **Positions must not be restored.** `data/collect/offsets.json` and
   `data/pipeline/cursor.json` are excluded from every backup by construction. See
   "The ordering rule" below — it is the only part of this document that can cost you data.

## Objectives

- A copy of every irreplaceable artifact, taken while the platform keeps running.
- A copy that can be **verified**, so a restore is a decision and not a hope.
- A recovery that loses no telemetry the sources still hold.
- Owner-only modes preserved end to end, because a copy that came back world-readable would
  give away the evidence it was taken to protect.

## Process

### Taking a backup

```bash
python -m scripts.run_backup --root /srv/ianua --json
```

Writes `data/backups/backup-<UTC timestamp>/`, mirroring the root's own layout, with a
`manifest.json`. Exit `0` on success, `1` on failure, `2` on bad arguments or because
the single-instance lock could not be taken, `3` if policy
blocks it, and `4` if another writer held the store's write lock — nothing was taken and
nothing was left behind, so retry rather than page. A second concurrent pass exits `0` and
does nothing, like every other scheduled entry point here.

What lands in it:

| | |
|---|---|
| `data/events/events.sqlite3` | via the online backup API, then attested |
| `data/{collect,events,pipeline,compliance}/audit.log` | plus rotated archives, checkpoints and head signatures |
| `data/compliance/evidence.jsonl` | the compliance evidence trail |
| `data/reports/*.md` | incident reports |
| `manifest.json` | attestation, every file's size and sha256, each chain's verdict |

What does not, and will not:

| | |
|---|---|
| `data/collect/offsets.json` | restoring one newer than the store is unrecoverable |
| `data/pipeline/cursor.json` | never needs restoring; re-correlating is at-least-once |
| `*.lock` | the lock is the open descriptor, not the file |

The backup's own integrity is anchored in the audit chain: the record it appends carries the
manifest's sha256, and the chain is hash-linked, so a manifest edited afterwards no longer
matches an entry an operator can verify. Set `AUDIT_HMAC_KEY` to get a head signature too —
**without one, an audit chain missing its most recent entries verifies as intact**, which is
exactly the shape a mid-write capture produces.

### Verifying one

```bash
python -m scripts.run_backup --root /srv/ianua --verify /srv/ianua/data/backups/backup-20261015T0200Z
```

Re-attests the store, re-hashes every file, and re-verifies every chain against the
manifest. Exit `1` and a list of problems on any mismatch. **Verify before you need it** —
on the schedule, not during the incident.

### Restoring

```bash
# 1. Quiesce. Stop the timers AND the services, then confirm nothing is running.
#    Stopping a timer does not stop the service it already triggered, and
#    "every entry point is one-shot" is not the same as "none is running now" —
#    a collector still in flight can recreate offsets.json after step 3 or write
#    the database during step 4, rebuilding the exact newer-offsets/older-store
#    state this runbook calls unrecoverable.
systemctl --user stop ianua-pipeline.timer ianua-collector.timer
systemctl --user stop ianua-pipeline.service ianua-collector.service
systemctl --user list-units 'ianua-*' --all --no-legend   # expect none active

# 1b. Belt and braces: the locks are the platform's own interlock. If any of
#     these is held, a pass is still running — wait rather than proceed.
for f in collect/collect.lock pipeline/cycle.lock events/retention.lock; do
  flock --nonblock --exclusive "/srv/ianua/data/$f" true \
    || echo "STILL RUNNING: $f is held; do not continue"
done

# 2. Verify the backup you are about to trust.
python -m scripts.run_backup --root /srv/ianua --verify /path/to/backup   # must exit 0

# 3. THE ORDERING RULE. Remove the positions before the store comes back.
rm -f /srv/ianua/data/collect/offsets.json /srv/ianua/data/pipeline/cursor.json

# 4. Put the state back.
cp -a /path/to/backup/data/. /srv/ianua/data/

# 5. Re-collect. Every source is re-read; content addressing stores only what is new.
python -m scripts.run_collector --root /srv/ianua --source /var/log/auth.log --json

# 6. Restart the scheduler.
systemctl --user start ianua-pipeline.timer ianua-collector.timer
```

### The ordering rule

**Never let `offsets.json` be newer than the store.** Of the four skew directions, exactly
one is unrecoverable, and it is this one:

| State | Outcome | Recoverable |
|---|---|---|
| Offsets **newer** than the store | Collector reports `events_stored: 0, lines_read: 0, offsets_advancing: true`, exits 0, while every unread line still sits in the source. Offsets are never rewound. | **No** |
| Store newer than the offsets | Lines are re-read; content addressing drops the duplicates. | Yes |
| Cursor behind the store | The window is re-correlated. At-least-once by design. | Yes |
| Cursor ahead of the store | Usually idles until new events arrive — **but not safely.** `next_stamp` compares the clock against the *store's* high-water mark, not against the cursor, so if the clock has stepped backward to below the cursor, re-collected events are stamped under it and the pipeline's strictly-after keyset never reads them. Measured: a store restored at mark T, a cursor at T+3600, a clock at T+60 → stamp T+60, permanently behind. | **No, after a backward clock step** |

Deleting both positions is therefore **a complete recovery, not a compromise** — measured
at 600 of 600 events with zero duplication. Step 3 exists so that a half-finished restore
cannot leave a stale store under current offsets.

Deleting the cursor in step 3 has a second consequence, and it is a safe one:
`scripts/run_retention.py` clamps its threshold to the cursor, and treats an absent cursor
as "nothing is known to have been processed", so **no retention pass will delete anything
until the detection cycle has run and recorded a position**. Before that clamp existed the
opposite was true — measured, the restore procedure below left no cursor and the next
retention pass destroyed 1500 of 1500 restored events. An operator who needs retention to
reclaim space before the cycle has caught up must pass `--include-unprocessed`, which is
gated on its own `retain_events:apply-unprocessed` grant.

Note that the cursor row above is the reason step 3 deletes the cursor too, rather than
leaving it as harmless. An earlier version of this table called an ahead cursor
recoverable; it is not, once the clock can move backwards, which is exactly when a host
has been rebuilt. Deleting it costs one re-correlated window — at-least-once is the
pipeline's design — and removes the case entirely.

## Risks

- **A verified backup is not a tamper control.** Anyone who can rewrite rows can recompute
  a digest over them. `UPDATE` is trigger-refused and the audit chains are the tamper
  evidence; the attestation catches *loss* — a truncated transfer, a copy that raced a
  writer, a prune nobody meant to run.
- **An unsigned audit chain cannot detect end truncation.** `AUDIT_HMAC_KEY` ships blank, so
  by default a chain missing its newest entries verifies as intact. Configure a key.
- **Backups are on the same node, so they do not survive its loss.** Egress is default-deny
  and has been refused twice (`DESIGN.md` decision log); copying a backup off the node is an
  operator action under AGENTS.md §5.1's external-network gate, not something the platform
  reaches for. A backup directory is self-contained and safe to move as a unit.
- **Backups are a second copy of sensitive evidence.** They are written owner-only inside
  the gitignored lab root. `data/` itself is created at the process umask — measured 0o755 —
  and the CLI warns when any lab-data path is readable beyond its owner rather than silently
  changing a directory it does not own.
- **Nothing prunes old backups.** Deleting them is a `destructive` decision like retention;
  no automatic deletion ships.
- **Restoring an older schema is a migration question, not a completeness one.** The
  manifest records the schema version it was taken under; `EventStore.open()` refuses a
  database written by a different one.

## Cost Considerations

A backup is roughly the size of the store, and the store grows at **~1.8 KB per event**
(measured: 1761-1885 bytes across runs). At the documented collector and `*/5` cycle
cadence that is ~507 MB/day and ~15 GB/month, so each backup costs about a month of
ingestion per copy retained. Choose a cadence and a copy count against the disk you have,
and pair it with `scripts/run_retention.py` — which is the knob that bounds the source, and
whose runbook is `docs/RETENTION.md`. The figures above are measured here and cited there,
rather than the other way round: an earlier version of this paragraph credited them to "its
own runbook" while that runbook did not exist, which made the two references circular around
an absent document.

Note also what retention does **not** buy, because it bears on sizing a volume: a prune
returns no bytes to the filesystem — measured byte-identical across a pass that deleted 85%
of events — so the store plateaus at its peak live set rather than shrinking. Reclaiming
disk is a manual `VACUUM`; `docs/RETENTION.md` has the procedure and its costs.

The backup itself is cheap: the online backup API copies pages under a read lock and the
attestation streams one `event_id` at a time, so neither loads the database into memory.

## Future Enhancements

- **Off-node copies**, which need the §5.1 external-network gate and an operator's
  decision, not a code change here.
- **Backup recency as a monitored indicator** — the two SLIs that have no input until a
  backup exists are backup recency and restore-verified recency. Both are computable now.
- **A scheduler artifact.** Every schedule in this repository, including the one that would
  run this, exists only as prose in `docs/PRODUCTION_SOC_PLAN.md`; no `.service`, `.timer`
  or crontab is committed.
- **Backup retention**, as a gated `destructive` action in the shape `run_retention.py`
  already established.
