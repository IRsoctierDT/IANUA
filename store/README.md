# `store/` — the SOC's memory

**Purpose** · Durable, append-only persistence for the canonical
`NormalizedEvent`, so the platform can answer questions about the past.
**Risk level** · Moderate — holds security evidence; integrity and containment
are the properties that matter.
**Skill level required** · Python; no database administration.
**Deployment complexity** · None. A file under `data/events/`, created on
first open.

---

## Why this is a separate package

`ingest/` translates ten telemetry formats across five domains into one shape,
and then keeps nothing. That is deliberate: its invariant is no clock, no
filesystem, no network, no subprocess, asserted over its own AST. A pure
parser is the right shape for the largest untrusted-input surface in the
platform.

It is the wrong shape for a SOC. The first question after an alert is *what
else did this host do in the hour before it*, and a function that holds
nothing cannot answer it. `store/` is the other half — the one allowed to
touch a disk — and it is separate rather than folded in because persistence
needs exactly the two things `ingest/` forbids. The platform already drew this
line once, between `ingest/` (normalize) and `correlation/` (resolve).

## The storage contract

| Property | How it is enforced |
|---|---|
| **Append-only** | SQLite `BEFORE UPDATE` triggers raise. Not an API convention — anything holding the file open would otherwise be able to rewrite history. |
| **Idempotent** | `event_id` is the SHA-256 of the canonical projection. Appending the same event twice stores it once. |
| **Tamper-evident** | Every row is re-hashed on read; a projection that does not match its `event_id` raises `StoreIntegrityError`. So does one that matches and still will not rebuild (a field past its bound), chained from the reader's `MalformedProjectionError`, since `event_id` is an unkeyed hash and a match does not prove which build wrote the row. |
| **No ambient clock** | `ingested_at` is a required keyword argument. The store never asks the host what time it is. |
| **Contained** | The database lives under gitignored `data/events/`. A filename with a separator, a traversal, or a leading dot is refused. |
| **No hostile sidecar** | Before SQLite opens the database, each `-journal`, `-wal` and `-shm` beside it must be absent or a regular file with one link (`lstat`, never followed). Anything else raises `StoreSidecarError`. See [Sidecars](#sidecars). |
| **Bounded** | Projections over 64 KiB are refused; every query is clamped to 10,000 rows. |
| **Versioned** | A database written by another schema version is refused, never implicitly migrated. |
| **Damage is a `StoreError`** | SQLite's two corruption verdicts (`SQLITE_CORRUPT`, `SQLITE_NOTADB`) are mapped to `StoreCorruptionError` at every public method, so a damaged file cannot reach a caller as a raw driver exception. A lock (`SQLITE_BUSY`), a trigger refusal (`IntegrityError`) and a caller bug (`ProgrammingError`) keep their own meaning. |
| **Verifiable cheaply** | `EventStore.verify_integrity()` runs `PRAGMA quick_check` (1.1-1.5 ms/MiB, measured). `attest()` and `scripts/run_retention.py` both gate on it, because a digest and a count that come from covering indexes describe the indexes and not the rows. |

## Use

```python
import time
from pathlib import Path

from ingest import normalize
from store import EventStore, Query

with EventStore.open(Path(".")) as events:
    events.append(normalize(record), ingested_at=time.time())

    # What else did this host do in the window?
    for stored in events.query(Query(hostname="web-01", since=start, until=end)):
        print(stored.event.message)

    # Every event mentioning an indicator — the intel pivot.
    events.query(Query(observable="4f2a...e91"))

    # Retention, keyed on ingestion time and counted.
    removed = events.prune(before=time.time() - 90 * 86_400)
```

`Query` filters AND together. Unset means unfiltered.

## Two behaviours worth knowing before you rely on them

**An event with no source timestamp is excluded from every time window.**
`ingest/` never back-fills "now", because fabricated ordering corrupts
correlation — so some events genuinely have no position in time. Treating
that as "in range" would place them inside every window anyone ever queries.
They remain reachable without a time filter; they are excluded, never lost.

**Retention prunes on `ingested_at`, not `occurred_at`.** Ingestion time is
always present and is the only one of the two this platform controls. Keying
retention on source-reported time would let a host with a skewed clock keep
its events forever, or have them pruned the moment they arrived.

## Sidecars

SQLite opens three files *by name* beside the database: `-journal` (its hot-journal
probe reads it on every open, WAL mode included), `-wal` and `-shm`. So whoever can
create a name in `data/events/` chooses what the store's own open touches.
`EventStore.open` therefore runs `refuse_unsafe_sidecars` before `sqlite3.connect`:
each name must be absent, or a regular file with exactly one link. Size and content
are not checked, because a live writer legitimately leaves a non-empty `-wal` and a
`-shm` behind. `scripts/run_backup.py` keeps its own `_sidecar_problem` with the same
rule, because its take reads the live store through `sqlite3.connect` rather than
`EventStore.open`; it runs before the take and in both verifiers, and names every
offending sidecar rather than the first. A security test pins that the two cover the
same names.

What happened before the check, measured through the collector, the pipeline,
retention, the backup take, both backup verifiers and the SLI reporter, on the tree
before either this check or the backup CLI's own (#255) existed. The SLI
reporter's exit code reflects all of its objectives, so its rows below describe what
happened to the files rather than an exit code.

| Planted beside `events.sqlite3` | Before | After |
|---|---|---|
| FIFO `-journal` | Hung inside SQLite's open (collector, pipeline, retention, take, SLI). The four with a lock held it, so every later pass printed "skipped" at exit 0. | Exit 1, `StoreSidecarError` naming the file |
| `-shm` hard-linked to another file | The other file was truncated and rewritten as 32 KiB of WAL index by every one of them. All but the SLI reporter exited 0, `--verify` reporting every digest matching. | Exit 1, nothing written |
| `-wal` hard-linked to another file | Overwritten with WAL frames by the collector, the take (both exit 0) and the SLI reporter. The pipeline and retention deleted the name. | Exit 1, nothing written |
| FIFO `-wal` | Deleted by every CLI without a verifier check, at exit 0 from the pipeline, retention and the take | Exit 1, left in place |
| Symlink or FIFO `-shm` | A bare SQLite error in place of the output | Exit 1, `StoreSidecarError` |
| Directory `-shm` | Exit 0 from the pipeline, retention, the take and both verifiers | Exit 1, `StoreSidecarError` |

**If you see the refusal.** None of these is something SQLite creates. Stop the
timers so nothing holds the store open, then find out how the file got there before
you remove it. A FIFO, socket, device, directory or symlink can be deleted, and SQLite
recreates its sidecars. A hard link means a second name shares the inode, often a
hard-link snapshot of `data/` (`cp -al`, `rsync --link-dest`). `find / -xdev -samefile
<sidecar>` names the other one. Removing the sidecar's name unlinks it from the store
and leaves the other copy intact. For a non-empty `-wal`, take a copy first: it can
hold frames that were never checkpointed.

**What it does not close.** The check and SQLite's open are separate syscalls, and
SQLite recreates its sidecars later. Winning that race needs write access to
`data/events/`, which the store keeps at `0o700`, and with that access the database
itself can be rewritten. This catches a sidecar that is already wrong at open. The
database file itself is not link-checked; `store.paths.confine` refuses a symlink
there, but not a hard link or a FIFO.

## Attesting what is held

`attest()` returns the row counts, a sha256 over every `event_id` in sorted order, the
high-water mark and the schema version. It exists because content addressing answers a
different question than it looks like it answers: it proves each row is what was written,
and proves nothing about whether all of them are there. Deleting 100 of 400 rows leaves
`PRAGMA integrity_check`, `count()`, `query()` and `high_water_mark()` all silent, so a
truncated copy is indistinguishable from a store that legitimately holds fewer events —
which is the one thing a restore has to be able to tell. `scripts/run_backup.py` records an
attestation in every backup manifest and `--verify` re-checks it; the runbook is
`docs/RESTORE.md`.

It is not a tamper control. Anyone who can rewrite rows can recompute a digest over them —
`UPDATE` is trigger-refused and the audit chain is the tamper evidence. What this catches is
*loss*.

## What is not here

No collection — nothing in this package fetches or listens for telemetry; a
caller hands it events. No correlation; that is `correlation/` (planned,
XDR-2). No access control; the store is a file, and who may read it is the
filesystem's business until the platform has a caller identity at all.

See `DESIGN.md` §5 boundary 10 for the trust argument and
`docs/PRODUCTION_SOC_PLAN.md` for where this sits in the program.
