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
| **Ordered under one lock** | An append takes the write lock (`BEGIN IMMEDIATE`) before it reads the high-water mark, so the ordering check and the insert are one decision. A second writer gets `SQLITE_BUSY` and retries, rather than committing between them and leaving a row behind one already stored. |
| **Tamper-evident** | Every row is re-hashed on read; a projection that does not match its `event_id` raises `StoreIntegrityError`. That refusal names the stored id only when it is a lowercase sha256 hex digest, the shape every write gives it, and otherwise gives its type and length, since `sli` copies the message into the report an operator records. So does one that matches and still will not rebuild (a field past its bound), chained from the reader's `MalformedProjectionError`, since `event_id` is an unkeyed hash and a match does not prove which build wrote the row. So does an `ingested_at` that is not a finite number: that column is outside the hash, and no write path stores text, bytes or an infinity in it. So does a high-water mark that is not a finite number, stored or derived: a `nan` mark compared false against every stamp and silently disabled the ordering control. So does a stored mark below the newest stored `ingested_at`, which no write leaves. So does any TEXT that is not valid UTF-8, in any column, with a message that gives its length and never its bytes. |
| **No ambient clock** | `ingested_at` is a required keyword argument. The store never asks the host what time it is. |
| **Contained** | The database lives under gitignored `data/events/`. A filename with a separator, a traversal, or a leading dot is refused. |
| **No hostile database file** | Before SQLite opens it, `events.sqlite3` itself must be absent (a fresh root, which then creates it) or a regular file with one link (`lstat`, never followed). Anything else raises `StoreFileError`. See [The database file itself](#the-database-file-itself). |
| **No hostile sidecar** | Before SQLite opens the database, each `-journal`, `-wal` and `-shm` beside it must be absent or a regular file with one link (`lstat`, never followed). Anything else raises `StoreSidecarError`, a `StoreFileError` subclass. See [Sidecars](#sidecars). |
| **Bounded** | Projections over 64 KiB are refused; every query is clamped to 10,000 rows, and a `limit` that is not an integer raises `TypeError`, a `bool` included. |
| **Versioned** | A database written by another schema version is refused, never implicitly migrated. The refusal names the recorded version only when it has the shape a build writes (one to nine ASCII digits), and otherwise gives its type and length, since `sli` copies the message into the report an operator records. |
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

`Query` filters AND together. Unset means unfiltered. A time bound (`since`, `until`,
`ingested_from`, or either keyset pair's timestamp) that is not a finite number raises
`ValueError`, and one that is not a number raises `TypeError`; leave a side unset to leave it
unbounded. A NaN bound used to return no rows with no error, which reads as a quiet period.

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
<sidecar>` names the other one. **Never remove a live `-wal` or `-journal` name**: it can
hold committed events that were never checkpointed, and measured, copying a hard-linked
`-wal` aside and then removing its name dropped 20 of 32 committed events from the store.
With nothing holding the store open, give the name a private copy instead and keep the
linked one: `cp -p <sidecar> <sidecar>.new && mv <sidecar> <a directory outside the
root>/ && mv <sidecar>.new <sidecar>` (measured: all 32 kept). A `-shm` holds no events and
can be moved out once nothing holds the store open. `docs/RESTORE.md`, the sidecar-link
row of "Verifying a restore", has the full sequence and why quiescing comes first.

### The database file itself

The same rule, applied by `refuse_unsafe_database` to the one file the sidecar check
did not state. `store.paths.confine` refuses a symlink at `events.sqlite3` and nothing
else, so until this check a hard link or a FIFO there reached SQLite. `EventStore.open`
runs it first, before the sidecars and before `sqlite3.connect`: the file must be
absent (a fresh root, which the open then creates) or a regular file with exactly one
link. `scripts/run_backup.py` calls the same function rather than keeping a copy,
before its take's own `sqlite3.connect` and in both verifiers, and reports the store's
own `problem` beside its other findings.

Measured through the same seven CLIs on the tree before the check (`9ff3604`), run
both as root and as an account the kernel applies file modes to. A test run as root
cannot see the hang: root is never refused the read-write open.

| At `events.sqlite3` | Before | After |
|---|---|---|
| Hard link, second name outside `data/` (a `cp -al` snapshot) | The collector wrote through it: the other name grew 4 KiB with a new digest, at exit 0. The pipeline, retention, the take and both verifiers changed nothing and exited 0 over it, so a restore made with `cp -al` would have verified clean | Exit 1 from all seven, `has 2 hard links`, neither name changed |
| A 0-byte file outside `data/`, hard-linked in | Initialised in place as a store, 0 -> 61440 bytes and 0o644 -> 0o600, by the collector, the pipeline and retention (all exit 0) and by the SLI reporter | Exit 1 from all seven, `has 2 hard links`, the file left at 0 bytes and 0o644 |
| A non-SQLite file, hard-linked in | Exit 1 from all seven: SQLite's "file is not a database" after it had opened the file, or the verifiers' header check | Exit 1, `has 2 hard links`, before it is opened |
| FIFO read-only to the running account: its own at 0o400, or another account's at 0o644 (what `sudo mkfifo` leaves) | The collector, the pipeline and retention hung inside SQLite's open, which retries read-only after `EACCES`. Each held its lock, so a second pass printed "skipped" at exit 0 | Exit 1, `is not a regular file (a FIFO)` |
| FIFO the account can write, or any FIFO as root | A bare "disk I/O error" from the same three (`pread` on a pipe fails), exit 1 | Exit 1, `is not a regular file (a FIFO)` |
| FIFO, under the take, `--verify` and `--verify-restore` | Read as absent: "no event store", "is missing", "no store at …", exit 1 | Exit 1, `is not a regular file (a FIFO)` |
| Directory or socket (measured through `EventStore.open`) | A bare "unable to open database file" | `StoreFileError`, `is not a regular file` |

**If you see the refusal.** Stop the timers first, so nothing holds the store open. A
FIFO, socket or directory at the store path is never something SQLite creates: find
out how it got there before you remove it, then restore the store from a backup
(`docs/RESTORE.md`). A hard link means another name shares the store's file;
`find / -xdev -samefile data/events/events.sqlite3` names it. There are two ways out,
and `tests/security/test_store_database_file.py` exercises both:

* If you do not need the other name (a stale snapshot), delete **that** name. The store
  keeps its content and is back to one link.
* If you need to keep it, give the store an inode of its own. From `data/events/`, run
  `cp -p events.sqlite3 events.sqlite3.unlinked && mv events.sqlite3.unlinked
  events.sqlite3`. The other name keeps the content it had at that moment, and nothing
  the store does reaches it again.

Neither is right for a name you cannot explain. That is the tampering case, and the
store's content is evidence about how it happened, so take a copy first.

**What it does not close.** The checks and SQLite's open are separate syscalls. SQLite
cannot be handed a descriptor that was checked, and it recreates its sidecars later.
Winning that race needs write access to `data/events/`, which the store keeps at
`0o700`, and with that access the database itself can be rewritten. This catches a
database or a sidecar that is already wrong at open. The SLI reporter's guard is a
single `lstat`: only absence reads as "no event store", a FIFO, directory or socket at
the store path reaches this check and is named (`StoreFileError`, every store indicator
`UNKNOWN`), and any other `lstat` error reads "cannot be checked". It creates nothing.

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

An `event_id` it cannot digest is still refused as a `StoreError`. Every id this store writes
is a sha256 hex digest, so an id that is not ASCII was written outside the platform, and
`attest()` raises `StoreIntegrityError` giving its length and never the id.

## What is not here

No collection — nothing in this package fetches or listens for telemetry; a
caller hands it events. No correlation; that is `correlation/` (planned,
XDR-2). No access control; the store is a file, and who may read it is the
filesystem's business until the platform has a caller identity at all.

See `DESIGN.md` §5 boundary 10 for the trust argument and
`docs/PRODUCTION_SOC_PLAN.md` for where this sits in the program.
