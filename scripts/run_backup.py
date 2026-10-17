#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Take a verifiable copy of the lab-data state, and verify one afterwards.

Nothing in this repository backed up anything. Every irreplaceable artifact
the platform produces — the event store, the hash-chained audit logs, the
compliance evidence trail, the incident reports — lived in exactly one place
on one node, and ``docs/PRODUCTION_SOC_PLAN.md`` said so honestly. This is the
mechanism; ``docs/RESTORE.md`` is the procedure.

**The naive backup is worse than none, and that is measured.** While a writer
holds the store open, the main ``.sqlite3`` file carried 4 KiB of a 548 KiB
database and the rest sat in the ``-wal`` sidecar. A copy of the main file
alone passes ``PRAGMA integrity_check``, opens through ``EventStore.open()``
without raising, and reports a plausible count — 353 of 400 events in one
measurement — so a partial loss is indistinguishable from a store that
legitimately holds fewer events. So this does not copy the file. It uses
SQLite's online backup API (``sqlite3.Connection.backup``, standard library),
which is correct under concurrent writes whatever the WAL contains, and then
**attests the copy it made** rather than the source it read.

**Completeness is attested, because nothing else attests it.** Content
addressing proves each row is what was written and says nothing about whether
all the rows are there: deleting 100 of 400 rows leaves ``integrity_check``,
``count()``, ``query()`` and ``high_water_mark()`` all silent.
:meth:`store.EventStore.attest` digests every ``event_id`` in sorted order
together with the row count, and the manifest carries that digest so a restore
can be *verified* instead of merely performed.

**Positions are deliberately not backed up.** ``data/collect/offsets.json``
and ``data/pipeline/cursor.json`` are excluded by construction, because of an
asymmetry that was measured in all four directions: a restored *cursor* is
safe either way (behind it re-correlates, ahead of it merely idles, since
``next_stamp`` reads the current clock), but **offsets newer than the store
are unrecoverable**. With offsets restored and the store lost, the collector
reports ``events_stored: 0, lines_read: 0, offsets_advancing: true`` and exits
0 while every line still sits unread in the source — permanent, silent, total
loss. Discarding both positions is a complete recovery: re-collection re-reads
the sources and content addressing drops what is already stored, measured at
600 of 600 events with zero duplication. A backup that cannot restore a
position cannot restore a bad one.

**Gated ``read_only``, and that is the honest class — with one measured
qualification.** No event content changes, nothing is deleted, no network is
reached, and a destination outside the lab-data root is refused. What it does
do is make a *second copy of sensitive evidence*, so the copy is written
owner-only inside the same gitignored root, and a destination off this node
would be an ``external_network`` gate under AGENTS.md §5.1 — which egress has
twice been refused. That is a deployment decision for an operator, not
something this script reaches for.

The qualification: an earlier version of this paragraph said the script
"writes no live file", and at the filesystem level that is false in exactly
the case a backup is most likely to be taken in. Measured, both
configurations:

* after a writer **exits normally**, its own ``close()`` has already
  checkpointed, so no ``-wal`` exists and the source is untouched — before and
  after are byte-identical and the mtime does not move;
* after a writer is **killed** (leaving a hot WAL — a crashed collector, an
  OOM, a pulled plug), SQLite checkpoints on last-connection close: the main
  file grew from 4 KiB to 60 KiB, its mtime changed, and ``-wal`` and
  ``-shm`` were **removed**.

The second case is wider than "no live writer", measured over four
configurations: an *idle* extra connection does not prevent the checkpoint,
and nor does one that has only run a statement touching no table. What
prevents it is another connection having actually joined the WAL by reading
WAL-backed data — a dashboard mid-query, say.

No committed data is lost — a checkpoint moves already-durable WAL frames into
the main file, and the copy is correct either way — so the action *class* is
unchanged. But the sentence was wrong, and ``tests/integration`` now pins the
post-crash behaviour so the corrected claim cannot drift back. (The reverse
case already had a test: a backup taken while a writer holds the store open
writes nothing to the source, because the backup is then not the last
connection.)

**Two verifications, at opposite ends of a restore.** ``--verify`` checks a
backup against its own manifest *before* you trust it. ``--verify-restore``
checks the live ``--root`` *after* step 4 of ``docs/RESTORE.md`` has copied
that backup into place — the promotion gate, and the half that was missing:
step 4 is a bare ``cp -a`` and nothing looked at the result. The asymmetry
matters because a store missing most of its pages **opens cleanly and reports
a plausible count** (353 of 400 events, measured in
``tests/integration/test_restore_drill.py``), so a half-finished copy leaves a
working SOC quietly short of evidence. See :func:`_verify_restore` for what it
compares and, more importantly, for what a green verdict does **not** say — it
speaks about the copy and says nothing about whether exactly one node is
active.

**Exit codes**, the whole interface a scheduler sees: ``0`` a backup was taken
or verified (including a skip because another pass held the lock), ``1`` the
backup, either verification or the audit write failed — including any mismatch
found by ``--verify`` or ``--verify-restore``, ``2`` bad arguments or the
single-instance lock could not be taken, ``3`` blocked by policy, ``4``
retryable contention — another writer held the
store's write lock, so no backup was taken and nothing was left behind. Retry
rather than page; see ``scripts/_exit_codes.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.audit import (  # noqa: E402
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    signing_key_from_env,
    verifier_from_env,
)
from agents.policies.bundle import (  # noqa: E402
    DEFAULT_BUNDLE_PATH,
    PolicyBundleError,
    load_bundle,
)
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from scripts._exit_codes import EXIT_RETRYABLE, is_retryable_contention  # noqa: E402
from scripts._locking import (  # noqa: E402
    DIR_MODE,
    FILE_MODE,
    LockUnavailableError,
    prepare_lock,
    single_instance,
)
from store import DEFAULT_FILENAME, EVENTS_SUBDIR, EventStore, StoreError  # noqa: E402
from store.paths import confine, validated_root  # noqa: E402

#: Where backups live: a sibling of the state they copy, inside the same
#: gitignored root, so a backup can never be the thing that commits evidence.
BACKUP_SUBDIR = Path("data") / "backups"
LOCK_FILE = "backup.lock"
MANIFEST_FILE = "manifest.json"
#: The audit chain this CLI appends to. Beside the store it copies, like
#: retention's, so one chain covers everything that touches the event store.
AUDIT_SUBDIR = EVENTS_SUBDIR
AUDIT_FILE = "audit.log"


ACTION_NAME = "backup_state"
#: Nothing existing is changed. See the module docstring on why a local copy
#: of evidence is ``read_only`` and an off-node one would not be.
BACKUP_CLASS: ActionClass = "read_only"

#: State that is copied, relative to the lab-data root. Declared rather than
#: discovered: a backup that walked the tree would eventually copy a lock, a
#: position file, or something a later stage put there for its own reasons.
COPIED_FILES: tuple[Path, ...] = (
    Path("data") / "collect" / "audit.log",
    Path("data") / "events" / "audit.log",
    Path("data") / "pipeline" / "audit.log",
    Path("data") / "compliance" / "audit.log",
    Path("data") / "compliance" / "evidence.jsonl",
)

#: Directories whose every file is copied, relative to the root.
COPIED_TREES: tuple[Path, ...] = (Path("data") / "reports",)

#: The hash chains among the copied files, verified at backup time so a torn
#: or truncated capture is recorded as such instead of being discovered during
#: an incident. Note an unsigned chain cannot detect *end* truncation — set
#: ``AUDIT_HMAC_KEY`` and the head signature does.
CHAIN_FILES: tuple[Path, ...] = COPIED_FILES[:4]

#: Never copied, and the reason is load-bearing. See the module docstring.
EXCLUDED: dict[str, str] = {
    "data/collect/offsets.json": (
        "offsets newer than the store are the one unrecoverable skew: the "
        "collector reports success and reads nothing while the source still "
        "holds every line. Discarding them is a complete recovery."
    ),
    "data/pipeline/cursor.json": (
        "a cursor is safe to discard — re-correlating is at-least-once by "
        "design — and restoring one is never necessary, so it is not kept."
    ),
}


def _unsafe_path(base: Path, relative: Path, *, what: str) -> str | None:
    """Why ``base/relative`` must not be touched, or ``None`` if it is safe.

    Two call sites, one rule, because both handle paths this process did not
    choose: the source tree can hold anything an operator or an agent put
    there, and a manifest is *data inside the artifact being verified* — a
    backup directory is documented as safe to move as a unit, so its contents
    are untrusted input on the way back in.

    Joining is not confinement. ``Path("/a") / "/etc/hostname"`` is
    ``/etc/hostname``, because pathlib discards the left side for an absolute
    right side, and ``..`` walks out. Measured on the first version of this
    script: a manifest naming ``/etc/hostname`` made ``--verify`` stat and
    sha256 that file and print the real digest in its failure report — an
    arbitrary-read oracle for anything the account can read. Separately,
    ``Path.is_file()`` follows symlinks and so does ``shutil.copy2``, so a
    symlink in ``data/reports/`` copied a file from outside the lab root into
    the backup as a regular file, at exit 0.

    Every component is checked, not only the leaf, because a symlinked
    *directory* escapes just as well — the reasoning
    ``store/paths.py::confine`` already applies, in the shape it does not
    cover.
    """
    if relative.is_absolute():
        return f"{what} {relative} is absolute; it must be relative to its root"
    if any(part in {"..", ""} for part in relative.parts):
        return f"{what} {relative} contains a traversal component"
    walked = base
    for part in relative.parts:
        walked = walked / part
        if walked.is_symlink():
            return (
                f"{what} {relative} passes through the symlink {walked} "
                f"(-> {walked.readlink()}); refusing to follow it out of the root"
            )
    # Defence in depth, and deliberately not test-covered: given the two
    # checks above — no absolute path, no `..`, no symlinked component — a
    # relative path cannot resolve outside its base, so four plants could not
    # make this line the one that fires. It is kept for the window the walk
    # cannot close (a link created between the check and the read, which
    # AGENTS.md §5 already records as unwinnable for `collect/`) and against a
    # future edit loosening one of the checks above it. Claiming a test proves
    # it would be the overstatement this file exists to avoid.
    resolved = (base / relative).resolve()
    if not resolved.is_relative_to(base.resolve()):
        return f"{what} {relative} resolves to {resolved}, outside {base}"
    return None


def _narrow_tree(root: Path) -> None:
    """Make every directory and file under ``root`` owner-only.

    A final sweep rather than a mode on each ``mkdir``, because
    ``mkdir(mode=…, parents=True)`` applies the mode to the **leaf only** and
    is a no-op on a directory that already exists — which left this script's
    own intermediate ``data/`` at the process umask (measured 0o755) on its
    first run, exactly the way it leaves the platform's. One sweep at the end
    cannot be forgotten by a later copy step.
    """
    root.chmod(DIR_MODE)
    for child in sorted(root.rglob("*")):
        child.chmod(DIR_MODE if child.is_dir() else FILE_MODE)


def _digest_file(path: Path) -> str:
    """sha256 of a file, read in blocks so a large chain costs no memory."""
    running = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            running.update(block)
    return running.hexdigest()


def _digest_prefix(path: Path, length: int) -> str:
    """sha256 of the FIRST ``length`` bytes of a file.

    The right comparison for an append-only artifact. A restored audit chain
    or evidence trail legitimately grows the moment anything runs — including
    this very verification, whose gate decision appends to
    ``data/events/audit.log`` before the check reads it — so byte equality
    against the manifest is the wrong property and would fail on a correct
    restore. "The backed-up content is a *prefix* of what is there now" is the
    property that actually matters: it fails on truncation and on any rewrite
    of history, and passes on honest growth.
    """
    running = hashlib.sha256()
    remaining = length
    with path.open("rb") as handle:
        while remaining > 0:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                break
            remaining -= len(block)
            running.update(block)
    return running.hexdigest()


def _copy_database(source: Path, target: Path) -> None:
    """Copy a live SQLite database correctly, whatever its WAL holds.

    ``sqlite3.Connection.backup`` is the online backup API: it copies pages
    under a read lock and restarts if a writer commits underneath it, so the
    result is a consistent snapshot without quiescing the writer and without
    the caller having to reason about ``-wal`` and ``-shm`` at all. A
    ``shutil.copy2`` of the main file is only valid when the WAL happens to be
    checkpointed, which is true between one-shot runs and false during one —
    and the failure is silent, which is why this does not do it.
    """
    with (
        contextlib.closing(sqlite3.connect(source)) as live,
        contextlib.closing(sqlite3.connect(target)) as copy,
    ):
        live.backup(copy)


def _is_append_only(relative: Path) -> bool:
    """Does this manifest entry name a stream that may legitimately GROW?

    Prefix comparison is right for an append-only artifact and wrong for
    everything else, and review found the two conflated: a report whose live
    copy held the backed-up bytes **followed by anything at all** passed
    ``_digest_prefix`` and produced a green promotion verdict. Measured on
    merged code — a 40-byte declared report, 94 bytes live with 54 appended,
    exit 0; and the same with 512 NUL bytes appended instead of prose, also
    exit 0.

    **The allow-list is for the prefix-compared side, not the strict side**, so
    the default is exact equality. A tree added to :data:`COPIED_TREES` later
    gets the strict comparison without anyone remembering to ask for it, which
    is the fail-closed direction: granting growth to something that cannot
    legitimately grow hides a rewrite, while demanding equality of something
    that does grow produces a loud, obvious finding an operator can read.

    Append-only means the four hash chains in :data:`COPIED_FILES`, the
    evidence stream beside them, and their rotation siblings — ``audit.log.1``,
    a checkpoint, a head signature — which is the same rule
    :func:`_copied_paths` uses to pick them up, expressed once so the backup
    side and the verify side cannot disagree about what may grow.

    ``data/reports/`` is not append-only: a report is rewritten whole, and
    within the step-4-to-step-5 window of :func:`_verify_restore` nothing
    writes one at all.
    """
    if relative in COPIED_FILES:
        return True
    return any(
        relative.parent == declared.parent and relative.name.startswith(declared.name)
        for declared in COPIED_FILES
    )


def _live_tree_inventory(root: Path) -> tuple[list[Path], list[str]]:
    """Every file presently in the copied trees, plus any tree root that is unsafe.

    The reverse of :func:`_copied_paths`' tree walk, and it exists because
    verification used to read the manifest in one direction only. See
    :func:`_verify_restore`'s ``UNDECLARED`` finding.

    **A symlinked tree root is reported, never skipped**, and review found the
    first version skipping it. That ``continue`` was lifted from
    :func:`_copied_paths`, where skipping is correct — a backup must not copy
    *through* a link and pull content from outside the lab root in. Here the
    direction is reversed and so is the right behaviour: the link is already in
    the live root, and ignoring it is how it survives a restore.

    Measured on the first version: a backup that declared **no** reports,
    restored over a root whose ``data/reports`` is a symlink to a directory
    outside the root, exited ``0``. No manifest report entries meant
    :func:`_unsafe_path` never ran; the symlinked root meant this walk skipped
    it; and ``dashboard/app.py`` reads that path, so a planted file claiming
    "Correlated 9000 events" would have been presented as this node's report.
    Two guards exist for exactly this and each declined it for a different
    reason, which is why the gap was invisible.
    """
    found: list[Path] = []
    unsafe: list[str] = []
    for tree in COPIED_TREES:
        base = root / tree
        if base.is_symlink():
            unsafe.append(
                f"UNDECLARED: {tree} in the live root is a symlink to "
                f"{str(base.readlink())!r}. No backup carries one, and "
                "`dashboard/app.py` reads this path — so whatever it points at would be "
                "presented as this node's reports. Remove the link and restore the real "
                "directory"
            )
            continue
        if not base.is_dir():
            continue
        found.extend(sorted(child.relative_to(root) for child in base.iterdir() if child.is_file()))
    return found, unsafe


def _copied_paths(root: Path) -> tuple[list[Path], list[str]]:
    """Declared files that exist and are safe to read, plus what was refused.

    Refused rather than silently skipped, and skipped rather than fatal. A
    symlink is not copied — ``shutil.copy2`` would follow it and pull content
    from outside the lab root into the backup — but one planted file must not
    stop every backup either, so the pass proceeds and both the manifest and
    the report name what was left out. Silently omitting evidence an operator
    believes is covered is the blind spot this project keeps finding; naming
    it is the control.
    """
    candidates = list(COPIED_FILES)
    for tree in COPIED_TREES:
        base = root / tree
        if base.is_dir() and not base.is_symlink():
            candidates.extend(sorted(child.relative_to(root) for child in base.iterdir()))
    # Rotated archives, checkpoints and head signatures sit beside their
    # chain; they are part of the same evidence and are copied with it.
    for relative in COPIED_FILES:
        parent = (root / relative).parent
        if not parent.is_dir() or parent.is_symlink():
            continue
        stem = relative.name
        candidates.extend(
            sorted(
                child.relative_to(root)
                for child in parent.iterdir()
                if child.name != stem and child.name.startswith(stem)
            )
        )

    found: list[Path] = []
    refused: list[str] = []
    for relative in sorted(set(candidates)):
        reason = _unsafe_path(root, relative, what="source")
        if reason is not None:
            refused.append(reason)
            continue
        # `is_file()` only after the symlink check, because it follows them.
        if (root / relative).is_file():
            found.append(relative)
    return found, sorted(refused)


def _verify_chains(root: Path) -> dict[str, object]:
    """Verify each hash chain under ``root``, naming what is missing.

    A chain that is absent is reported as absent, never as intact: a monitor
    pointed at a missing path must not stay green, which is the contract
    ``scripts/audit_verify.py`` already states and the one place in this
    repository that forgets it (``scripts/audit_maintenance.py``) is recorded
    as a defect rather than copied here.
    """
    # ``verifier_from_env`` rather than ``signing_key_from_env``: this reads a
    # chain, so it must resolve what ``scripts.audit_verify`` resolves. It did
    # not, and the docstring above claims it follows that contract — on an
    # Ed25519 deployment (the scheme whose point is that a verifier holds only
    # the public key) no signer was configured, the head signature came back
    # ``unsigned``, and a stale or forged one was recorded here as ``intact``.
    # The writer below keeps ``signing_key_from_env``, because a verifier
    # cannot sign.
    chains: dict[str, object] = {}
    verifier = verifier_from_env()
    for relative in CHAIN_FILES:
        path = root / relative
        logger = AuditLogger(path, signer=verifier)
        if not logger.exists():
            chains[str(relative)] = {"present": False}
            continue
        report = logger.verify_report()
        chains[str(relative)] = {
            "present": True,
            "intact": bool(report.intact),
            "entries": int(report.entries),
            "signature": str(report.signature),
            "failure": report.failure,
        }
    return chains


def _take_backup(root: Path, destination: Path) -> dict[str, object]:
    """Copy the declared state into ``destination`` and attest what landed.

    The destination mirrors the root's own layout (``data/events/…``), so a
    restore is a plain directory copy and no tool has to know a second shape —
    and so ``EventStore.open(destination)`` and :func:`_verify_chains` work on
    a backup unchanged, which is what makes verification cheap.
    """
    unsafe = _unsafe_path(root, EVENTS_SUBDIR / DEFAULT_FILENAME, what="event store")
    if unsafe is not None:
        # The one source that is fatal rather than skipped: a backup with no
        # store restores as an empty store nothing can distinguish from a
        # real one, so there is no safe way to proceed without it.
        raise StoreError(unsafe)
    source_db = root / EVENTS_SUBDIR / DEFAULT_FILENAME
    if not source_db.is_file():
        raise StoreError(
            f"no event store at {source_db}; refusing to write a backup that "
            "would restore as an empty store indistinguishable from a real one"
        )

    destination.mkdir(mode=DIR_MODE, parents=True, exist_ok=False)
    destination.chmod(DIR_MODE)

    target_db = destination / EVENTS_SUBDIR / DEFAULT_FILENAME
    target_db.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    target_db.parent.chmod(DIR_MODE)
    _copy_database(source_db, target_db)
    target_db.chmod(FILE_MODE)

    files: list[dict[str, object]] = []
    copied, refused = _copied_paths(root)
    for relative in copied:
        target = destination / relative
        target.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        target.parent.chmod(DIR_MODE)
        shutil.copy2(root / relative, target)
        target.chmod(FILE_MODE)
        files.append(
            {
                "path": str(relative),
                "size": target.stat().st_size,
                "sha256": _digest_file(target),
            }
        )

    # The copy is attested, never the source: attesting the source would
    # describe a database that has since moved on, and the thing a restore
    # needs to check is the copy.
    with EventStore.open(destination) as copy:
        attestation = copy.attest()

    # Every directory this backup created, not just the leaves.
    _narrow_tree(destination)

    return {
        "format": "ianua.backup.v1",
        "taken_at": datetime.now(UTC).isoformat(),
        "store": {
            "path": str(EVENTS_SUBDIR / DEFAULT_FILENAME),
            "size": target_db.stat().st_size,
            "sha256": _digest_file(target_db),
            "attestation": attestation.to_dict(),
        },
        "files": files,
        "chains": _verify_chains(destination),
        "excluded": dict(EXCLUDED),
        # Named in the artifact, not only in the run's output, because
        # whoever restores this is not whoever took it.
        "refused": refused,
    }


#: The one path :func:`_take_backup` writes the store to, and so the only one
#: a manifest may name. See :func:`_load_manifest`.
_STORE_PATH = str(EVENTS_SUBDIR / DEFAULT_FILENAME)


def _is_count(value: object) -> bool:
    """A non-negative ``int`` that is not a ``bool`` (an ``int`` subclass)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _malformed(directory: Path, what: str) -> StoreError:
    """The refusal for a manifest whose shape cannot be verified against."""
    return StoreError(
        f"{MANIFEST_FILE} in {directory}: {what}; refusing to verify against a "
        "damaged or edited manifest"
    )


def _load_manifest(directory: Path) -> dict[str, Any]:
    """Read ``directory``'s manifest and check its **shape**, or raise ``StoreError``.

    A manifest is data inside the artifact being verified (see
    :func:`_unsafe_path`), and both verifiers used its fields as though they
    were well-formed. Measured through the CLI on the code this replaces: a
    JSON array, a string ``store``, a string ``files`` entry and a list
    ``chains`` each ended in a ``TypeError``/``AttributeError`` traceback under
    ``--verify`` and ``--verify-restore`` alike — exit 1 by accident, no message.

    **The sharper defect was a write.** A ``store.path`` naming any *other*
    existing file in the backup passed ``is_file()``, so :func:`_verify_backup`
    went on to ``EventStore.open(directory)`` — which ``mkdir``s and
    ``connect``s — and **created** ``data/events/events.sqlite3`` inside the
    backup under inspection (measured). That is the hazard
    :func:`_verify_restore` already guards against, so ``store.path`` must be
    the one path :func:`_take_backup` writes. Shape only: every digest, size
    and count is still compared by the callers, and the escape checks still run.
    """
    manifest_path = directory / MANIFEST_FILE
    if not manifest_path.is_file():
        raise StoreError(f"no {MANIFEST_FILE} in {directory}; this is not a backup")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError; RecursionError
        # is json's own — measured, 100,000 nested `[` was a traceback in both modes.
        raise _malformed(directory, f"cannot be decoded as JSON ({type(exc).__name__})") from exc
    if not isinstance(manifest, dict):
        raise _malformed(directory, "not a JSON object")
    if manifest.get("format") != "ianua.backup.v1":
        # Capped: the repr of a 2 MB format string was 2,000,032 bytes of stderr.
        raise _malformed(directory, f"unknown format {str(manifest.get('format'))[:80]!r}")
    store_entry = manifest.get("store")
    if not isinstance(store_entry, dict):
        raise _malformed(directory, "'store' is not an object")
    if store_entry.get("path") != _STORE_PATH:
        raise _malformed(
            directory,
            f"store path {store_entry.get('path')!r} is not {_STORE_PATH!r}, the only path "
            "a backup writes",
        )
    attestation = store_entry.get("attestation")
    if not isinstance(store_entry.get("sha256"), str) or not isinstance(attestation, dict):
        raise _malformed(directory, "store sha256 must be a string and attestation an object")
    if not _is_count(attestation.get("events")) or not isinstance(attestation.get("digest"), str):
        raise _malformed(directory, "attestation must carry an integer events and a string digest")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise _malformed(directory, "'files' is not a list")
    for entry in files:
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("path"), str)
            and isinstance(entry.get("sha256"), str)
            and _is_count(entry.get("size"))
        ):
            raise _malformed(
                directory,
                f"file entry {str(entry)[:80]!r} needs a string path, a string sha256 and an "
                "integer size",
            )
    chains = manifest.get("chains")
    if not isinstance(chains, dict):
        raise _malformed(directory, "'chains' is not an object")
    for relative in CHAIN_FILES:
        # A backup records a verdict for every chain, so an absent or non-object
        # one is an edit — and both verifiers used to `continue` past it, which
        # let removing a chain's record (or `chains: {}`) silence the one check
        # made independently of the manifest: measured, exit 0 over intact=False.
        recorded = chains.get(str(relative))
        if not (
            isinstance(recorded, dict)
            and isinstance(recorded.get("present"), bool)
            and (not recorded["present"] or _is_count(recorded.get("entries")))
        ):
            raise _malformed(
                directory,
                f"chains[{str(relative)!r}] must record a boolean present and, when "
                "present, an integer entries",
            )
    return manifest


#: SQLite's file header begins with this magic; bytes 18 and 19 are the write
#: and read format versions, both ``2`` for a WAL-mode database.
_SQLITE_MAGIC = b"SQLite format 3\x00"


def _unsafe_to_open(db: Path, *, what: str) -> str | None:
    """Why ``EventStore.open`` must not be handed ``db``, or ``None`` if it may be.

    ``EventStore.open`` is the store's only constructor and it **initialises**:
    it sets ``journal_mode=WAL``, applies the schema to any file without a
    ``meta`` table, and on close checkpoints whatever ``-wal`` sits beside the
    file. Right for the collector; a write for a verifier. Measured through the
    CLI before this check, manifest untouched and the store at the canonical
    path: a 0-byte backup store (the module docstring's "truncated transfer")
    went 0 -> 61440 bytes with ``events``/``meta``/``observables`` created
    *inside the backup under inspection*, same inode, and a second ``--verify``
    then reported a different digest — the evidence that it was a truncated
    copy was gone; a foreign SQLite file holding one table gained the three
    and went 0o644 -> 0o600; a 0-byte file *outside* the backup, hard-linked
    to the store path (which :func:`_unsafe_path` cannot see), was initialised
    in place; a 0-byte **live** store under ``--verify-restore`` likewise; and
    a hot ``-wal`` planted beside an intact backup store was checkpointed into
    it at **exit 0**, "every file digest match the manifest", sha256 changed.

    So the facts ``open`` would act on are read first, without a connection
    that can write: size, the sidecar, the header bytes, and the schema
    catalogue through ``immutable=1``. Not ``mode=ro`` — measured, that left
    ``-wal`` and ``-shm`` behind in the backup after close; ``immutable=1``
    touched nothing. It ignores a WAL, which is why a non-empty one is refused
    on its own rather than read through. A reason is a reported problem and
    not a raise, so the rest of the report still runs.
    """
    size = db.stat().st_size
    if size == 0:
        return (
            f"{what} is 0 bytes, a truncated transfer; SQLite treats an empty file as a "
            "new database and opening it would initialise it, so it was not opened"
        )
    wal = db.with_name(db.name + "-wal")
    if wal.is_file() and wal.stat().st_size:
        return (
            f"{what} has a {wal.stat().st_size}-byte -wal beside it that was never "
            "checkpointed; opening it would checkpoint those frames into the file, so it "
            "was not opened"
        )
    with db.open("rb") as handle:
        head = handle.read(20)
    if head[:16] != _SQLITE_MAGIC:
        return f"{what} is not a SQLite database ({size} bytes)"
    if head[18:20] != b"\x02\x02":
        return (
            f"{what} is not in WAL mode (header bytes 18-19 are {head[18:20].hex()}); "
            "opening it would rewrite its header, so it was not opened"
        )
    try:
        with contextlib.closing(sqlite3.connect(f"{db.as_uri()}?immutable=1", uri=True)) as conn:
            schema = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
            ).fetchone()
    except sqlite3.DatabaseError as exc:
        return f"{what} cannot be read as a SQLite database: {exc}"
    if schema is None:
        return (
            f"{what} carries no event-store schema (no meta table); opening it would "
            "create one, so it was not opened"
        )
    return None


def _verify_backup(directory: Path) -> dict[str, object]:
    """Re-check a backup against its own manifest, and report every mismatch.

    Collects findings rather than raising on the first, because an operator
    deciding whether to restore from this copy needs to know everything that
    is wrong with it, not the first thing.

    **What this writes, stated exactly.** The *bytes* of every file it reads,
    the store included, are left as found — :func:`_unsafe_to_open` names the
    cases that used to be initialised in place. Two things still change under
    it: ``EventStore.open`` narrows the store and its directory to owner-only
    if a transfer left them wider (a mode change, in the direction
    :func:`_take_backup` writes), and the WAL sidecars it creates while open
    are removed on close. Content-neutral is the claim; metadata-neutral is not.
    """
    manifest = _load_manifest(directory)

    problems: list[str] = []

    store_entry = manifest["store"]
    unsafe = _unsafe_path(directory, Path(str(store_entry["path"])), what="manifest store path")
    if unsafe is not None:
        # A path that escapes is a tamper indicator, so it is reported rather
        # than followed — and reported as a problem rather than raised, so an
        # operator deciding whether to restore sees everything at once.
        problems.append(unsafe)
        store_entry = {**store_entry, "path": None}
    db = directory / str(store_entry["path"]) if store_entry["path"] else None
    if db is None:
        pass
    elif not db.is_file():
        problems.append(f"{store_entry['path']} is missing")
    else:
        actual = _digest_file(db)
        if actual != store_entry["sha256"]:
            problems.append(
                f"{store_entry['path']}: sha256 {actual} does not match the manifest's "
                f"{store_entry['sha256']}"
            )
        unopenable = _unsafe_to_open(db, what=str(store_entry["path"]))
        if unopenable is not None:
            problems.append(unopenable)
        else:
            with EventStore.open(directory) as copy:
                attested = copy.attest().to_dict()
            expected = store_entry["attestation"]
            for key in sorted(expected):
                if attested.get(key) != expected[key]:
                    problems.append(
                        f"store attestation {key}: {attested.get(key)!r} does not match "
                        f"the manifest's {expected[key]!r}"
                    )

    for entry in manifest["files"]:
        unsafe = _unsafe_path(directory, Path(str(entry["path"])), what="manifest path")
        if unsafe is not None:
            problems.append(unsafe)
            continue
        path = directory / str(entry["path"])
        if not path.is_file():
            problems.append(f"{entry['path']} is missing")
            continue
        if path.stat().st_size != entry["size"]:
            problems.append(f"{entry['path']}: size {path.stat().st_size} != {entry['size']}")
        actual = _digest_file(path)
        if actual != entry["sha256"]:
            problems.append(f"{entry['path']}: sha256 {actual} != {entry['sha256']}")

    # The chains are re-verified now, not trusted from the manifest: a chain
    # recorded intact at backup time and broken since is exactly what this is
    # for.
    chains = _verify_chains(directory)
    for name, state in sorted(chains.items()):
        if not isinstance(state, dict):
            continue
        recorded = manifest["chains"][name]  # shape-checked by _load_manifest
        if state.get("present") != recorded.get("present"):
            problems.append(
                f"{name}: present={state.get('present')!r} at backup time was "
                f"{recorded.get('present')!r}"
            )
        # Independent of the record on purpose: this is the one check the
        # manifest cannot answer, so nothing in the manifest may silence it.
        if state.get("present") and not state.get("intact"):
            problems.append(f"{name}: chain no longer verifies: {state.get('failure')}")

    return {
        "backup": str(directory),
        "taken_at": manifest.get("taken_at"),
        "events": manifest["store"]["attestation"]["events"],
        "verified": not problems,
        "problems": problems,
        "chains": chains,
    }


def _verify_restore(root: Path, backup: Path) -> dict[str, object]:
    """Verify the **live** ``root`` holds what ``backup``'s manifest attested.

    The promotion gate. ``--verify`` checks a backup against its own manifest
    *before* a restore; nothing checked the live tree *after* one, and
    ``docs/RESTORE.md`` step 4 is a bare ``cp -a``. That is the dangerous
    direction, measured: a store missing most of its pages **opens cleanly
    through** :meth:`store.EventStore.open` **and reports a plausible count** —
    353 of 400 events in ``tests/integration/test_restore_drill.py``. So an
    interrupted copy leaves a working SOC quietly missing evidence, at the one
    moment an operator is least able to notice.

    Structure cannot catch that, which is why this compares against the
    expectation the backup *carried* rather than checking that the database
    looks healthy. :meth:`store.EventStore.attest` gates on
    ``PRAGMA quick_check`` on the way, so the integrity read comes free.

    **What a green verdict does NOT say.** It speaks only about the copy. It
    says nothing about the fence — whether exactly one node is active. The
    only candidate fence clearing today's charter is operator-driven promotion,
    and the operator is the fence *only if they stopped the former active's
    timers*; that is procedural and this repository cannot check it. See
    ``DESIGN.md``'s active/passive decision row. Do not read "restore verified"
    as "safe to promote".

    **The window is narrow and the report says so rather than merely failing.**
    This is an exact comparison, so it is valid between ``docs/RESTORE.md``
    steps 4 and 5 — re-collection in step 5 legitimately adds events. Run late,
    an operator gets a mismatch; the findings below name the *direction*, so
    "you already re-collected" never reads the same as "evidence is missing".

    **Three things review found this gate was not checking, all of which the
    manifest already carried.** Each was measured on the merged code, each
    exited ``0``, and the fix in every case reads a field that was sitting in
    the file this function had just parsed:

    * ``observables`` was never compared. The digest covers the
      ``event_id`` set only, so losing every observable row left the count, the digest and
      ``quick_check`` all satisfied — 20 of 20 destroyed, exit ``0``.
    * Report entries were compared by *prefix*, so a report holding the
      backed-up bytes followed by anything at all passed. See
      :func:`_is_append_only`; reports are now exact, streams still prefix.
    * The manifest was walked in one direction only, so a report written after
      the backup — which step 4's ``cp -a`` *merges* rather than replaces —
      survived unseen. See :func:`_live_tree_inventory`.
    """
    manifest = _load_manifest(backup)

    problems: list[str] = []
    store_entry = manifest["store"]
    expected = store_entry["attestation"]
    live_events: int | None = None

    # The store. Existence is checked FIRST and deliberately: EventStore.open
    # CREATES the database if absent, so opening it blind would have this
    # verification manufacture an empty store and then report the loss of every
    # event — a read-only check that writes the thing it was asked to inspect.
    # And existence is not enough: an existing EMPTY file was created into
    # regardless (measured, 0 -> 61440 bytes with the schema), so whether
    # opening would write is checked next. See _unsafe_to_open.
    db = root / EVENTS_SUBDIR / DEFAULT_FILENAME
    if not db.is_file():
        problems.append(
            f"no store at {db}: the restore did not put one there, and this check will "
            "not create one to measure"
        )
    elif (unopenable := _unsafe_to_open(db, what=f"the live store {db}")) is not None:
        problems.append(unopenable)
    else:
        with EventStore.open(root) as live:
            attested = live.attest().to_dict()
        live_events = int(attested.get("events", -1))
        want_events = int(expected["events"])
        if live_events < want_events:
            problems.append(
                f"LOSS: the live store holds {live_events} event(s); the backup attested "
                f"{want_events}. {want_events - live_events} are missing. A partial copy "
                "opens cleanly and reports a plausible count, which is why this is checked "
                "against the manifest and not against the database looking healthy"
            )
        elif live_events > want_events:
            problems.append(
                f"ADDED: the live store holds {live_events} event(s); the backup attested "
                f"{want_events}. This is what docs/RESTORE.md step 5 (re-collect) does, so "
                "it is expected if you have already run it — this check belongs between "
                "steps 4 and 5. It is NOT evidence loss"
            )
        elif attested.get("digest") != expected["digest"]:
            problems.append(
                f"SUBSTITUTED: the live store holds exactly {live_events} event(s) as "
                "attested, but a different set of them — the completeness digest differs. "
                "Equal counts with unequal digests means this is not the store that was "
                "backed up"
            )

        # Observables are checked SEPARATELY and not in the chain above, because
        # the whole point is that they can be short while every event-shaped
        # check passes. `attest()`'s digest is a sha256 over the sorted
        # `event_id` set only — observables are not in the preimage — so a
        # restore that loses observable rows and no event rows satisfies
        # `quick_check`, the count and the digest together. Measured on merged
        # code: 20 observables deleted of 20, events untouched, digest equal,
        # exit 0. Indicator pivots return nothing on a store this gate had just
        # called verified, because `correlation/entities.py` joins on this table.
        #
        # The manifest already carried the number: `attestation.to_dict()` is
        # stored whole, so this reads a field that was sitting in the file.
        live_observables = attested.get("observables")
        want_observables = expected.get("observables")
        # Fail CLOSED on a manifest that cannot answer. The first version of this
        # block guarded with `isinstance(...) and isinstance(...)` and silently
        # SKIPPED the check otherwise — measured, deleting `observables` from a
        # v1 manifest and then deleting every live observable row gave exit 0, and
        # so did a string `"20"`. `_verify_backup` compares only the keys it
        # finds, so nothing else caught it either. The manifest is untrusted input
        # here (`_unsafe_path` already treats its paths that way), and a guard that
        # skips on malformed input is a fail-open inside a fix for a family of
        # fail-opens. `bool` is excluded explicitly, being an `int` subclass.
        counts_usable = True
        for whose, value in (
            ("the backup's manifest", want_observables),
            ("the live store", live_observables),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                counts_usable = False
                problems.append(
                    f"{whose} does not state a usable observable count ({value!r}, type "
                    f"{type(value).__name__}). An `ianua.backup.v1` attestation always "
                    "carries one, so this is a damaged or edited manifest and the "
                    "completeness check cannot run — refused rather than skipped"
                )
        if counts_usable:
            if live_observables < want_observables:
                problems.append(
                    f"LOSS: the live store holds {live_observables} observable(s); the "
                    f"backup attested {want_observables}. "
                    f"{want_observables - live_observables} are missing. Every event-level "
                    "check can pass while this is short — the completeness digest covers "
                    "event_ids only — and indicator pivots will silently return nothing"
                )
            elif live_observables > want_observables:
                problems.append(
                    f"ADDED: the live store holds {live_observables} observable(s); the "
                    f"backup attested {want_observables}. Re-collection (docs/RESTORE.md "
                    "step 5) does this, so it is expected if you have already run it. It "
                    "is NOT evidence loss"
                )

    # Declared files. Prefix comparison for the append-only streams only; exact
    # equality for everything else. See _is_append_only for why the allow-list
    # is on the growing side.
    declared: set[Path] = set()
    for entry in manifest["files"]:
        entry_path = Path(str(entry["path"]))
        unsafe = _unsafe_path(root, entry_path, what="manifest path")
        if unsafe is not None:
            problems.append(unsafe)
            continue
        declared.add(entry_path)
        path = root / entry_path
        backed_up = int(entry["size"])
        if not path.is_file():
            problems.append(f"{entry['path']} is missing from the live root")
            continue
        live_size = path.stat().st_size
        if _is_append_only(entry_path):
            if live_size < backed_up:
                problems.append(
                    f"TRUNCATED: {entry['path']} is {live_size} bytes; the backup holds "
                    f"{backed_up}. An append-only artifact cannot legitimately shrink"
                )
            elif _digest_prefix(path, backed_up) != entry["sha256"]:
                problems.append(
                    f"REWRITTEN: {entry['path']}'s first {backed_up} bytes do not match the "
                    "backup, so its history was not appended to — it was replaced"
                )
        elif live_size != backed_up:
            problems.append(
                f"ALTERED: {entry['path']} is {live_size} bytes; the backup holds "
                f"{backed_up}. This is not an append-only stream — a report is rewritten "
                "whole and nothing writes one during this window — so any size difference "
                "means the live copy is not the backed-up one"
            )
        elif _digest_file(path) != entry["sha256"]:
            problems.append(
                f"ALTERED: {entry['path']} is {backed_up} bytes as attested but hashes "
                "differently, so its contents were changed without changing its length"
            )

    # The reverse direction, which nothing did: a live file the manifest never
    # listed. docs/RESTORE.md step 4 is a bare `cp -a`, which MERGES into a
    # nonempty destination rather than replacing it, so a report written after
    # the backup was taken survives the restore. Measured on merged code: a
    # backup at 20 events with one declared report, a live root grown to 35
    # events and a second report describing them, store deleted and `cp -a`
    # applied — exit 0, with the later report still present claiming
    # "Correlated 35 events" over a store holding 20. The dashboard reads this
    # tree, so it would present that report against the restored store.
    #
    # Scoped to COPIED_TREES deliberately. A blanket reverse walk would flag
    # the rotation siblings beside the chains, which legitimately appear after
    # a backup, so it would false-alarm and get the gate switched off.
    live_files, unsafe_trees = _live_tree_inventory(root)
    problems.extend(unsafe_trees)
    for live_only in live_files:
        if live_only not in declared:
            problems.append(
                f"UNDECLARED: {live_only} is in the live root but not in the backup "
                "manifest. docs/RESTORE.md step 4 is a `cp -a`, which merges rather than "
                "replaces, so this is a file from before the restore that outlived it — "
                "it describes evidence the restored store may no longer hold. This is NOT "
                "store evidence loss; the store itself is checked above"
            )

    # Positions must be ABSENT. Step 3 deletes them and no backup carries one;
    # a position present here is the newer-offsets state docs/RESTORE.md calls
    # the single unrecoverable skew.
    for relative, why in sorted(EXCLUDED.items()):
        if (root / relative).exists():
            problems.append(
                f"POSITION PRESENT: {relative} exists in the live root. "
                f"docs/RESTORE.md step 3 removes it before the store comes back, because "
                f"{why.split(':')[0]}"
            )

    # Chains: entries may only GROW, and must still verify.
    chains = _verify_chains(root)
    for name, state in sorted(chains.items()):
        if not isinstance(state, dict):
            continue
        recorded = manifest["chains"][name]  # shape-checked by _load_manifest
        if recorded.get("present") and not state.get("present"):
            problems.append(f"{name}: present in the backup, absent from the live root")
            continue
        if not state.get("present"):
            continue
        if not state.get("intact"):
            problems.append(f"{name}: chain does not verify: {state.get('failure')}")
        live_entries = state.get("entries")
        kept = recorded.get("entries")
        if isinstance(live_entries, int) and isinstance(kept, int) and live_entries < kept:
            problems.append(
                f"{name}: {live_entries} entries in the live root, {kept} in the backup — "
                "an append-only chain lost history"
            )

    return {
        "root": str(root),
        "backup": str(backup),
        "taken_at": manifest.get("taken_at"),
        "events": expected["events"],
        "live_events": live_events,
        "verified": not problems,
        "problems": problems,
        "chains": chains,
    }


def _wide_paths(root: Path) -> list[str]:
    """Lab-data paths readable or writable beyond their owner.

    Reported rather than silently corrected. ``store/`` narrows the directory
    it owns and the database inside it, but ``data/`` itself is created at the
    process umask — measured at 0o755 — and a restore from a loose archive can
    leave a hash chain world-writable. Changing a directory this script does
    not own would be a side effect an operator did not ask for; saying so is
    not.
    """
    wide: list[str] = []
    for candidate in (root / "data", *(root / relative for relative in COPIED_FILES)):
        if not candidate.exists():
            continue
        mode = candidate.stat().st_mode & 0o077
        if mode:
            wide.append(f"{candidate.relative_to(root)} is {oct(candidate.stat().st_mode & 0o777)}")
    return wide


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help=(
            "Lab-data root holding data/events/ (default: repo root). Must be an "
            "absolute path that already exists as a real directory: a typo, or a "
            "relative root that is really the scheduler's working directory, must "
            "not build a shadow tree and report a backup of nothing."
        ),
    )
    parser.add_argument(
        "--name",
        default=None,
        help=(
            "Name for this backup under data/backups/ (default: a UTC "
            "timestamp). Must be a single safe filename."
        ),
    )
    parser.add_argument(
        "--verify",
        type=Path,
        default=None,
        help=(
            "Verify an existing backup directory against its manifest instead "
            "of taking a new one. Re-attests the store and re-verifies every "
            "chain; exits 1 on any mismatch."
        ),
    )
    parser.add_argument(
        "--verify-restore",
        type=Path,
        default=None,
        metavar="BACKUP",
        help=(
            "Verify that --root's LIVE tree holds what BACKUP's manifest attested, "
            "instead of taking a backup. The promotion gate: --verify checks a backup "
            "before a restore, this checks the restored root after one. Run it between "
            "steps 4 and 5 of docs/RESTORE.md; exits 1 on any mismatch. It speaks only "
            "about the copy and says nothing about whether exactly one node is active."
        ),
    )
    parser.add_argument(
        "--caller",
        default=None,
        help="Who this pass is for, recorded in the audit chain. Never inferred.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Policy bundle to enforce (default: the committed bundle).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    args = parser.parse_args(argv)
    if args.verify is not None and args.verify_restore is not None:
        # Not a mutually_exclusive_group: that reports "not allowed with", which
        # does not say which check the operator wanted. These two verify
        # different things at different points in a restore, so naming both is
        # the useful message.
        parser.error(
            "--verify and --verify-restore do different things: --verify checks a backup "
            "against its own manifest BEFORE a restore, --verify-restore checks the live "
            "--root AFTER one. Pass one."
        )
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    started_at = time.monotonic()

    try:
        root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("backup", args.caller)
        name = args.name or f"backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        destination = confine(root, BACKUP_SUBDIR, name, error=StoreError, what="backup")
        engine = load_bundle(args.policy)
        # Last in the startup try, deliberately: the only statement here that
        # opens a descriptor, so nothing can fail after it and abandon the handle.
        lock = prepare_lock(root / BACKUP_SUBDIR, LOCK_FILE)
    except (PrincipalError, PolicyBundleError, StoreError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Wrapped because the startup `try` has already closed by here, and a
    # lock that fails for a reason that is NOT contention must still be a
    # message and exit 2 rather than a traceback in cron mail. The caught
    # type is deliberately specific: a bare `except OSError` around this
    # block would relabel any failure inside the pass as a lock problem.
    try:
        with single_instance(lock) as acquired:
            if not acquired:
                print("skipped: another backup pass holds the lock; this invocation did nothing.")
                return 0
            return _run(
                args,
                root=root,
                destination=destination,
                principal=principal,
                engine=engine,
                started_at=started_at,
            )

    except LockUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _run(
    args: argparse.Namespace,
    *,
    root: Path,
    destination: Path,
    principal: Principal,
    engine: object,
    started_at: float,
) -> int:
    if args.verify is not None:
        mode = "verify"
    elif args.verify_restore is not None:
        mode = "verify-restore"
    else:
        mode = "take"
    verifying = mode != "take"
    label = f"{ACTION_NAME}:{mode}"

    try:
        audit = AuditLogger(root / AUDIT_SUBDIR / AUDIT_FILE, signing_key=signing_key_from_env())
    except (OSError, ValueError) as exc:
        print(f"error: audit log unusable, refusing to run: {exc}", file=sys.stderr)
        return 1

    try:
        enforce(
            action_class=BACKUP_CLASS,
            name=label,
            engine=engine,  # type: ignore[arg-type]
            audit=audit,
            actor=principal,
        )
    except ToolBlockedError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 3
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: could not record the gate decision: {exc}", file=sys.stderr)
        return 1

    try:
        if mode == "verify":
            payload = _verify_backup(args.verify.resolve())
        elif mode == "verify-restore":
            payload = _verify_restore(root, args.verify_restore.resolve())
        else:
            manifest = _take_backup(root, destination)
            manifest_path = destination / MANIFEST_FILE
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            manifest_path.chmod(FILE_MODE)
            attestation = manifest["store"]["attestation"]  # type: ignore[index]
            payload = {
                "backup": str(destination),
                "taken_at": manifest["taken_at"],
                "events": attestation["events"],
                "digest": attestation["digest"],
                "files": len(manifest["files"]),  # type: ignore[arg-type]
                "manifest_sha256": _digest_file(manifest_path),
                "excluded": sorted(EXCLUDED),
                "refused": manifest["refused"],
                "wide_paths": _wide_paths(root),
            }
    except (StoreError, sqlite3.Error, ValueError, OSError, KeyError) as exc:
        # sqlite3.Error is neither OSError nor StoreError, so a corrupt or
        # locked database would otherwise escape as a traceback in cron mail.
        # Contention first, since it is also a `sqlite3.Error`: a backup that
        # could not get a read snapshot has taken nothing and left nothing,
        # which is the retryable case and not the damaged one.
        if is_retryable_contention(exc):
            print(f"error: the store is busy, no backup was taken: {exc}", file=sys.stderr)
            return EXIT_RETRYABLE
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Audited before the report: the copy already exists by this point, so a
    # failed report must not leave the chain silent about it. The manifest's
    # own sha256 goes into the record, which is what anchors the manifest —
    # the chain is hash-linked, so a manifest edited afterwards no longer
    # matches an entry an operator can verify.
    try:
        audit.record(
            actor=principal.render(),
            action=f"{label}:{payload.get('events', 0)}",
            action_class=BACKUP_CLASS,
            decision="allow",
            reason=escape_delimiter(
                f"{mode if verifying else 'wrote'} backup {payload['backup']} "
                f"holding {payload.get('events')} event(s); "
                + (
                    f"verified={payload.get('verified')} problems={len(payload.get('problems', []))}"  # type: ignore[arg-type]
                    if verifying
                    else f"manifest sha256 {payload.get('manifest_sha256')}"
                )
            ),
        )
    except (AuditFieldError, OSError, ValueError) as exc:
        print(f"error: pass ran but could not be recorded: {exc}", file=sys.stderr)
        return 1

    try:
        if args.json:
            payload["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
            print(json.dumps(payload, sort_keys=True, default=str))
        else:
            _print_text(payload, mode=mode)
    except OSError as exc:
        print(f"error: pass ran but its report could not be written: {exc}", file=sys.stderr)
        return 1

    if verifying and not payload["verified"]:
        return 1
    return 0


def _print_text(payload: dict[str, object], *, mode: str) -> None:
    if mode != "take":
        raw = payload["problems"]
        problems = raw if isinstance(raw, list) else []
        restored = mode == "verify-restore"
        subject = (
            f"{payload.get('root')} against {payload['backup']}"
            if restored
            else (str(payload["backup"]))
        )
        if payload["verified"]:
            if restored:
                print(
                    f"restore verified: {payload['root']} holds the "
                    f"{payload['events']} event(s) {payload['backup']} attested, every "
                    "declared file carries the backed-up history as a prefix, and every "
                    "chain still verifies."
                )
                # Said on success, not only in the docs, because a green line
                # here is exactly what an operator will quote as justification
                # for promoting — and it does not justify that.
                print(
                    "  NOTE: this verifies the COPY. It says nothing about the fence — "
                    "whether the former active node's timers are stopped. That is "
                    "procedural; see DESIGN.md's active/passive row and docs/RESTORE.md."
                )
                return
            print(
                f"verified {payload['backup']}: {payload['events']} event(s), "
                f"attestation and every file digest match the manifest."
            )
            return
        print(f"FAILED to verify {subject}: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return
    print(
        f"wrote {payload['backup']}: {payload['events']} event(s), "
        f"{payload['files']} file(s) beside the store."
    )
    print(f"  completeness digest {payload['digest']}")
    print(
        "  positions are not in this backup by design "
        f"({', '.join(sorted(EXCLUDED))}); see docs/RESTORE.md."
    )
    refused = payload.get("refused")
    if isinstance(refused, list) and refused:
        print("  warning: sources NOT in this backup, refused as unsafe to read:")
        for entry in refused:
            print(f"    {entry}")
    wide = payload.get("wide_paths")
    if isinstance(wide, list) and wide:
        print("  warning: lab-data paths readable or writable beyond their owner:")
        for entry in wide:
            print(f"    {entry}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
