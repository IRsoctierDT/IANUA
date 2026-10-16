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

**Exit codes**, the whole interface a scheduler sees: ``0`` a backup was taken
or verified (including a skip because another pass held the lock), ``1`` the
backup, the verification or the audit write failed, ``2`` bad arguments, ``3``
blocked by policy, ``4`` retryable contention — another writer held the
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


def _verify_backup(directory: Path) -> dict[str, object]:
    """Re-check a backup against its own manifest, and report every mismatch.

    Collects findings rather than raising on the first, because an operator
    deciding whether to restore from this copy needs to know everything that
    is wrong with it, not the first thing.
    """
    manifest_path = directory / MANIFEST_FILE
    if not manifest_path.is_file():
        raise StoreError(f"no {MANIFEST_FILE} in {directory}; this is not a backup")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "ianua.backup.v1":
        raise StoreError(f"unknown backup format {manifest.get('format')!r}")

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
        with EventStore.open(directory) as copy:
            attested = copy.attest().to_dict()
        expected = store_entry["attestation"]
        for key in sorted(expected):
            if attested.get(key) != expected[key]:
                problems.append(
                    f"store attestation {key}: {attested.get(key)!r} does not match the "
                    f"manifest's {expected[key]!r}"
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
        recorded = manifest["chains"].get(name)
        if not isinstance(state, dict) or not isinstance(recorded, dict):
            continue
        if state.get("present") != recorded.get("present"):
            problems.append(
                f"{name}: present={state.get('present')!r} at backup time was "
                f"{recorded.get('present')!r}"
            )
        elif state.get("present") and not state.get("intact"):
            problems.append(f"{name}: chain no longer verifies: {state.get('failure')}")

    return {
        "backup": str(directory),
        "taken_at": manifest.get("taken_at"),
        "events": manifest["store"]["attestation"]["events"],
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
    return parser.parse_args(argv)


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
    verifying = args.verify is not None
    label = f"{ACTION_NAME}:{'verify' if verifying else 'take'}"

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
        if verifying:
            payload = _verify_backup(args.verify.resolve())
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
                f"{'verified' if verifying else 'wrote'} backup {payload['backup']} "
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
            _print_text(payload, verifying=verifying)
    except OSError as exc:
        print(f"error: pass ran but its report could not be written: {exc}", file=sys.stderr)
        return 1

    if verifying and not payload["verified"]:
        return 1
    return 0


def _print_text(payload: dict[str, object], *, verifying: bool) -> None:
    if verifying:
        raw = payload["problems"]
        problems = raw if isinstance(raw, list) else []
        if payload["verified"]:
            print(
                f"verified {payload['backup']}: {payload['events']} event(s), "
                f"attestation and every file digest match the manifest."
            )
            return
        print(f"FAILED to verify {payload['backup']}: {len(problems)} problem(s)")
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
