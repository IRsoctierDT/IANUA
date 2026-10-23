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

**Exit codes**, the whole interface a scheduler sees (``2`` includes a ``--root``
that is a backup, or inside one): ``0`` a backup was taken
or verified, or a take was skipped because another take or ``--verify-restore``
held the lock (a take whose own copy of a chain does not verify still exits
``0``, and names the chain in a warning and in ``chains_broken``); ``1`` the
backup, either verification or the audit write failed — including any mismatch
found by ``--verify`` or ``--verify-restore``;
``2`` bad arguments or the single-instance lock could not be taken; ``3``
blocked by policy; ``4`` retryable — another writer held the store's write
lock, so no backup was taken and nothing was left behind, or a ``--verify`` or
``--verify-restore`` was skipped because another pass held its lock, so nothing
was verified. A skipped verify used to exit ``0`` like a pass (found by
independent review). Retry rather than page; see ``scripts/_exit_codes.py``.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import time
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.audit import (  # noqa: E402
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    signer_from_env,
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
from scripts._terminal import printable as _printable  # noqa: E402
from store import (  # noqa: E402
    DEFAULT_FILENAME,
    EVENTS_SUBDIR,
    Attestation,
    EventStore,
    StoreError,
    StoreFileError,
    refuse_unsafe_database,
)
from store.paths import confine, validated_root  # noqa: E402

#: Where backups live: a sibling of the state they copy, inside the same
#: gitignored root, so a backup can never be the thing that commits evidence.
BACKUP_SUBDIR = Path("data") / "backups"
LOCK_FILE = "backup.lock"
#: ``--verify`` serialises with other verifies only. It held ``backup.lock``, and
#: measured, a 1 TiB sparse file planted in a backup kept it reading at about
#: 200 MiB/s, roughly an hour and a half, while every scheduled take printed
#: "skipped" at exit 0 (found by independent review). It reads one backup; it
#: writes the root's audit chain, and SQLite's transient -wal and -shm beside
#: the backup's store while it attests it. A take copies each chain under that
#: chain's own shared lock (AuditLogger.reading), so a verify's records cannot
#: tear the copy.
VERIFY_LOCK_FILE = "verify.lock"
#: How far the live events chain may have grown past the backup's copy before
#: --verify-restore will append to it: far above the records repeated runs of
#: this gate add (two per run, a few hundred bytes each), and small enough that
#: appending, which reads the head segment whole, is bounded.
LIVE_CHAIN_GROWTH = 16 * 1024 * 1024
#: The largest live segment of that chain the gate will read, to append its
#: record, when the backup does not list it: a same-node restore merges into the
#: old tree, so such a segment can be there. This bounds only the read; whether
#: the segment belongs is _undeclared_chain_segments' finding. Far above any
#: rotation size this platform configures.
LIVE_SEGMENT_CAP = 256 * 1024 * 1024
# The post-restore trust anchor is outside the backup manifest, so bound the
# entire chain family before AuditLogger reads its segments and sidecars.
AUDIT_ANCHOR_BYTES_CAP = 256 * 1024 * 1024
AUDIT_ANCHOR_FILES_CAP = 4096
AUDIT_ANCHOR_DIRECTORY_ENTRIES_CAP = 16384
#: The exit a skipped --verify or --verify-restore returns: nothing was
#: verified, so it must never read as a pass, and it is retryable, not a page.
EXIT_SKIPPED_VERIFY = EXIT_RETRYABLE
#: Far above any real manifest (about 375,000 file entries at the measured 179
#: bytes each); a manifest is read whole, so it is bounded before it is parsed.
MANIFEST_CAP = 64 * 1024 * 1024
MANIFEST_FILE = "manifest.json"

#: The manifest format this version writes and the only one it verifies.
#: Bumped from v1 when the attestation gained ``observables_digest``: a v1
#: attestation carried an observable COUNT and nothing over the rows, so
#: replacing observable rows one-for-one verified green — equal count, equal
#: event count, equal event digest, clean ``quick_check`` — while every
#: indicator pivot joined on keys the backup never held. Found by review on
#: the promotion gate; the owner chose a format bump over a second verdict
#: class, so the digest is mandatory here rather than optional.
MANIFEST_FORMAT = "ianua.backup.v2"

#: Formats this verifier recognises and refuses, each with what an operator
#: needs to read. Refused outright, not verified "as far as possible": a gate
#: that passes a backup on the checks it happens to be able to run is how a
#: substituted observables table reached a green verdict in the first place.
SUPERSEDED_FORMATS: dict[str, str] = {
    "ianua.backup.v1": (
        "its attestation has no digest over the observables rows, so this verifier "
        "cannot tell a faithful copy from one whose indicator table was substituted "
        "row-for-row."
    ),
}

#: Every field a manifest attestation must carry, read from the dataclass so
#: this list cannot fall behind it. Both verifiers require all of them before
#: comparing any: `_verify_backup` used to compare only the keys it found, so
#: a manifest with a field deleted passed on what was left.
ATTESTATION_FIELDS: tuple[str, ...] = tuple(field.name for field in fields(Attestation))
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

#: The detached head signature beside each chain (``AuditLogger``'s
#: ``<chain>.sig``), mapped to the chain it signs. Copied and declared like any
#: other sibling, and not append-only: every signed ``record()`` replaces it whole.
HEAD_SIGNATURES: dict[Path, Path] = {
    chain.with_name(chain.name + ".sig"): chain for chain in CHAIN_FILES
}

#: The one chain this CLI writes — ``_run`` records each pass's gate decision
#: here before anything is verified — and so the one head signature that
#: legitimately differs from the backup's after a correct restore. Nothing else
#: writes a chain between ``docs/RESTORE.md`` steps 4 and 5, so every other
#: signature must be byte-identical to the backup's, key or not. Excusing any
#: other ``valid`` one would excuse every field the signature check does not read
#: (``algo``, or a key nobody declared) — measured, an edited ``algo`` verified at
#: exit 0 (found by review). See :func:`_verify_restore`.
GATE_CHAIN: Path = AUDIT_SUBDIR / AUDIT_FILE
GATE_SIGNATURE: Path = GATE_CHAIN.with_name(AUDIT_FILE + ".sig")

#: ``AuditLogger``'s lock sidecar beside each declared file. Never copied:
#: ``docs/RESTORE.md`` has always said ``*.lock`` does not land in a backup, and
#: :func:`_copied_paths`' sibling rule copied ``audit.log.lock`` anyway once the
#: logger gained one. The lock is the open descriptor, not the file.
LOCK_SIDECARS: frozenset[Path] = frozenset(
    declared.with_name(declared.name + ".lock") for declared in COPIED_FILES
)

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

    A path the filesystem cannot look up **raises** here, as an I/O error
    does: on the take, where every path came from the filesystem, that is a
    real failure and the take must fail. The verifiers call
    :func:`_unsafe_manifest_path`, which turns it into a finding.
    """
    # Capped: a manifest path is untrusted, and a 2 MB one was echoed whole.
    shown = _capped(str(relative))
    if relative.is_absolute():
        return f"{what} {shown} is absolute; it must be relative to its root"
    if any(part in {"..", ""} for part in relative.parts):
        return f"{what} {shown} contains a traversal component"
    walked = base
    for part in relative.parts:
        walked = walked / part
        if walked.is_symlink():
            # The component relative to the root, and the target's tail: capping
            # the absolute path cut both to the root's own prefix, which named
            # neither (found by independent review).
            return (
                f"{what} {shown} passes through the symlink "
                f"{_capped(str(walked.relative_to(base)))} "
                f"(-> {_capped_tail(str(walked.readlink()))}); refusing to follow it out "
                "of the root"
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
        return f"{what} {shown} resolves to {_capped_tail(str(resolved))}, outside {base}"
    return None


def _unsafe_manifest_path(base: Path, relative: Path, *, what: str) -> str | None:
    """:func:`_unsafe_path` for a path a manifest supplied, where one the
    filesystem cannot even look up is a finding rather than an error.

    Measured, found by independent review: a NUL byte, a lone surrogate (a
    JSON ``\\ud800`` escape) and an overlong component each raised out of the
    walk, and the bare error replaced the verifier's whole report, hiding a
    genuine mismatch beside the entry. Not walkable is not safe, so it is a
    reason like the others.

    Only the verifiers call this. The first version put the catch in
    :func:`_unsafe_path` itself, which the take shares, and review of that
    measured the cost: a take over an unsearchable ``data/reports`` then exited
    0 without the reports, where it had failed closed.
    """
    text = str(relative)
    if "\x00" in text:
        # is_symlink() quietly answers False for it and resolve() raises.
        return f"{what} {_capped(repr(text))} contains a NUL byte and cannot be checked"
    try:
        return _unsafe_path(base, relative, what=what)
    except (OSError, ValueError) as exc:
        return f"{what} {_capped(repr(text))} cannot be checked ({type(exc).__name__})"


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


def _open_regular(path: Path) -> BinaryIO:
    """``path`` opened for reading, refusing anything but a regular file.

    One descriptor, checked by ``fstat``: ``O_NOFOLLOW`` refuses a symlink at
    the leaf and ``O_NONBLOCK`` keeps a FIFO swapped in after an ``is_file()``
    check from blocking the open, so what is checked is what is read.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb")


def _digest_exact(path: Path, size: int) -> tuple[int, str | None]:
    """``path``'s size and, only if it is exactly ``size`` bytes, its sha256.

    The size comes first and from the descriptor that is read, because a
    digest reads to the end: measured, a ``files[]`` entry the manifest
    recorded as 34 bytes, planted as a 1 TiB sparse file, was digested in full
    after the size mismatch was already known, and the store's size was never
    compared at all (found by independent review). At most ``size`` bytes are
    read, and a file that grows or shrinks while it is read is a mismatch too,
    reported as :data:`CHANGED_WHILE_READ` rather than as a size it never had
    (found by review: it reported ``size + 1`` and the bytes read so far).
    """
    with _open_regular(path) as handle:
        actual = os.fstat(handle.fileno()).st_size
        if actual != size:
            return actual, None
        running = hashlib.sha256()
        remaining = size
        while remaining:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                return CHANGED_WHILE_READ, None
            running.update(block)
            remaining -= len(block)
        if handle.read(1):
            return CHANGED_WHILE_READ, None
    return actual, running.hexdigest()


#: :func:`_digest_exact`'s size for a file that changed length while it was read.
CHANGED_WHILE_READ = -1


def _size_finding(path: object, size: int, recorded: object) -> str:
    """``size N != M``, or that the file changed while it was read."""
    if size == CHANGED_WHILE_READ:
        return f"{path}: changed size while it was read (the manifest records {recorded})"
    return f"{path}: size {size} != {recorded}"


def _unbounded_chain(directory: Path, chain: Path, sizes: dict[str, int]) -> str | None:
    """Why ``chain`` in ``directory`` must not be verified, or ``None``.

    Verifying a chain reads each of its segments whole into memory, and
    finds the archives and checkpoint by listing the directory, so a manifest
    check alone never bounded it: measured, a 1 TiB sparse ``audit.log.99``
    planted beside a backup's chain, with the manifest untouched, ended
    ``--verify`` in a MemoryError traceback (found by independent review). A
    take declares every file of the family, so each must be in the manifest at
    the size it has; anything else is reported and not read.

    A chain directory that passes through a symlink is refused, not skipped: a
    take never writes one, and measured, skipping it let ``--verify`` read a
    2 GiB file outside the backup whole (found by independent review). And
    last, the chain's lock is tried without waiting: see :func:`_lock_in_use`.
    """
    parent = directory / chain.parent
    unsafe = _unsafe_manifest_path(directory, chain.parent, what="chain directory")
    if unsafe is not None:
        return f"{chain}: not verified: {unsafe}"
    if not parent.is_dir():
        return None
    for child in sorted(parent.iterdir()):
        if not child.name.startswith(chain.name):
            continue
        relative = str(child.relative_to(directory))
        try:
            held = child.lstat().st_size
        except OSError as exc:
            return f"{chain}: not verified: {relative} cannot be checked ({type(exc).__name__})"
        if relative not in sizes:
            return (
                f"{chain}: not verified: {_capped(relative)} is beside it but not in the "
                "manifest; a take declares every file of a chain's family, so this one was "
                "not put there by a take"
            )
        if held != sizes[relative]:
            return (
                f"{chain}: not verified: {relative} is {held} bytes and the manifest "
                f"records {sizes[relative]}, so reading it is not bounded by the manifest"
            )
    return _lock_in_use(directory, chain)


def _lock_in_use(directory: Path, chain: Path) -> str | None:
    """Why ``chain``'s lock in a backup must not be waited on, or ``None``.

    A backup has no writer, so nothing should hold a lock in one, and verifying
    a chain takes a **blocking** shared lock on its ``.lock``. Measured, found
    by independent review: a backup's ``audit.log.lock`` replaced by a hard
    link to ``data/backups/backup.lock`` (both empty, so its manifest entry
    still matched) made ``--verify-restore`` under a key wait for ever on the
    lock it already held, while every take skipped at exit 0; linked to
    ``verify.lock``, ``--verify`` did the same. So the lock is tried without
    waiting first, and a held one is a finding. A holder that appears after
    this probe can still make the read wait: that needs a process on this
    node and write access to the backup.
    """
    lock = directory / chain.with_name(chain.name + ".lock")
    try:
        handle = _open_regular(lock)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"{chain}: not verified: its lock cannot be checked ({type(exc).__name__})"
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return (
                f"{chain}: not verified: its lock in the backup is held, by another process "
                "or because it is the same file as a lock this pass holds. A backup has no "
                "writer, so nothing should hold one; find the other names with find "
                "<mount> -xdev -samefile on it"
            )
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return None


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

    **Append-only means the five streams in :data:`COPIED_FILES` themselves,
    and nothing beside them.** This used to grant growth to every sibling whose
    name starts with a declared one — "``audit.log.1``, a checkpoint, a head
    signature" — on the theory that it was the rule :func:`_copied_paths` copies
    them by, so the two sides could not disagree. But *which files to copy* and
    *which files may grow* are different questions, and none of the three grows:

    * a rotated archive is frozen once ``AuditLogger._rotate`` renames it;
    * a checkpoint is rewritten whole, and only by ``_prune``, which nothing runs
      within the step-4-to-step-5 window of :func:`_verify_restore`;
    * a head signature is rewritten whole by every signed ``record()`` — see
      :data:`HEAD_SIGNATURES` and :func:`_verify_restore` for how it is judged.

    Measured on the old rule: with ``AUDIT_HMAC_KEY`` set, **every correct
    restore failed** ``REWRITTEN: data/events/audit.log.sig``, because this
    command's own gate decision re-signs that chain before the check reads it;
    and blank lines appended to a rotated archive, or whitespace to a
    checkpoint, verified green, since chain verification skips blank lines and
    ``json.loads`` accepts trailing whitespace. The two sides still cannot
    disagree in the direction that matters: every file a backup copies has a
    manifest entry, and every entry is compared, strictly unless named here.

    ``data/reports/`` is not append-only either: a report is rewritten whole, and
    within that window nothing writes one at all.
    """
    return relative in COPIED_FILES


def _signature_judged(state: object) -> bool:
    """May :data:`GATE_SIGNATURE` go byte-uncompared, because its chain report covers it?

    Asked of that one signature only: every other is compared exactly, because
    nothing rewrites its chain in this window. In exactly two states, and in both
    the verdict stays honest without the
    bytes: the signature verified (``valid`` — under a key, present and covering
    the current head), or the chain is already a finding (``intact`` false), so
    the pass is red whatever the bytes say and comparing them would only add a
    misleading second finding, since the gate decision re-signs the events chain.

    Everything else falls through to the exact comparison, and the first version
    of this predicate got one of them wrong. ``unsigned`` means no verifier, so
    nothing read the signature. But a key in hand is not the same as the
    signature having been checked: a chain pruned to its checkpoint
    (``--retain-segments 0``) has no entry to sign, ``verify_report`` reports
    ``empty`` without reading the sidecar, and treating that as judged let a
    same-length forgery verify at exit 0 (found by review). A chain absent from
    the live root has no state, so its signature is compared too.
    """
    if not isinstance(state, dict) or state.get("present") is not True:
        return False
    return state.get("signature") == "valid" or state.get("intact") is False


def _altered(entry: dict[str, Any], path: Path) -> str | None:
    """The ``ALTERED`` finding for a declared file that may not change, or ``None``.

    Everything :func:`_is_append_only` does not name, and a head signature that
    :func:`_signature_judged` does not excuse, must be byte-identical to the backup.
    """
    backed_up = int(entry["size"])
    live_size = path.stat().st_size
    if live_size != backed_up:
        return (
            f"ALTERED: {entry['path']} is {live_size} bytes; the backup holds "
            f"{backed_up}. Only the declared streams may grow, and nothing in this "
            "window rewrites anything else — a report, a rotated archive, a checkpoint, "
            "or a head signature nothing re-signed — so any size difference means the "
            "live copy is not the backed-up one"
        )
    if _digest_file(path) != entry["sha256"]:
        return (
            f"ALTERED: {entry['path']} is {backed_up} bytes as attested but hashes "
            "differently, so its contents were changed without changing its length"
        )
    return None


def _head_signature_chain(relative: Path) -> Path | None:
    """The chain whose detached head signature ``relative`` names, or ``None``."""
    for chain in CHAIN_FILES:
        if relative.parent == chain.parent and relative.name == f"{chain.name}.sig":
            return chain
    return None


def _backed_up_chain_problems(backup: Path, manifest: dict[str, Any]) -> list[str]:
    """Authenticate each backed-up chain where its signature still means something.

    A live head signature proves only what this process just signed: the gate
    record replaced it before the comparison runs, so comparing its bytes failed
    every correct signed restore, and verifying it says nothing about the
    history that was restored. The backup still holds the signature the take
    wrote, over the chain the take copied, so that is where the key is checked;
    and every file in the chain's family must be in the backup exactly as the
    manifest recorded, which ties the live prefix (compared against the same
    manifest) to the bytes the key was checked over.

    Every chain the manifest records as present is checked, not only those with
    a ``.sig`` entry: measured on main, deleting the backup's signature and its
    manifest entry, then recomputing the chain over an edited entry and the
    manifest's digests, gave ``--verify-restore`` exit 0 under a key (found by
    independent review).

    With no key configured nothing can authenticate a signed chain, so the
    backed-up chain is checked by its manifest digests alone, and #256's exact
    comparison of the live head signature is what stands in for the key.
    """
    problems: list[str] = list(_events_chain_problems(manifest))
    problems.extend(_backup_inventory_problems(backup, manifest))
    verifier = verifier_from_env()
    for chain in CHAIN_FILES:
        recorded = bool(manifest["chains"][str(chain)].get("present"))  # shape-checked
        if AuditLogger(backup / chain).exists() != recorded:
            # Before the short-circuit below, which trusted this field: measured,
            # a forged events chain with its signature stripped passed at exit 0
            # once the manifest also called the chain absent (found by
            # independent review). --verify already compares the two.
            problems.append(
                f"{chain}: the manifest records present={recorded} and the backup "
                f"{'holds' if not recorded else 'does not hold'} it"
            )
            continue
        if not recorded:
            continue
        family = [
            entry
            for entry in manifest["files"]
            if Path(str(entry["path"])).parent == chain.parent
            and Path(str(entry["path"])).name.startswith(chain.name)
        ]
        for entry in family:
            relative = Path(str(entry["path"]))
            unsafe = _unsafe_manifest_path(backup, relative, what="backup path")
            if unsafe is not None:
                problems.append(unsafe)
                continue
            held = backup / relative
            if not held.is_file():
                problems.append(f"{entry['path']} is missing from the backup")
            elif _digest_exact(held, entry["size"])[1] != entry["sha256"]:
                problems.append(
                    f"{entry['path']}: the backup's copy is not what its manifest recorded, "
                    "so the live chain cannot be traced to the history the take signed"
                )
        if verifier is None:
            # Nothing can authenticate a signed chain without the key; #256 compares
            # the live head signature's bytes exactly instead (see GATE_SIGNATURE).
            continue
        unbounded = _unbounded_chain(
            backup, chain, {str(entry["path"]): entry["size"] for entry in manifest["files"]}
        )
        if unbounded is not None:
            problems.append(unbounded)
            continue
        try:
            report = AuditLogger(backup / chain, signer=verifier).verify_report()
        except MemoryError:
            problems.append(f"{chain}: a file of the backed-up chain is too large to verify")
            continue
        except RecursionError:
            # json's own, on a deeply nested line: measured, a traceback that
            # replaced the report (found by independent review).
            problems.append(f"{chain}: a line of the backed-up chain is nested too deeply to read")
            continue
        if chain == AUDIT_SUBDIR / AUDIT_FILE and not any(
            _head_signature_chain(Path(str(e["path"]))) == chain for e in family
        ):
            problems.append(
                f"{chain}: the backup carries no head signature for it and a key is set. A "
                "take records its signed gate decision there before it copies, so a backup "
                "taken under a key always has one. A backup taken before the key was "
                "configured has none: verify it with the key unset, then take a fresh "
                "signed backup"
            )
            continue
        if not report.intact:
            taken = manifest["chains"][str(chain)]
            if report.signature == "missing" and taken.get("signature") in {"missing", "unsigned"}:
                # The take itself recorded it unsigned: with a key but before any
                # keyed record ("missing"), or with no key at all ("unsigned"). Found
                # by review: the generic finding below sent an operator away from a
                # correct backup. The manifest is not authenticated, so this says what
                # it records and does not vouch for it; 4b fails either way.
                problems.append(
                    f"{chain}: the backed-up chain carries no head signature, and its manifest "
                    f"records it unsigned when the backup was taken (signature "
                    f"{taken.get('signature')!r}): a backup taken before the key was "
                    "configured, or before this chain's first keyed record, if the manifest "
                    "is genuine. It cannot be authenticated under the key: see docs/RESTORE.md "
                    "for the unkeyed recourse"
                )
                continue
            problems.append(
                f"{chain}: the backed-up chain does not authenticate (signature "
                f"{report.signature}): {report.failure}"
            )
    return problems


def _events_chain_problems(manifest: dict[str, Any]) -> list[str]:
    """Why the manifest's events chain cannot be a take's, as findings.

    Every take records its gate decision in ``data/events/audit.log`` before
    it copies anything, so a genuine backup always holds that chain with at
    least one entry. Measured, found by independent review: with the chain's
    family deleted and the manifest calling it absent, or with ``entries`` set
    to 0, ``--verify-restore`` exited 0 with every backed-up record gone. The
    other chains can be legitimately absent, which is why removing one of them
    and its record is still undetectable without authenticating the manifest
    (the recorded residual).
    """
    record = manifest["chains"][str(AUDIT_SUBDIR / AUDIT_FILE)]  # shape-checked
    entries = record.get("entries")
    if record.get("present") and _is_count(entries) and entries >= 1:
        return []
    checkpoint = f"{AUDIT_SUBDIR / AUDIT_FILE}.checkpoint"
    if record.get("present") and any(e["path"] == checkpoint for e in manifest["files"]):
        # A rotation that pruned every segment (--retain-segments 0) inside the
        # take's copy window leaves only the checkpoint (found by review).
        return []
    return [
        f"{AUDIT_SUBDIR / AUDIT_FILE}: the manifest records it "
        f"{'present with ' + repr(entries) + ' entries' if record.get('present') else 'absent'}. "
        "A take records its gate decision there before it copies anything, so a backup a "
        "take wrote always holds it with at least one entry"
    ]


def _linked_live_chain(root: Path) -> str | None:
    """Why this pass must not touch ``root``'s chains, or ``None``.

    Every mode's first write is the gate decision in ``data/events/audit.log``,
    and a take then holds every chain's lock while it copies, so a chain or a
    chain lock with a second name is refused before either, whatever the other
    name is. Measured, found by independent review: a ``--verify`` or a take
    whose ``--root`` was a hard-link copy of a backup appended its gate record
    into that backup; and a chain lock that was the same file as
    ``data/backups/backup.lock`` (``cp -a`` keeps hard links *between* the
    files it copies, so a backup holding one restores it) made 4b and every
    take wait for ever on the lock they held themselves. A copied restore and a
    hard-link farm of ``data/backups`` leave every one of these with one link.
    Checked by path, before the lock is taken: a link swapped in while the pass
    waits for that lock is not caught, which needs write access to the chain's
    directory.
    """
    for chain in CHAIN_FILES:
        lock = root / chain.with_name(chain.name + ".lock")
        for path in (root / chain, lock):
            try:
                found = os.lstat(path)
            except OSError:
                continue  # absent, or unusable: AuditLogger says which
            if not stat.S_ISREG(found.st_mode) or found.st_nlink <= 1:
                # A directory's link count is its subdirectories plus two, not a
                # second name: measured, an empty directory at a lock path was
                # refused as "shares its file with 1 other name(s)" (found by
                # review). AuditLogger refuses a non-regular chain or lock itself,
                # and a reader proceeds without a lock that is not a regular file.
                continue
            others = found.st_nlink - 1
            if path == lock:
                return (
                    f"the live {path.relative_to(root)} shares its file with {others} other "
                    "name(s), and this pass takes that lock, so it would wait on whatever else "
                    "holds that file — measured, the lock this pass already holds. Find them "
                    f"with find <mount> -xdev -samefile {path}, then remove this chain lock's "
                    f"name ({path.relative_to(root)}): a chain lock holds nothing, and the next "
                    "record recreates it"
                )
            return (
                f"the live {path.relative_to(root)} shares its file with {others} other "
                "name(s), and this pass appends to it, which would change whatever else uses "
                f"that file. Find them with find <mount> -xdev -samefile {path}. If this root "
                "was restored with cp -al, rsync --link-dest or ln, or from a backup that holds "
                "hard links, remove its linked files and repeat docs/RESTORE.md step 4 with "
                "cp -a --no-preserve=links. Never restore over a live root to clear this"
            )
    return None


def _root_in_backup(root: Path, backup: Path | None) -> str | None:
    """Why ``--root`` must not be used, because it is a backup or inside one, or ``None``.

    Every mode writes its audit records, and its lock, under ``--root``, so a
    ``--root`` that is a backup, or inside one, writes into that backup: measured,
    ``--verify`` with the backup as its own root appended its gate and outcome
    records to the backup's chain, and a take with a backup as its root wrote
    those records and a whole nested backup into it, at exit 0; neither backup
    verified again (both found by independent review). So the argued backup is
    checked, and so is any backup the root is or lies under, wherever it was
    moved to: a directory whose ``manifest.json`` declares a backup format. By
    content, not by place: requiring the directory to sit in ``data/backups``
    missed a backup copied elsewhere (measured, a pass with ``--root`` at its
    ``data/`` wrote records and locks into it), and a bare ``manifest.json``
    refused a lab root under some unrelated one (both found by review).

    A lab root that holds a backup manifest at its top is refused too, with the
    file named: it was restored by copying a whole backup directory rather than
    the backup's ``data/``, which step 4 does, and the manifest does not belong
    there. A manifest that cannot be read or parsed is not taken as a backup's.
    """
    resolved = Path(os.path.realpath(root))
    if backup is not None and (resolved == backup or resolved.is_relative_to(backup)):
        return (
            f"--root {resolved} is the backup being verified, or inside it, and this pass "
            "writes its audit records under --root, which would change the backup. Use the "
            "lab-data root as --root"
        )
    for candidate in (resolved, *resolved.parents):
        if not _holds_backup_manifest(candidate):
            continue
        if candidate == resolved:
            return (
                f"--root {resolved} holds a backup manifest ({resolved / MANIFEST_FILE}), so "
                "it is a backup, or a lab root restored by copying a whole backup directory. "
                "This pass writes its audit records and its lock under --root, which would "
                "change a backup. If it is a backup, use the lab-data root as --root. If it is "
                "a restored lab root, move that manifest.json out of it and keep it: "
                "docs/RESTORE.md step 4 copies only the backup's data/"
            )
        return (
            f"--root {resolved} lies inside the backup {candidate} (it holds a backup "
            "manifest), and this pass writes its audit records and its lock under --root, "
            "which would change that backup. Use the lab-data root as --root"
        )
    return None


def _holds_backup_manifest(directory: Path) -> bool:
    """Does ``directory`` hold a ``manifest.json`` that declares a backup format?"""
    try:
        with _open_regular(directory / MANIFEST_FILE) as handle:
            raw = handle.read(MANIFEST_CAP + 1)
        if len(raw) > MANIFEST_CAP:
            return False
        loaded = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError):
        return False
    found = loaded.get("format") if isinstance(loaded, dict) else None
    return found == MANIFEST_FORMAT or found in SUPERSEDED_FORMATS


def _live_chain_bound(root: Path, backup: Path) -> str | None:
    """Why the live events chain is too large for this gate to append to, or ``None``.

    Appending reads the head segment whole, before any check runs. Measured,
    found by independent review: a 1 TiB sparse ``audit.log`` in the backup,
    restored by step 4, made the gate record a ``MemoryError`` traceback in
    place of the report, and so did an empty one beside a 1 TiB archive. So,
    before the gate, each live file of that chain's family that the backup
    holds must be no larger than the backup's copy, plus
    :data:`LIVE_CHAIN_GROWTH` for the active log, which repeated runs of this
    gate append to, and one the backup does not hold no larger than
    :data:`LIVE_SEGMENT_CAP`. Only the read is bounded here: whether such a
    leftover segment belongs to the restored chain is :func:`_verify_restore`'s
    ``UNDECLARED`` finding.
    """
    try:
        manifest = _load_manifest(backup)
        sizes = {str(entry["path"]): entry["size"] for entry in manifest["files"]}
        chain = AUDIT_SUBDIR / AUDIT_FILE
        parent = root / chain.parent
        if not parent.is_dir() or parent.is_symlink():
            return None  # main() refuses a symlinked data/events at exit 2, before this
        children = sorted(parent.iterdir())
    except (StoreError, OSError):
        # Refused by name once the pass runs, inside its guarded try: measured,
        # an unreadable backup was a PermissionError traceback here (found by
        # review).
        return None
    for child in children:
        if not child.name.startswith(chain.name) or child.name.endswith((".lock", ".sig")):
            continue
        relative = str(child.relative_to(root))
        try:
            held = child.lstat().st_size
        except OSError:
            continue
        recorded = sizes.get(relative)
        if child.name == chain.name:
            allowed = (recorded or 0) + LIVE_CHAIN_GROWTH
        elif recorded is not None:
            allowed = recorded
        else:
            allowed = LIVE_SEGMENT_CAP
        if held > allowed:
            return (
                f"the live {relative} is {held} bytes, more than the {allowed} this gate "
                f"allows it ({'the backup holds ' + str(recorded) if recorded is not None else 'the backup does not hold it'}). "
                "The gate reads that chain's segments to append its record, so it was not "
                "run. Move that file out of the root and keep it for investigation, then "
                "repeat docs/RESTORE.md step 4 from a backup that passes step 2"
            )
    return None


def _backup_inventory_problems(backup: Path, manifest: dict[str, Any]) -> list[str]:
    """Files in a backup's ``data/`` the manifest does not account for, and links inside it.

    Step 4's ``cp -a`` copies everything under ``data/``, and keeps hard links
    *between* the files it copies. Measured, found by independent review: a
    backup with a chain lock hard-linked to a planted ``data/backups/backup.lock``
    passed ``--verify``, and once restored, 4b and every take waited for ever on
    the lock they held themselves. A take writes only the files it declares, the
    store and the store's transient sidecars, each with one name within the
    backup, so anything else is reported, and so is a directory no reported
    path lies in. Links *between* backups, which a hard-link snapshot farm makes,
    are not looked at here; the store check refuses a linked store anyway (#259).
    """
    store = str(manifest["store"]["path"])  # shape-checked: a string
    allowed = {str(entry["path"]) for entry in manifest["files"]} | {store}
    allowed |= {store + suffix for suffix in _SIDECARS}
    # Every directory a declared file lies in. A take creates no other, and a
    # planted empty one at a lock or position path passed step 2 and, restored,
    # stopped every CLI at exit 2 (found by review), so any other is reported
    # and not descended into.
    folders = {str(parent) for path in allowed for parent in Path(path).parents}
    base = backup / "data"
    if base.is_symlink() or not base.is_dir():
        return []  # the path walks name a symlinked data/; an absent one is a missing store
    problems: list[str] = []
    seen: dict[tuple[int, int], str] = {}
    for directory, dirnames, filenames in os.walk(base):
        undeclared_dirs = []
        for name in sorted(dirnames + filenames):
            path = Path(directory) / name
            relative = str(path.relative_to(backup))
            try:
                found = path.lstat()
            except OSError as exc:
                problems.append(
                    f"{_capped(relative)} in the backup cannot be checked ({type(exc).__name__})"
                )
                continue
            if stat.S_ISDIR(found.st_mode):
                if relative not in folders:
                    undeclared_dirs.append(name)
                    problems.append(
                        f"UNDECLARED: {_capped(relative)} is a directory in the backup that no "
                        "file its manifest lists lies in. A take creates none, and step 4's cp "
                        "-a would copy it into the live root, where a directory at a lock or "
                        "position path stops the CLIs that open it"
                    )
                continue
            if relative not in allowed:
                kind = "a file" if stat.S_ISREG(found.st_mode) else _kind_of(found.st_mode)
                problems.append(
                    f"UNDECLARED: {_capped(relative)} is {kind} in the backup that its manifest "
                    "does not list. A take writes only the files it declares, and step 4's "
                    "cp -a would copy it into the live root"
                )
                continue
            key = (found.st_dev, found.st_ino)
            if stat.S_ISREG(found.st_mode) and key in seen:
                problems.append(
                    f"{seen[key]} and {relative} in the backup are the same file (a hard link "
                    "inside the backup). A take never makes one, and step 4's cp -a would "
                    "recreate it in the live root"
                )
            seen.setdefault(key, relative)
        dirnames[:] = [name for name in dirnames if name not in undeclared_dirs]
    return problems


def _same_file(left: Path, right: Path) -> bool:
    """Are these two names one file? ``False`` when either cannot be looked up."""
    try:
        return os.path.samestat(os.lstat(left), os.lstat(right))
    except (OSError, ValueError):
        return False


def _linked(relative: Path) -> str:
    """The finding for a live file that is the backup's own file."""
    return (
        f"LINKED: {relative} in the live root is the backup's own file (a hard link), so "
        "the next write to it, step 5's re-collection or any later pass, changes the backup "
        "too. A restore is a copy: remove the linked files from the live root (cp -a cannot "
        "copy over them: they are the same file), then repeat docs/RESTORE.md step 4 with "
        "cp -a --no-preserve=links"
    )


def _shared_live_file(relative: Path, links: int) -> str:
    """The finding for a live file with a second name that is not the backup's."""
    return (
        f"LINKED: {relative} in the live root shares its file with {links - 1} other "
        "name(s), so the next write to it changes them too: a restore made with cp -al, "
        "rsync --link-dest or ln from some other copy. Find them with find <mount> -xdev "
        "-samefile, remove the linked files from the live root, then repeat docs/RESTORE.md "
        "step 4 with cp -a --no-preserve=links"
    )


def _linked_to_backup(root: Path, argument: Path) -> str | None:  # argument: resolved
    """Why this ``--verify-restore`` must not write its gate record, or ``None``.

    The pass's first write is the gate decision in the live chain, so a live
    chain that *is* the backup's chain is refused before it. Measured on main:
    with step 4 done as a hard-link copy (``cp -al``), the gate and pass records
    appended through the shared inode into the backup's own ``audit.log``, which
    then failed ``--verify`` for good, while this check exited 0 "restore
    verified" (found by independent review).

    Identity, so this names the backup as the other copy; any other second name
    is :func:`_linked_live_chain`'s refusal, which follows it. Only ``audit.log``
    is checked here: the head signature is replaced through a new inode, and the
    lock is created read-only and never written (measured). The store and every
    other declared file are reported by :func:`_verify_restore`.
    """
    relative = AUDIT_SUBDIR / AUDIT_FILE
    if _same_file(root / relative, argument / relative):
        return (
            f"the live {relative} is the backup's own file (a hard link), and this pass "
            "appends to it, which would change the backup it is checking. A restore is a "
            "copy: remove the linked files from the live root (cp -a cannot copy over them), "
            "then repeat docs/RESTORE.md step 4 with cp -a --no-preserve=links, never with cp -al, "
            "rsync --link-dest or ln"
        )
    return None


def _undeclared_chain_segments(
    root: Path, manifest: dict[str, Any], *, skip: dict[Path, str]
) -> dict[Path, list[str]]:
    """Live chain segments the backup did not hold, as ``UNDECLARED`` findings, per chain.

    Step 4's ``cp -a`` merges: it replaces the active log with the backup's and
    leaves any archive or checkpoint the old tree had beside it. Within the
    step-4-to-step-5 window nothing rotates a chain (this gate's own logger has
    no size limit), so a segment the manifest does not list predates the
    restore. Measured, found by independent review: after any rotation since the
    take, a same-node restore failed 4b with an unexplained "chain break …
    found seq 0", repeating step 4 could not clear it, and moving the leftover
    archive aside did. That segment holds audit records written after the
    backup, so the remedy keeps it rather than deleting it. Locks and head
    signatures are not segments: a lock holds nothing, and this gate's own
    record replaces the events chain's signature.
    """
    declared = {str(entry["path"]) for entry in manifest["files"]}
    found: dict[Path, list[str]] = {}
    for chain in CHAIN_FILES:
        parent = root / chain.parent
        if chain in skip or parent.is_symlink() or not parent.is_dir():
            continue
        for child in sorted(parent.iterdir()):
            name = child.name
            if not name.startswith(chain.name) or name.endswith((".lock", ".sig")):
                continue
            relative = str(child.relative_to(root))
            if relative in declared:
                continue
            found.setdefault(chain, []).append(_leftover_segment(relative, child, chain))
    return found


def _leftover_segment(relative: str, child: Path, chain: Path) -> str:
    """The ``UNDECLARED`` finding for one live chain file the backup does not hold.

    By what it is, because the remedy is the same and the reason to keep it is
    not: an archive holds audit records written after the backup; an active
    log the backup does not list belongs to a chain the backup never held
    (measured: naming only its archive left 4b failing on that log, found by
    review); a checkpoint records segments pruned after the backup; and
    anything that is not a regular file is no segment at all.
    """
    shown = _capped(relative)
    keep = "Move it out of the root and keep it, then re-run this check"
    try:
        mode = child.lstat().st_mode
    except OSError as exc:
        return f"UNDECLARED: {shown} beside {chain} cannot be checked ({type(exc).__name__})"
    if not stat.S_ISREG(mode):
        return (
            f"UNDECLARED: {shown} is {_kind_of(mode)} at a name of {chain}'s family, not a "
            f"chain segment, and the backup does not hold it. {keep}"
        )
    if child.name == chain.name:
        return (
            f"UNDECLARED: {shown} is the live log of a chain the backup does not hold, so it "
            "is from before the restore. It holds audit records written after the backup: "
            f"do not delete it. {keep}, with any archives beside it"
        )
    if child.name.endswith(".checkpoint"):
        what = "a checkpoint of segments pruned after the backup was taken"
    else:
        what = "an archive holding audit records written after the backup"
    return (
        f"UNDECLARED: {shown} is beside the restored {chain} but not in the backup: {what}, "
        "which step 4's cp -a merge left behind, so the restored chain does not continue "
        f"into it. Do not delete it. {keep}"
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
    refused: list[str] = []
    for tree in COPIED_TREES:
        base = root / tree
        # By the same rule as a file. A symlinked tree root used to be skipped
        # without a word, so a take over one exited 0 with every report
        # silently absent (found by independent review).
        unsafe = _unsafe_path(root, tree, what="tree")
        if unsafe is not None:
            refused.append(f"{unsafe}; none of its files are in this backup")
            continue
        if base.is_dir():
            candidates.extend(sorted(child.relative_to(root) for child in base.iterdir()))
    # Rotated archives, checkpoints and head signatures sit beside their
    # chain; they are part of the same evidence and are copied with it. The
    # lock sidecar sits there too and is not evidence (see LOCK_SIDECARS). This
    # rule says what to COPY and nothing about what may grow: _is_append_only
    # answers that, and the two questions have different answers.
    for relative in COPIED_FILES:
        parent = (root / relative).parent
        if not parent.is_dir() or parent.is_symlink():
            continue
        stem = relative.name
        candidates.extend(
            sorted(
                child.relative_to(root)
                for child in parent.iterdir()
                if child.name != stem
                and child.name.startswith(stem)
                and child.relative_to(root) not in LOCK_SIDECARS
            )
        )

    found: list[Path] = []
    for relative in sorted(set(candidates)):
        reason = _unsafe_path(root, relative, what="source")
        if reason is not None:
            refused.append(reason)
            continue
        # `is_file()` only after the symlink check, because it follows them.
        if (root / relative).is_file():
            found.append(relative)
        elif (root / relative).exists():
            # A subdirectory or a special file in a copied tree used to be left
            # out without a word, the blind spot this function names everywhere
            # else (found by independent review). An absent declared chain is
            # normal and stays silent.
            refused.append(
                f"source {_capped(str(relative))} is not a regular file, so it is not in "
                "this backup"
            )
    return found, sorted(refused)


def _verify_chains(root: Path, *, skip: dict[Path, str] | None = None) -> dict[str, object]:
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
    # The writer in ``_run`` resolves ``signer_from_env`` instead, because a
    # verifier cannot sign; the two share one precedence.
    chains: dict[str, object] = {}
    verifier = verifier_from_env()
    for relative in CHAIN_FILES:
        path = root / relative
        logger = AuditLogger(path, signer=verifier)
        if not logger.exists():
            chains[str(relative)] = {"present": False}
            continue
        reason = (skip or {}).get(relative)
        if reason is not None:
            chains[str(relative)] = {
                "present": True,
                "intact": False,
                "failure": reason,
                "skipped": True,
            }
            continue
        try:
            report = logger.verify_report()
        except (MemoryError, RecursionError) as exc:
            # A chain file larger than memory, read whole by verify_report, or
            # a line nested deeper than json will parse.
            chains[str(relative)] = {
                "present": True,
                "intact": False,
                "failure": (
                    "a file of this chain is too large to verify in memory"
                    if isinstance(exc, MemoryError)
                    else "a line of this chain is nested too deeply to read"
                ),
            }
            continue
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
    database = _database_problem(source_db, what=f"the live store {source_db}")
    if database is not None:
        # Before is_file(), which reads a FIFO as "no event store", and before the
        # destination exists, so a refused take leaves no partial copy. The take
        # never reaches EventStore.open on the source, so this is its only check.
        raise StoreError(database)
    if not source_db.is_file():
        raise StoreError(
            f"no event store at {source_db}; refusing to write a backup that "
            "would restore as an empty store indistinguishable from a real one"
        )
    sidecar = _sidecar_problem(source_db, what=f"the live store {source_db}")
    if sidecar is not None:
        # Before the backup directory is created, so a refused take leaves no
        # partial copy; the gate's allow record is already in the chain, with no
        # outcome record after it. The type and link count only: a live writer
        # legitimately has a non-empty -wal, which the online backup API copies.
        raise StoreError(sidecar)

    destination.mkdir(mode=DIR_MODE, parents=True, exist_ok=False)
    destination.chmod(DIR_MODE)

    target_db = destination / EVENTS_SUBDIR / DEFAULT_FILENAME
    target_db.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    target_db.parent.chmod(DIR_MODE)
    _copy_database(source_db, target_db)
    target_db.chmod(FILE_MODE)

    files: list[dict[str, object]] = []
    # Listed and copied under every chain's shared lock, the one AuditLogger's
    # writers take exclusively, so each chain, its archives and its head
    # signature are one consistent set. Measured without it once --verify no
    # longer shared the take's lock: a verify's record landing between the
    # copy of audit.log and of audit.log.sig left a signed backup whose
    # signature was stale, which could never pass --verify or the promotion
    # gate, at exit 0; 8 of 40 takes under a continuous verify (found by
    # independent review). Writers wait for the copy, which is small next to
    # the store. In CHAIN_FILES order, and no record is made inside it.
    with contextlib.ExitStack() as held:
        for chain in CHAIN_FILES:
            if _unsafe_path(root, chain.parent, what="chain directory") is not None:
                # Refused as a source below, so not locked either: measured, the
                # take flocked a file outside the root through the symlink and
                # waited as long as anything held it (found by review).
                continue
            held.enter_context(AuditLogger(root / chain).reading())
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
        "format": MANIFEST_FORMAT,
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


def _require_format(manifest: object) -> None:
    """Refuse every manifest format but :data:`MANIFEST_FORMAT`, naming the recourse.

    A superseded format is refused with *why* and *what to do*: an operator
    holding only v1 backups in a disaster has no way to make this gate pass,
    and must know that before they read the refusal as "the restore is bad".
    """
    if not isinstance(manifest, dict):
        raise StoreError(
            f"the manifest is not a JSON object ({type(manifest).__name__}); a "
            f"{MANIFEST_FORMAT} manifest always is one, so this is a damaged or edited "
            "manifest and nothing in it can be compared"
        )
    found = manifest.get("format")
    if found == MANIFEST_FORMAT:
        return
    if isinstance(found, str) and found in SUPERSEDED_FORMATS:
        raise StoreError(
            f"backup format {found!r} is superseded by {MANIFEST_FORMAT!r} and is refused: "
            f"{SUPERSEDED_FORMATS[found]} This is not a verdict on the copy. Recourse: "
            "verify it with the repository revision that wrote it, and take a fresh backup "
            "with this version as soon as a live store exists — a backup in this format can "
            "never satisfy this gate"
        )
    # Capped: the repr of a 2 MB format string was 2,000,032 bytes of stderr.
    raise StoreError(
        f"unknown backup format {_capped(repr(found))}; this version verifies {MANIFEST_FORMAT!r}"
    )


#: Stands for "the manifest's store entry has no attestation at all", which is a
#: different finding from "the attestation is not an object" and must not become
#: a bare ``KeyError`` on the way to either.
_MISSING: object = object()

#: The attestation fields that count rows, and so are never negative.
_COUNTS: frozenset[str] = frozenset({"events", "observables"})


def _capped(text: str, limit: int = 80) -> str:
    """``text`` cut to ``limit`` characters: manifest content echoed into a report.

    Measured, a 2 MB manifest field became 2 MB of output and 4 MB of audit chain
    before anything bounded it.
    """
    return text if len(text) <= limit else text[:limit] + "..."


def _capped_tail(text: str, limit: int = 80) -> str:
    """``text`` cut to its last ``limit`` characters: a path whose end is the news."""
    return text if len(text) <= limit else "..." + text[-limit:]


# `_printable` (imported above from `scripts._terminal`): a report line can carry
# manifest content, and `_capped` bounds its length but not what it does.
# Measured, found by independent review: a `files[]` path of
# "/\x1b[2J\x1b[Hrestore verified: OK\r\n" cleared the operator's terminal and
# wrote a forged line, and a lone surrogate crashed the text report with a
# traceback partway through. Escaping where a line reaches the terminal covers
# every echo site at once; `--json` is already escaped by `json.dumps`.


#: How each attestation field must be typed to be comparable. ``bool`` is an
#: ``int`` subclass and is refused wherever an int is required.
_ATTESTATION_TYPES: dict[str, tuple[type, ...]] = {
    "events": (int,),
    "observables": (int,),
    "schema_version": (int,),
    "digest": (str,),
    "observables_digest": (str,),
    "high_water": (int, float, type(None)),
}


def _require_shape(manifest: dict[str, Any]) -> dict[str, Any]:
    """Refuse a manifest whose containers cannot be read, naming which and why.

    ``store`` and ``chains`` must be objects, ``files`` a list. Each was
    otherwise indexed blind downstream, which a damaged or edited manifest
    turned into a bare ``KeyError`` or ``TypeError`` — exit 1 for the wrong
    reason (found by independent review). Raised, like :func:`_require_format`,
    because nothing in such a manifest can be compared: this is not a verdict
    on the copy. A missing ``attestation`` is *not* raised here — it is a
    finding from :func:`_attestation_gaps`, beside everything else wrong.
    """
    for key, kind, what in (
        ("store", dict, "an object"),
        ("files", list, "a list"),
        ("chains", dict, "an object"),
    ):
        if key not in manifest:
            raise StoreError(
                f"the manifest has no {key!r}; a {MANIFEST_FORMAT} manifest always carries "
                "it, so this is a damaged or edited manifest and nothing in it can be compared"
            )
        if not isinstance(manifest[key], kind):
            raise StoreError(
                f"the manifest's {key!r} is not {what} ({type(manifest[key]).__name__}); a "
                f"{MANIFEST_FORMAT} manifest always carries one, so this is a damaged or "
                "edited manifest and nothing in it can be compared"
            )
    store_entry: dict[str, Any] = manifest["store"]
    return store_entry


def _attestation_gaps(expected: object) -> list[str]:
    """Findings for an attestation that cannot be compared field-for-field.

    Presence of every :data:`ATTESTATION_FIELDS` member and the type each
    must have (:data:`_ATTESTATION_TYPES`) — checked here, once, for both
    verifiers, and **checked rather than coerced**: the first version left the
    counts to "where they are compared", and there ``events`` went through
    ``int()``, so a manifest saying ``"40"`` or ``40.9`` verified green and
    ``null`` raised a bare ``TypeError`` (found by independent review).
    Returned as findings and not raised, so an operator sees them beside
    everything else wrong with the copy.
    """
    if expected is _MISSING:
        return [
            f"the manifest's store entry has no 'attestation'; a {MANIFEST_FORMAT} manifest "
            "always carries one, so this is a damaged or edited manifest and nothing in it "
            "can be compared"
        ]
    if not isinstance(expected, dict):
        return [
            f"the manifest's store attestation is not an object "
            f"({type(expected).__name__}); a {MANIFEST_FORMAT} manifest always carries "
            "one, so this is a damaged or edited manifest and nothing in it can be compared"
        ]
    gaps: list[str] = []
    # A field this version does not write is an edit, and --verify used to
    # flag one by comparing every key it found; comparing only the known
    # fields let an added one through at exit 0 (found by independent review).
    unknown = sorted(repr(key) for key in expected if key not in ATTESTATION_FIELDS)
    if unknown:
        gaps.append(
            f"the manifest's store attestation carries {len(unknown)} field(s) a "
            f"{MANIFEST_FORMAT} attestation never does ({_capped(', '.join(unknown))}), "
            "so this is a damaged or edited manifest"
        )
    for name in ATTESTATION_FIELDS:
        if name not in expected:
            gaps.append(
                f"the manifest's store attestation has no {name!r}. A {MANIFEST_FORMAT} "
                "attestation always carries it, so this is a damaged or edited manifest — "
                "refused rather than compared on what is left"
            )
            continue
        value = expected[name]
        kinds = _ATTESTATION_TYPES[name]
        if isinstance(value, bool) or not isinstance(value, kinds):
            want = (
                "an integer"
                if kinds == (int,)
                else "a string"
                if kinds == (str,)
                else "a number or null"
            )
            gaps.append(
                f"the manifest's store attestation {name!r} is not {want} "
                f"({_capped(repr(value))}, type {type(value).__name__}); it cannot be "
                "compared and the check is refused rather than coerced or skipped"
            )
        elif name in _COUNTS and isinstance(value, int) and value < 0:
            # A count is never negative; read as one, --verify-restore called the
            # live store's surplus expected re-collection (found by review).
            gaps.append(
                f"the manifest's store attestation {name!r} is negative ({value}); a "
                "count never is, so this is a damaged or edited manifest"
            )
    return gaps


#: The one path :func:`_take_backup` writes the store to, and so the only one
#: a manifest may name. See :func:`_load_manifest`.
_STORE_PATH = str(EVENTS_SUBDIR / DEFAULT_FILENAME)


def _is_count(value: object) -> bool:
    """A non-negative ``int`` that is not a ``bool`` (an ``int`` subclass)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _unreadable_manifest(directory: Path) -> str:
    """The refusal for a manifest this account may not read, which says nothing of its content.

    Not :func:`_malformed`'s "damaged or edited": measured, a backup under a
    mode this account could not read was reported as damaged, and one it could
    not search as a bare errno (found by review).
    """
    return (
        f"{MANIFEST_FILE} in {directory} cannot be read by this account (PermissionError); "
        "this says nothing about whether the backup is damaged. Check the modes and "
        "ownership of the backup and its directories, or run as the account that took it"
    )


def _malformed(directory: Path, what: str) -> StoreError:
    """The refusal for a manifest whose shape cannot be verified against."""
    return StoreError(
        f"{MANIFEST_FILE} in {directory}: {what}; refusing to verify against a "
        "damaged or edited manifest"
    )


def _store_path_problem(backup: Path, store_entry: dict[str, Any]) -> str | None:
    """Why the manifest's store path must not be opened, or ``None`` if it may be.

    Any path but :data:`_STORE_PATH` is this one's finding, escaping included;
    the canonical path is then walked by :func:`_unsafe_path` for a symlinked
    component. Both are findings rather than refusals,
    so an operator deciding whether to restore sees them beside everything
    else, and a verifier never opens a path this names a reason for: a store
    path naming another file in the backup sent ``--verify`` on to
    ``EventStore.open``, which created a store inside the backup under
    inspection (measured, found by independent review). ``path`` is a string;
    :func:`_load_manifest` checked that.
    """
    path = store_entry["path"]
    # The string first: walking a NUL-bearing or overlong path raised a bare
    # OSError that replaced the whole report (found by independent review).
    if path != _STORE_PATH:
        return (
            f"manifest store path {_capped(repr(path))} is not {_STORE_PATH!r}, the only "
            "path a backup writes, so it was not opened"
        )
    return _unsafe_manifest_path(backup, Path(path), what="manifest store path")


def _load_manifest_with_digest(directory: Path) -> tuple[dict[str, Any], str]:
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
    :func:`_verify_restore` already guards against, so a ``store.path`` that is
    not the one :func:`_take_backup` writes is never opened — reported as a
    finding by :func:`_store_path_problem`, not raised here, because #241
    settled that an escaping path is a finding an operator reads beside
    everything else. This function checks only that it is a string. Shape
    only: every digest, size and count is still compared by the callers, and
    the escape checks still run.

    **Format and containers are #241's checks**, :func:`_require_format` and
    :func:`_require_shape`, run here so both verifiers get them from one place,
    with the file named. The attestation is deliberately *not* checked here:
    :func:`_attestation_gaps` reports it as findings beside everything else
    wrong with the copy, which a raise from this function would hide.
    """
    manifest_path = directory / MANIFEST_FILE
    try:
        present = manifest_path.is_file()
    except PermissionError as exc:
        raise StoreError(_unreadable_manifest(directory)) from exc
    if not present:
        raise StoreError(f"no {MANIFEST_FILE} in {directory}; this is not a backup")
    # Bounded before it is parsed. Measured, a manifest extended to 1 TiB ended
    # both verifiers in a MemoryError traceback, and one of 2 GiB took 55 s and
    # 4.2 GB of memory before failing to decode (found by independent review).
    try:
        with _open_regular(manifest_path) as handle:
            raw = handle.read(MANIFEST_CAP + 1)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            # O_NOFOLLOW's refusal, which "cannot be read (OSError)" did not name
            # (found by review).
            raise _malformed(directory, "is a symlink, which a take never writes") from exc
        if isinstance(exc, PermissionError):
            raise StoreError(_unreadable_manifest(directory)) from exc
        raise _malformed(directory, f"cannot be read ({type(exc).__name__})") from exc
    if len(raw) > MANIFEST_CAP:
        raise _malformed(directory, f"is larger than {MANIFEST_CAP} bytes")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError; RecursionError
        # is json's own — measured, 100,000 nested `[` was a traceback in both modes.
        # MemoryError because the cap bounds bytes, not objects: measured, 64 MiB
        # of empty objects peaked at 1.69 GiB (found by review).
        raise _malformed(directory, f"cannot be decoded as JSON ({type(exc).__name__})") from exc
    try:
        _require_format(manifest)
        store_entry = _require_shape(manifest)
    except StoreError as exc:
        raise StoreError(f"{MANIFEST_FILE} in {directory}: {exc}") from exc
    if not isinstance(store_entry.get("path"), str) or not isinstance(
        store_entry.get("sha256"), str
    ):
        raise _malformed(directory, "store path and sha256 must be strings")
    if not _is_count(store_entry.get("size")):
        # Required, because it is what bounds the store's digest; every v2
        # manifest a take writes carries it.
        raise _malformed(directory, "store size must be a non-negative integer")
    for entry in manifest["files"]:
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
    chains = manifest["chains"]
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
    checked: dict[str, Any] = manifest  # a dict: _require_format refused anything else
    return checked, hashlib.sha256(raw).hexdigest()


def _load_manifest(directory: Path) -> dict[str, Any]:
    """Read and shape-check a manifest when its exact source bytes are not needed."""
    return _load_manifest_with_digest(directory)[0]


def _audit_anchor_path_problem(
    anchor: Path, *, root: Path, backup: Path, external: bool
) -> str | None:
    """Why an independently retained audit-chain anchor cannot be used."""
    if not anchor.is_absolute():
        return f"audit anchor {anchor} must be an absolute path"
    try:
        info = anchor.lstat()
    except OSError as exc:
        return f"audit anchor {anchor} cannot be inspected ({type(exc).__name__})"
    if stat.S_ISLNK(info.st_mode):
        return f"audit anchor {anchor} is a symlink"
    if not stat.S_ISREG(info.st_mode):
        return f"audit anchor {anchor} is not a regular file"
    if info.st_nlink != 1:
        return f"audit anchor {anchor} has {info.st_nlink} hard links"
    if external:
        try:
            resolved = Path(os.path.realpath(anchor))
        except (OSError, RecursionError, ValueError):
            return f"audit anchor {anchor} cannot be resolved safely"
        if resolved == root or root in resolved.parents:
            return "the --audit-anchor must be outside --root"
        if resolved == backup or backup in resolved.parents:
            return "the --audit-anchor must be outside the backup"
    signature = anchor.with_name(anchor.name + ".sig")
    checkpoint = anchor.with_name(anchor.name + ".checkpoint")
    lock = anchor.with_name(anchor.name + ".lock")
    if external:
        try:
            lock.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            return f"audit anchor lock sidecar {lock} cannot be inspected ({type(exc).__name__})"
        else:
            return (
                f"audit anchor lock sidecar {lock} is present; preserve the chain family "
                "without its lock files"
            )
    archive_prefix = anchor.name + "."
    total_bytes = 0
    family_files = 0
    directory_entries = 0
    try:
        with os.scandir(anchor.parent) as entries:
            for entry in entries:
                directory_entries += 1
                if directory_entries > AUDIT_ANCHOR_DIRECTORY_ENTRIES_CAP:
                    return (
                        "audit anchor directory has more than "
                        f"{AUDIT_ANCHOR_DIRECTORY_ENTRIES_CAP} entries"
                    )
                name = entry.name
                archive = name.startswith(archive_prefix) and name[len(archive_prefix) :].isdigit()
                if name not in {anchor.name, signature.name, checkpoint.name} and not archive:
                    continue
                family_files += 1
                if family_files > AUDIT_ANCHOR_FILES_CAP:
                    return f"audit anchor family has more than {AUDIT_ANCHOR_FILES_CAP} files"
                family_info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(family_info.st_mode) or family_info.st_nlink != 1:
                    return (
                        f"audit anchor family file {entry.path} is not a singly linked regular file"
                    )
                total_bytes += family_info.st_size
                if total_bytes > AUDIT_ANCHOR_BYTES_CAP:
                    return f"audit anchor family exceeds {AUDIT_ANCHOR_BYTES_CAP} bytes"
    except OSError as exc:
        return f"audit anchor family beside {anchor} cannot be inspected ({type(exc).__name__})"
    return None


def _manifest_anchor_problem(anchor: Path, manifest_sha256: str) -> tuple[str | None, str | None]:
    """Require the exact manifest digest in a verified take record.

    A configured audit verifier makes the record cryptographically verifiable;
    without one, the caller reports the unsigned chain-only posture explicitly.
    """
    logger = AuditLogger(anchor, signer=verifier_from_env())
    report, found = logger.find_record(
        lambda record: (
            record.get("decision") == "allow"
            and record.get("action_class") == BACKUP_CLASS
            and isinstance(record.get("action"), str)
            and str(record["action"]).startswith(f"{ACTION_NAME}:take:")
            and isinstance(record.get("reason"), str)
            and str(record["reason"]).endswith(f"manifest sha256 {manifest_sha256}")
        )
    )
    if not report.intact:
        return (
            f"manifest audit anchor {anchor} does not verify: {report.failure or report.signature}",
            report.signature,
        )
    if not found:
        return (
            f"manifest sha256 {manifest_sha256} has no matching take record in "
            f"audit anchor {anchor}",
            report.signature,
        )
    return None, report.signature


#: The files SQLite opens beside a database, and reads or writes through.
_SIDECARS = ("-wal", "-journal", "-shm")

#: How a non-regular sidecar is named in a finding.
_KINDS = (
    (stat.S_ISLNK, "a symlink"),
    (stat.S_ISDIR, "a directory"),
    (stat.S_ISFIFO, "a FIFO"),
    (stat.S_ISSOCK, "a socket"),
    (stat.S_ISCHR, "a character device"),
    (stat.S_ISBLK, "a block device"),
)


def _database_problem(db: Path, *, what: str) -> str | None:
    """Why ``db`` itself is unsafe to hand to SQLite, or ``None`` if absent or safe.

    The store's rule, not a copy of it: :func:`store.refuse_unsafe_database`
    decides, and this phrases its ``problem`` as a finding, because the
    verifiers report rather than raise. (:func:`_sidecar_problem` is a copy, from
    before the store had a check, and a test pins that the two name the same
    files; here ``tests/security/test_store_database_file.py`` pins that the
    finding carries the store's ``problem`` word for word.) Absent is ``None``: each caller says
    "missing" in its own terms after this has ruled out a file that is present
    but not usable.

    Called before ``is_file()`` everywhere it matters, because ``is_file()``
    follows the type: measured on the tree before this check, a FIFO at the
    store path read as "no event store" under the take, "is missing" under
    ``--verify`` and "no store at …" under ``--verify-restore``, all at exit 1
    and all naming the wrong thing. And a hard link is a regular file, so
    ``is_file()`` passed it: the take and both verifiers exited 0 over a store
    that shares its inode with another name, so a backup restored with
    ``cp -al`` would have verified clean and then changed with every write to
    the live store. The take's own source connection can write, too: after a
    killed writer it checkpoints the WAL into the file (see the module
    docstring), which through a link is a write to the other name.
    """
    try:
        refuse_unsafe_database(db)
    except StoreFileError as exc:
        return (
            f"{what} cannot be opened safely: it {exc.problem}. SQLite opens the store "
            "by name and writes it in place, so a FIFO would block it and a second link "
            "would receive its writes; the store was not opened"
        )
    return None


def _kind_of(mode: int) -> str:
    """How a file of ``mode`` that is not a regular file is named in a finding."""
    return next((name for test, name in _KINDS if test(mode)), "unrecognised")


def _sidecar_problem(db: Path, *, what: str) -> str | None:
    """Why a file beside ``db`` makes it unsafe to hand to SQLite, or ``None``.

    SQLite opens every sidecar with the database: it checkpoints a ``-wal``,
    replays a ``-journal``, and truncates and rewrites a ``-shm`` as its WAL
    index. Each must therefore be absent or a regular file with a single link.
    Measured, found by independent review:

    - a FIFO ``-journal`` hung both verifiers, and a plain take, inside the
      open while they held the backup lock, so every later pass skipped at
      exit 0; a FIFO ``-wal`` was deleted;
    - a symlinked, FIFO or directory ``-shm`` replaced the report with a bare
      SQLite error and left a new ``-wal`` in the tree under inspection;
    - a ``-shm`` **hard-linked** to another file had that file overwritten
      with 32 KiB of WAL index: the backup's own manifest, and the live
      store, were each destroyed under a run that exited 0 "verified".

    A hard link is a regular file, which is why the link count is checked
    with the type, and why this is one ``lstat`` per name. It is a check on
    the path, so a sidecar swapped in between it and the open is not caught:
    that needs write access to the directory, the same window
    :func:`_unsafe_to_open` already leaves.

    Every offending sidecar is named, with what is wrong with it, because the
    remedies differ: a FIFO or a symlink is never benign, while a second link
    can come from a hard-link copy of the tree (``cp -al``, ``rsync
    --link-dest``) and the size says whether a ``-wal`` holds frames (found by
    review: the first version named only the first sidecar, and only as "not a
    regular file with a single link").
    """
    reasons: list[str] = []
    for suffix in _SIDECARS:
        side = db.with_name(db.name + suffix)
        try:
            found = os.lstat(side)
        except FileNotFoundError:
            continue
        except OSError as exc:
            reasons.append(f"its {suffix} cannot be checked ({type(exc).__name__})")
            continue
        if not stat.S_ISREG(found.st_mode):
            kind = next((name for test, name in _KINDS if test(found.st_mode)), "unrecognised")
            reasons.append(f"its {suffix} is {kind}, not a regular file")
        elif found.st_nlink != 1:
            reasons.append(
                f"its {suffix} ({found.st_size} bytes) has {found.st_nlink} links: another "
                "name shares the file, and SQLite would write through both"
            )
    if not reasons:
        return None
    return (
        f"{what} cannot be opened safely: {'; '.join(reasons)}. SQLite opens every "
        "sidecar with the store, so the store was not opened"
    )


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
    that can write: the file's own type and link count
    (:func:`_database_problem`), size, the sidecars (:func:`_sidecar_problem`),
    the header bytes, and the schema catalogue through ``immutable=1``. Not ``mode=ro`` — measured, that left
    ``-wal`` and ``-shm`` behind in the backup after close; ``immutable=1``
    touched nothing. It ignores a WAL, which is why a non-empty one is refused
    on its own rather than read through. A reason is a reported problem and
    not a raise, so the rest of the report still runs.

    The link count is checked first, and that is what now covers the hard-linked
    0-byte case above, not only the size: a *non-empty* store hard-linked to a
    name outside the backup passed every check here and verified clean at exit 0,
    measured, and ``EventStore.open`` itself now refuses it, which would have
    replaced this report with a bare error. Callers have already confirmed
    ``is_file()``, so a FIFO cannot reach this function; they ask
    :func:`_database_problem` themselves when ``is_file()`` fails.
    """
    database = _database_problem(db, what=what)
    if database is not None:
        return database
    size = db.stat().st_size
    if size == 0:
        return (
            f"{what} is 0 bytes, a truncated transfer; SQLite treats an empty file as a "
            "new database and opening it would initialise it, so it was not opened"
        )
    sidecar = _sidecar_problem(db, what=what)
    if sidecar is not None:
        return sidecar
    wal = db.with_name(db.name + "-wal")
    if wal.is_file() and wal.stat().st_size:
        return (
            f"{what} has a {wal.stat().st_size}-byte -wal beside it that was never "
            "checkpointed; opening it would checkpoint those frames into the file, so it "
            "was not opened"
        )
    journal = db.with_name(db.name + "-journal")
    if journal.is_file() and journal.stat().st_size:
        # Measured, found by independent review: a hot rollback journal planted
        # beside a WAL-mode store was replayed into it on open, the store's
        # sha256 changed, the journal was deleted and the run exited 0.
        return (
            f"{what} has a {journal.stat().st_size}-byte -journal beside it; opening it "
            "would replay that journal into the file, so it was not opened"
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


def _verify_backup(directory: Path, *, audit_anchor: Path) -> dict[str, object]:
    """Re-check a backup against its manifest and the source-chain digest anchor.

    Collects findings rather than raising on the first, because an operator
    deciding whether to restore from this copy needs to know everything that
    is wrong with it, not the first thing.

    The audit anchor is the live source events chain; this check refuses a
    manifest whose raw bytes were not recorded by the take.

    **What this writes, stated exactly.** The *bytes* of every file it reads,
    the store included, are left as found — :func:`_unsafe_to_open` names the
    cases that used to be initialised in place. Two things still change under
    it: ``EventStore.open`` narrows the store and its directory to owner-only
    if a transfer left them wider (a mode change, in the direction
    :func:`_take_backup` writes), and the WAL sidecars it creates while open
    are removed on close. Content-neutral is the claim; metadata-neutral is not.
    """
    manifest, manifest_sha256 = _load_manifest_with_digest(directory)

    problems: list[str] = []
    anchor_problem, anchor_signature = _manifest_anchor_problem(audit_anchor, manifest_sha256)
    if anchor_problem is not None:
        problems.append(anchor_problem)

    store_entry: dict[str, Any] = manifest["store"]  # shape-checked by _load_manifest
    # Bound before the branches below: the return reads it on every path, and
    # only one of the three reaches the attestation comparison. Binding it inside
    # that branch raised UnboundLocalError on a backup whose store was missing or
    # whose store path escaped — a regression the base branch did not have, found
    # by independent review; no test covered either input.
    expected = store_entry.get("attestation", _MISSING)
    gaps = _attestation_gaps(expected)
    problems.extend(gaps)
    unsafe = _store_path_problem(directory, store_entry)
    if unsafe is not None:
        # A path that escapes, or names any file but the store, is a tamper
        # indicator, so it is reported rather than followed — and reported as a
        # problem rather than raised, so an operator deciding whether to restore
        # sees everything at once.
        problems.append(unsafe)
        store_entry = {**store_entry, "path": None}
    db = directory / str(store_entry["path"]) if store_entry["path"] else None
    if db is None:
        pass
    elif not db.is_file():
        # A FIFO or a directory fails is_file() and is not missing: name what is there.
        problems.append(
            _database_problem(db, what=str(store_entry["path"]))
            or f"{store_entry['path']} is missing"
        )
    else:
        size, actual = _digest_exact(db, store_entry["size"])
        if actual is None:
            problems.append(
                f"{_size_finding(store_entry['path'], size, store_entry['size'])}, "
                "so it is not the backed-up store and was not read further"
            )
        elif actual != store_entry["sha256"]:
            problems.append(
                f"{store_entry['path']}: sha256 {actual} does not match the manifest's "
                f"{_capped(store_entry['sha256'])}"
            )
        unopenable = _unsafe_to_open(db, what=str(store_entry["path"]))
        if unopenable is not None:
            problems.append(unopenable)
        elif actual is None:
            # Not opened: the size already says this is not the store that was
            # backed up, so attesting it answers nothing, and opening it would
            # write SQLite's -wal and -shm into the backup for no verdict.
            pass
        else:
            with EventStore.open(directory) as copy:
                attested = copy.attest().to_dict()
            # Compared only when every field is there. The first version of this
            # change still indexed `expected["events"]` below after reporting it
            # missing, so the operator saw a bare KeyError on stderr and not the
            # finding — exit 1 for the wrong reason, which a test caught.
            for key in ATTESTATION_FIELDS if not gaps else ():
                if attested.get(key) != expected[key]:
                    problems.append(
                        f"store attestation {key}: {attested.get(key)!r} does not match "
                        f"the manifest's {_capped(repr(expected[key]))}"
                    )

    for entry in manifest["files"]:
        unsafe = _unsafe_manifest_path(directory, Path(str(entry["path"])), what="manifest path")
        if unsafe is not None:
            problems.append(unsafe)
            continue
        path = directory / str(entry["path"])
        if not path.is_file():
            problems.append(f"{entry['path']} is missing")
            continue
        size, actual = _digest_exact(path, entry["size"])
        if actual is None:
            problems.append(_size_finding(entry["path"], size, entry["size"]))
        elif actual != entry["sha256"]:
            problems.append(f"{entry['path']}: sha256 {actual} != {_capped(entry['sha256'])}")

    # The chains are re-verified now, not trusted from the manifest: a chain
    # recorded intact at backup time and broken since is exactly what this is
    # for. Only where the manifest bounds the read; see _unbounded_chain.
    sizes = {str(entry["path"]): entry["size"] for entry in manifest["files"]}
    unbounded = {
        chain: reason
        for chain in CHAIN_FILES
        if (reason := _unbounded_chain(directory, chain, sizes)) is not None
    }
    chains = _verify_chains(directory, skip=unbounded)
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
            if state.get("skipped"):
                problems.append(str(state.get("failure")))
            elif recorded.get("present") and recorded.get("intact") is False:
                # Not "no longer": the take's own check already failed it.
                problems.append(
                    f"{name}: chain does not verify, and did not when the backup was taken "
                    f"either: {state.get('failure')}"
                )
            else:
                problems.append(f"{name}: chain no longer verifies: {state.get('failure')}")
    problems.extend(_events_chain_problems(manifest))
    problems.extend(_backup_inventory_problems(directory, manifest))

    return {
        "backup": str(directory),
        "taken_at": manifest.get("taken_at"),
        # Only a checked value: this lands in the audit record's action, where a
        # manifest's '|' suppressed the whole report (found by independent review).
        "events": expected["events"] if not gaps else None,
        "verified": not problems,
        "problems": problems,
        "chains": chains,
        "manifest_anchor_signature": anchor_signature,
    }


def _verify_restore(root: Path, backup: Path, *, audit_anchor: Path) -> dict[str, object]:
    """Verify the **live** ``root`` holds what ``backup``'s manifest attested.

    The promotion gate. The independent ``audit_anchor`` is the source events
    chain preserved outside the live root and backup before step 4. ``--verify``
    checks a backup against its manifest
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

    **And a fourth, found on the fix for the first.** An observable *count*
    is not a commitment to contents: rows replaced one-for-one left the count,
    the event count, the event digest and ``quick_check`` all satisfied. The
    attestation now carries ``observables_digest`` and the manifest format is
    :data:`MANIFEST_FORMAT`; a v1 manifest is refused by
    :func:`_require_format` with the recourse named, and a v2 manifest missing
    any attestation field is refused by :func:`_attestation_gaps` rather than
    compared on what is left.

    **The gate's own head signature is judged by its chain, not by its bytes,
    when a key is set** — and that is a fix, not a relaxation. The old classifier
    prefix-compared it, so with ``AUDIT_HMAC_KEY`` set this gate failed every
    correct restore: the gate decision re-signs ``data/events/audit.log`` before
    the comparison reads its ``.sig``. That one signature
    (:data:`GATE_SIGNATURE`) must still be present, and is excused its bytes only
    where :func:`_verify_chains` found it valid for the current head (or the
    chain is already a finding) — see :func:`_signature_judged`. With no key
    nothing re-signed it, so it is compared exactly. **Every other signature is
    compared exactly, key or not**: nothing rewrites its chain in this window, and
    the signature check reads three fields of the sidecar and no others.
    """
    manifest, manifest_sha256 = _load_manifest_with_digest(backup)

    problems: list[str] = []
    anchor_problem, anchor_signature = _manifest_anchor_problem(audit_anchor, manifest_sha256)
    if anchor_problem is not None:
        problems.append(anchor_problem)
    store_entry: dict[str, Any] = manifest["store"]  # shape-checked by _load_manifest
    expected = store_entry.get("attestation", _MISSING)
    gaps = _attestation_gaps(expected)
    problems.extend(gaps)
    # Never opened here (the live store is), but a tamper indicator all the same.
    store_path = _store_path_problem(backup, store_entry)
    if store_path is not None:
        problems.append(store_path)
    live_events: int | None = None

    # The store. Existence is checked FIRST and deliberately: EventStore.open
    # CREATES the database if absent, so opening it blind would have this
    # verification manufacture an empty store and then report the loss of every
    # event — a read-only check that writes the thing it was asked to inspect.
    # And existence is not enough: an existing EMPTY file was created into
    # regardless (measured, 0 -> 61440 bytes with the schema), so whether
    # opening would write is checked next. See _unsafe_to_open.
    db = root / EVENTS_SUBDIR / DEFAULT_FILENAME
    if gaps:
        # Refused above, by name, per missing field. Not compared "as far as
        # possible": passing a copy on the checks a verifier happens to be able
        # to run is how a substituted observables table reached a green verdict.
        problems.append(
            "the store was not compared: the manifest's attestation is unusable (see the "
            "findings above), and a comparison against part of it would be a verdict on "
            "part of the evidence"
        )
    elif (
        live_path := _unsafe_manifest_path(
            root, EVENTS_SUBDIR / DEFAULT_FILENAME, what="the live store"
        )
    ) is not None:
        # Walked as the backup side's store path is. A symlinked live store
        # reached EventStore.open, whose confine() raised and replaced the whole
        # report with a bare error (found by independent review); and SQLite
        # looks for the sidecars beside the target, not beside the link.
        problems.append(live_path)
    elif not db.is_file():
        # As in _verify_backup: a FIFO or a directory here is a finding, not an absence.
        problems.append(
            _database_problem(db, what=f"the live store {db}")
            or f"no store at {db}: the restore did not put one there, and this check will "
            "not create one to measure"
        )
    elif _same_file(db, backup / EVENTS_SUBDIR / DEFAULT_FILENAME):
        # Identity, which no comparison can see: a hard-linked store compares
        # equal to itself. Not opened, so nothing here touches the backup's own
        # file. See _linked_to_backup.
        problems.append(_linked(EVENTS_SUBDIR / DEFAULT_FILENAME))
    elif (unopenable := _unsafe_to_open(db, what=f"the live store {db}")) is not None:
        problems.append(unopenable)
    else:
        with EventStore.open(root) as live:
            attested = live.attest().to_dict()
        live_events = int(attested.get("events", -1))
        # Not int(): coercion accepted "40" and 40.9 and raised a bare TypeError
        # on null. _attestation_gaps guarantees an int here or the block is skipped.
        want_events = expected["events"]
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
                f"{want_events}. Re-collection (docs/RESTORE.md step 5) does this and is "
                "the expected cause — this check belongs between steps 4 and 5. It cannot, "
                "however, tell re-collection from substitution plus addition: once rows were "
                "added the digest necessarily differs. If you have NOT run step 5, treat "
                "this as SUBSTITUTED"
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
        # exit 0. An indicator pivot (`query(observable=...)`) returns nothing on a
        # store this gate had just called verified. (Not correlation: measured,
        # `correlation/entities.py` never reads `observables`; an earlier version
        # of this comment said it joined on this table.)
        #
        # The manifest already carried the number: `attestation.to_dict()` is
        # stored whole, so this reads a field that was sitting in the file.
        live_observables = attested["observables"]
        want_observables = expected["observables"]
        want_digest = expected["observables_digest"]
        # Types were checked by _attestation_gaps, in one place for both
        # verifiers. This block used to check them here — the manifest side
        # duplicating that, the live side vacuous (attest() returns a typed
        # dataclass) — while `events` two blocks up went through int() and
        # was never checked at all. Checked, not coerced, upstream.
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
                "step 5) does this and is the expected cause. It cannot, however, tell "
                "re-collection from substitution plus addition: once rows were added the "
                "observables digest necessarily differs. If you have NOT run step 5, "
                "treat this as SUBSTITUTED"
            )
        elif attested["observables_digest"] != want_digest:
            # Equal count, different rows. The event count, the event digest
            # and quick_check are all satisfied in this state; this digest is
            # the only check that sees it.
            problems.append(
                f"SUBSTITUTED: the live store holds exactly {live_observables} "
                "observable(s) as attested, but not the same rows — the observables "
                "digest differs. An indicator pivot on this store returns events for "
                "values the backup never held. This is not the store that was backed up"
            )

        # The two attestation fields this verifier never read while `--verify`
        # compared all six (found by independent review). schema_version always:
        # a copy restored onto a different schema is a migration question and is
        # never expected between steps 4 and 5. high_water only when the event
        # count matched: with rows added or lost the mark necessarily moved and
        # LOSS/ADDED already names the cause.
        if attested["schema_version"] != expected["schema_version"]:
            problems.append(
                f"store attestation schema_version: {attested['schema_version']!r} does not "
                f"match the manifest's {expected['schema_version']!r} — a migration question, "
                "not a completeness one, and not expected between docs/RESTORE.md steps 4 and 5"
            )
        if live_events == want_events and attested["high_water"] != expected["high_water"]:
            problems.append(
                f"store attestation high_water: {attested['high_water']!r} does not match "
                f"the manifest's {expected['high_water']!r} while the event count does — the "
                "mark moved without the count, which no restore step does"
            )

    # Declared files. Prefix comparison for the append-only streams only; exact
    # equality for everything else. See _is_append_only for why the allow-list
    # is on the growing side.
    declared: set[Path] = set()
    gate_signature: str | None = None
    for entry in manifest["files"]:
        entry_path = Path(str(entry["path"]))
        unsafe = _unsafe_manifest_path(root, entry_path, what="manifest path")
        if unsafe is not None:
            problems.append(unsafe)
            continue
        declared.add(entry_path)
        path = root / entry_path
        backed_up = int(entry["size"])
        if not path.is_file():
            problems.append(f"{entry['path']} is missing from the live root")
            continue
        if _same_file(path, backup / entry_path):
            # Equal to the backup by construction, so no comparison below can
            # fail; the finding is the identity itself.
            problems.append(_linked(entry_path))
            continue
        links = path.lstat().st_nlink
        if links > 1:
            # Not the argued backup's, so identity cannot see it: measured, a
            # restore hard-linked from a second copy of the backup, or by rsync
            # --link-dest from the previous one, passed 4b at exit 0, and the
            # gate itself or step 5 then wrote into that copy (found by
            # independent review). A copied restore leaves one link.
            problems.append(_shared_live_file(entry_path, links))
            continue
        if entry_path == GATE_SIGNATURE:
            # The one signature this command re-signs (see GATE_SIGNATURE); every
            # other falls through to the exact comparison below. Its bytes are
            # compared NOW, so the chain report is the last read this pass makes,
            # and whether the finding stands is decided from that report without
            # touching the disk again (a second review round found reads after it).
            gate_signature = _altered(entry, path)
            continue
        if not _is_append_only(entry_path):
            if (altered := _altered(entry, path)) is not None:
                problems.append(altered)
            continue
        live_size = path.stat().st_size
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
        try:
            found = os.lstat(root / relative)
        except FileNotFoundError:
            continue
        except OSError as exc:
            problems.append(
                f"POSITION PRESENT: {relative} cannot be checked ({type(exc).__name__})"
            )
            continue
        if stat.S_ISDIR(found.st_mode):
            # Step 3's rm -f does not remove a directory (found by review); it
            # does remove a FIFO, a socket or a symlink.
            problems.append(
                f"POSITION PRESENT: {relative} in the live root is a directory, which no pass "
                "writes and step 3's rm -f does not remove. Move it out of the root and keep "
                "it for investigation, then re-run this check"
            )
            continue
        kind = "" if stat.S_ISREG(found.st_mode) else f" (as {_kind_of(found.st_mode)})"
        problems.append(
            f"POSITION PRESENT: {relative} exists in the live root{kind}. "
            f"docs/RESTORE.md step 3 removes it before the store comes back, because "
            f"{why.split(':')[0]}"
        )

    # The backed-up chains, authenticated where their signatures still mean
    # something; the live ones below show only that each continues cleanly.
    problems.extend(_backed_up_chain_problems(backup, manifest))

    # Not through a symlinked chain directory: measured, data/compliance
    # pointed outside the root passed at exit 0 "every chain still verifies"
    # (found by review).
    unsafe_chains = {
        chain: f"{chain}: not verified: {reason}"
        for chain in CHAIN_FILES
        if (reason := _unsafe_manifest_path(root, chain.parent, what="live chain directory"))
        is not None
    }
    problems.extend(unsafe_chains.values())
    for chain, leftovers in _undeclared_chain_segments(root, manifest, skip=unsafe_chains).items():
        problems.extend(leftovers)
        unsafe_chains[chain] = (
            f"{chain}: not verified, because a segment beside it is not in the backup "
            "(see the UNDECLARED finding)"
        )

    # Chains, verified LAST: after every stream, report and signature above was
    # read. A prefix comparison allows any growth, so a chain report taken before
    # any of those reads missed whatever an unquiesced writer appended during
    # them (found by review, twice). What lands after this read is unseen in any
    # order; nothing below touches the disk.
    chains = _verify_chains(root, skip=unsafe_chains)

    # The gate's own signature, from that same report. Where it verified the
    # signature — present, under the key, covering the current head — or already
    # reports the chain broken, the byte finding is dropped: this command's gate
    # decision replaced data/events/audit.log.sig whole before any of this ran,
    # which failed every correct signed restore as REWRITTEN. Otherwise (no key)
    # nothing re-signed it, so it must be the backed-up file.
    if gate_signature is not None and not _signature_judged(chains.get(str(GATE_CHAIN))):
        problems.append(gate_signature)

    # Chains: entries may only GROW, and must still verify.
    for name, state in sorted(chains.items()):
        if not isinstance(state, dict) or state.get("skipped"):
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
        # .get, not []: with a field missing the attestation was refused above
        # by name, and indexing it here turned that finding into a bare
        # `error: 'events'` on stderr — measured, exit 1 with an empty stdout.
        # Only a checked value: this lands in the audit record's action, where a
        # manifest's '|' suppressed the whole report (found by independent review).
        "events": expected["events"] if not gaps else None,
        "live_events": live_events,
        "verified": not problems,
        "problems": problems,
        "chains": chains,
        "manifest_anchor_signature": anchor_signature,
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
            "chain, and checks the raw manifest digest against the source "
            "events audit chain (current --root by default); exits 1 on any mismatch."
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
            "steps 4 and 5 of docs/RESTORE.md; exits 1 on any mismatch. Requires "
            "--audit-anchor, the independently preserved source audit chain from step 4a. "
            "It speaks only about the copy and says nothing about whether exactly one "
            "node is active."
        ),
    )
    parser.add_argument(
        "--audit-anchor",
        type=Path,
        default=None,
        metavar="AUDIT_LOG",
        help=(
            "The independently preserved source data/events/audit.log. Required for "
            "--verify-restore; optional for --verify when the source --root is unavailable. "
            "Must be an absolute path outside --root and the backup."
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
    if args.audit_anchor is not None and args.verify is None and args.verify_restore is None:
        parser.error("--audit-anchor is only used with --verify or --verify-restore")
    if args.verify_restore is not None and args.audit_anchor is None:
        parser.error(
            "--verify-restore requires --audit-anchor: pass the independently preserved "
            "source data/events/audit.log from docs/RESTORE.md step 4a"
        )
    return args


def main(argv: list[str] | None = None) -> int:
    # A character the terminal's encoding cannot represent is escaped, not
    # raised: measured, an accented letter in a manifest path under a
    # non-UTF-8 stdout cut the report off with a traceback (found by independent
    # review). _printable handles control characters; this handles the encoding.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    args = _parse_args(argv)
    started_at = time.monotonic()

    try:
        root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("backup", args.caller)
        name = args.name or f"backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        destination = confine(root, BACKUP_SUBDIR, name, error=StoreError, what="backup")
        # The gate decision is the first write of every mode, so its path is
        # confined before anything is written. AuditLogger refuses a symlink only
        # at the leaf, and measured, a data/events linked into a backup took the
        # gate record into that backup's chain, which then failed --verify for
        # good; a --verify of another backup did it at exit 0 (found by
        # independent review).
        try:
            confine(root, AUDIT_SUBDIR, AUDIT_FILE, error=StoreError, what="audit log")
        except OSError as exc:
            # Not a symlink but not checkable (an unsearchable data/events): the
            # failure the AuditLogger line in _run reports, with its exit code,
            # rather than a bare errno at the arguments' exit 2 (found by review).
            print(
                f"error: audit log unusable, refusing to run: {_printable(str(exc))}",
                file=sys.stderr,
            )
            return 1
        argued = args.verify if args.verify is not None else args.verify_restore
        # Before the lock, which is created under --root: a --root that is a
        # backup would put a lock, and then audit records, inside it. A bad
        # argument, so exit 2, as the exit-code tables say.
        try:
            resolved = _resolve_argument(argued) if argued is not None else None
        except StoreError:
            resolved = None  # refused by name in _run, at exit 1
        inside = _root_in_backup(root, resolved)
        if inside is not None:
            print(f"error: {_printable(inside)}", file=sys.stderr)
            return 2
        if args.verify_restore is not None and resolved is not None:
            if args.audit_anchor is None:
                print(
                    "error: --verify-restore requires --audit-anchor",
                    file=sys.stderr,
                )
                return 2
            refusal = _audit_anchor_path_problem(
                args.audit_anchor, root=root, backup=resolved, external=True
            )
            if refusal is not None:
                print(f"error: {_printable(refusal)}", file=sys.stderr)
                return 1
        elif args.verify is not None:
            if args.audit_anchor is not None:
                external_anchor = True
                verify_anchor = args.audit_anchor
            else:
                external_anchor = False
                verify_anchor = root / GATE_CHAIN
            if external_anchor and not verify_anchor.is_absolute():
                print("error: --audit-anchor must be an absolute path", file=sys.stderr)
                return 1
            refusal = _audit_anchor_path_problem(
                verify_anchor,
                root=root,
                backup=resolved or root,
                external=external_anchor,
            )
            if refusal is not None:
                print(f"error: {_printable(refusal)}", file=sys.stderr)
                return 1
        engine = load_bundle(args.policy)
        # Last in the startup try, deliberately: the only statement here that
        # opens a descriptor, so nothing can fail after it and abandon the handle.
        lock = prepare_lock(
            root / BACKUP_SUBDIR, VERIFY_LOCK_FILE if args.verify is not None else LOCK_FILE
        )
    except (PrincipalError, PolicyBundleError, StoreError, ValueError, OSError) as exc:
        print(f"error: {_printable(str(exc))}", file=sys.stderr)
        return 2

    # Wrapped because the startup `try` has already closed by here, and a
    # lock that fails for a reason that is NOT contention must still be a
    # message and exit 2 rather than a traceback in cron mail. The caught
    # type is deliberately specific: a bare `except OSError` around this
    # block would relabel any failure inside the pass as a lock problem.
    try:
        with single_instance(lock) as acquired:
            if not acquired:
                which = "verify" if args.verify is not None else "backup"
                message = (
                    f"skipped: another {which} pass holds the lock; this invocation did nothing."
                )
                if args.verify is None and args.verify_restore is None:
                    if args.json:
                        print(json.dumps({"skipped": True, "reason": message}))
                    else:
                        print(message)
                    return 0
                # A gate that verified nothing must not exit like one that
                # passed: measured, a tampered backup cleared docs/RESTORE.md
                # step 2 at exit 0 while a scheduled verify held the lock, and
                # step 4b while a take did (found by independent review).
                message += " Nothing was verified."
                if args.json:
                    print(json.dumps({"skipped": True, "verified": False, "reason": message}))
                else:
                    print(message)
                return EXIT_SKIPPED_VERIFY
            return _run(
                args,
                root=root,
                destination=destination,
                principal=principal,
                engine=engine,
                started_at=started_at,
            )

    except LockUnavailableError as exc:
        print(f"error: {_printable(str(exc))}", file=sys.stderr)
        return 2


def _resolve_argument(path: Path) -> Path:
    """The backup a ``--verify`` or ``--verify-restore`` argument names, resolved.

    ``realpath`` rather than ``Path.resolve()``, which raises RuntimeError on a
    symlink loop on 3.11 and 3.12, so a planted loop was a traceback. And guarded,
    because ``realpath`` itself recurses once per link there: a chain of about a
    thousand links raised RecursionError, also a RuntimeError, and also a
    traceback (both found by independent review). Either becomes a refusal
    beside the others, at exit 1.
    """
    try:
        return Path(os.path.realpath(path))
    except RecursionError:
        raise StoreError(
            f"{path} is a chain of more symbolic links than can be followed; this is not a backup"
        ) from None


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

    # Before the gate record, which is every mode's first write and appends to
    # the live events chain. The argument is resolved once, here, so a link
    # chain too deep to follow is refused before anything is written: measured,
    # the check below fell open on it and the gate record landed in the backup
    # (found by independent review).
    restore_from: Path | None = None
    verify_from: Path | None = None
    restore_anchor: Path | None = None
    try:
        if mode == "verify-restore":
            restore_from = _resolve_argument(args.verify_restore)
            if args.audit_anchor is None:
                raise StoreError("--verify-restore requires --audit-anchor")
            if not args.audit_anchor.is_absolute():
                raise StoreError("--audit-anchor must be an absolute path")
            restore_anchor = args.audit_anchor
        elif mode == "verify":
            verify_from = _resolve_argument(args.verify)
    except StoreError as exc:
        print(f"error: {_printable(str(exc))}", file=sys.stderr)
        return 1
    refusal = (
        _linked_to_backup(root, restore_from) if restore_from is not None else None
    ) or _linked_live_chain(root)
    if refusal is None and restore_from is not None:
        refusal = _live_chain_bound(root, restore_from)
    if refusal is not None:
        print(f"error: {_printable(refusal)}", file=sys.stderr)
        return 1
    if restore_from is not None and restore_anchor is not None:
        refusal = _audit_anchor_path_problem(
            restore_anchor, root=root, backup=restore_from, external=True
        )
        if refusal is not None:
            print(f"error: {_printable(refusal)}", file=sys.stderr)
            return 1
    verify_anchor = root / GATE_CHAIN
    if verify_from is not None:
        if args.audit_anchor is not None:
            external_anchor = True
            if not args.audit_anchor.is_absolute():
                print("error: --audit-anchor must be an absolute path", file=sys.stderr)
                return 1
            verify_anchor = args.audit_anchor
        else:
            external_anchor = False
        refusal = _audit_anchor_path_problem(
            verify_anchor,
            root=root,
            backup=verify_from,
            external=external_anchor,
        )
        if refusal is not None:
            print(f"error: {_printable(refusal)}", file=sys.stderr)
            return 1

    try:
        signer = signer_from_env()
        if mode == "verify-restore" and signer is None and verifier_from_env() is not None:
            # A verify-only node (AUDIT_ED25519_PUBLIC_KEY alone). The gate
            # decision below is appended to the restored events chain before
            # anything is verified, and this node cannot sign it: the restored
            # head would be left unsigned and then reported stale, a red verdict
            # this pass caused, written into the chain it was asked to inspect.
            # Refused before that write instead.
            raise ValueError(
                "this node can verify Ed25519 signatures (AUDIT_ED25519_PUBLIC_KEY) but cannot "
                "sign (no AUDIT_ED25519_PRIVATE_KEY). --verify-restore records its gate "
                f"decision in {GATE_CHAIN} first, which would leave the restored chain's head "
                "unsigned. Run it where the private key is set (the node being promoted needs "
                "it to write anyway), or check the chains read-only with scripts.audit_verify"
            )
        audit = AuditLogger(root / AUDIT_SUBDIR / AUDIT_FILE, signer=signer)
    except (OSError, ValueError, MemoryError, RecursionError) as exc:
        print(
            f"error: audit log unusable, refusing to run: {_printable(str(exc))}", file=sys.stderr
        )
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
    except (AuditFieldError, OSError, ValueError, MemoryError, RecursionError) as exc:
        # MemoryError and RecursionError: appending reads the head segment
        # whole and parses its last line (see _live_chain_bound).
        print(
            "error: could not record the gate decision: "
            f"{_printable(str(exc) or type(exc).__name__)}",
            file=sys.stderr,
        )
        return 1

    try:
        if verify_from is not None:
            payload = _verify_backup(verify_from, audit_anchor=verify_anchor)
        elif restore_from is not None:
            if restore_anchor is None:
                raise StoreError("--verify-restore requires --audit-anchor")
            payload = _verify_restore(root, restore_from, audit_anchor=restore_anchor)
        else:
            manifest = _take_backup(root, destination)
            manifest_path = destination / MANIFEST_FILE
            # Written whole under a temporary name and renamed into place, so a
            # --verify, which no longer waits for a take, sees either no
            # manifest or a complete one; and hashed from the bytes written,
            # not re-read.
            serialized = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            staging = destination / f".{MANIFEST_FILE}.tmp"
            staging.write_bytes(serialized)
            staging.chmod(FILE_MODE)
            staging.replace(manifest_path)
            attestation = manifest["store"]["attestation"]  # type: ignore[index]
            payload = {
                "backup": str(destination),
                "taken_at": manifest["taken_at"],
                "events": attestation["events"],
                "digest": attestation["digest"],
                "files": len(manifest["files"]),  # type: ignore[arg-type]
                "manifest_sha256": hashlib.sha256(serialized).hexdigest(),
                "excluded": sorted(EXCLUDED),
                "refused": manifest["refused"],
                "wide_paths": _wide_paths(root),
                # The take's own verdict on what it copied, which only the
                # manifest carried: measured, a take whose copy was torn exited
                # 0 "wrote" and the next --verify called it a chain that "no
                # longer verifies" (found by independent review).
                "chains_broken": [
                    f"{name}: {state.get('failure')}"
                    for name, state in sorted(manifest["chains"].items())  # type: ignore[attr-defined]
                    if isinstance(state, dict) and state.get("present") and not state.get("intact")
                ],
            }
    except (StoreError, sqlite3.Error, ValueError, OSError, KeyError) as exc:
        # sqlite3.Error is neither OSError nor StoreError, so a corrupt or
        # locked database would otherwise escape as a traceback in cron mail.
        # Contention first, since it is also a `sqlite3.Error`: a backup that
        # could not get a read snapshot has taken nothing and left nothing,
        # which is the retryable case and not the damaged one.
        if is_retryable_contention(exc):
            print(
                f"error: the store is busy, no backup was taken: {_printable(str(exc))}",
                file=sys.stderr,
            )
            return EXIT_RETRYABLE
        print(f"error: {_printable(str(exc))}", file=sys.stderr)
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
    except (AuditFieldError, OSError, ValueError, MemoryError, RecursionError) as exc:
        print(
            f"error: pass ran but could not be recorded: {_printable(str(exc) or type(exc).__name__)}",
            file=sys.stderr,
        )
        return 1

    try:
        if args.json:
            payload["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
            print(json.dumps(payload, sort_keys=True, default=str))
        else:
            _print_text(payload, mode=mode)
    except OSError as exc:
        print(
            f"error: pass ran but its report could not be written: {_printable(str(exc))}",
            file=sys.stderr,
        )
        return 1

    if verifying and not payload["verified"]:
        return 1
    return 0


def _print_text(payload: dict[str, object], *, mode: str) -> None:
    def say(line: str) -> None:
        # Every line, not only those known to carry manifest text: the subject
        # and success lines carry a resolved path, which a planted symlink can
        # make anything (found by independent review).
        print(_printable(line))

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
            signature = str(payload.get("manifest_anchor_signature", "unknown"))
            say(f"  manifest audit-anchor signature: {signature}")
            if signature in {"unsigned", "empty"}:
                say(
                    "  NOTE: the source audit chain is internally consistent but unsigned; "
                    "it does not cryptographically authenticate the manifest against an "
                    "attacker able to rewrite that chain."
                )
            if restored:
                say(
                    f"restore verified: {payload['root']} holds the "
                    f"{payload['events']} event(s) {payload['backup']} attested, every "
                    "declared stream carries the backed-up history as a prefix, every "
                    "other declared file is unchanged, and every chain still verifies "
                    "(head signatures included, when a key is set)."
                )
                # Said on success, not only in the docs, because a green line
                # here is exactly what an operator will quote as justification
                # for promoting — and it does not justify that.
                say(
                    "  NOTE: this verifies the COPY. It says nothing about the fence — "
                    "whether the former active node's timers are stopped. That is "
                    "procedural; see DESIGN.md's active/passive row and docs/RESTORE.md."
                )
                return
            say(
                f"verified {payload['backup']}: {payload['events']} event(s), "
                f"attestation and every file digest match the manifest."
            )
            return
        say(f"FAILED to verify {subject}: {len(problems)} problem(s)")
        for problem in problems:
            say(f"  - {problem}")
        return
    say(
        f"wrote {payload['backup']}: {payload['events']} event(s), "
        f"{payload['files']} file(s) beside the store."
    )
    say(f"  completeness digest {payload['digest']}")
    say(
        "  positions are not in this backup by design "
        f"({', '.join(sorted(EXCLUDED))}); see docs/RESTORE.md."
    )
    broken = payload.get("chains_broken")
    if isinstance(broken, list) and broken:
        say("  warning: chains that did NOT verify in this backup as it was taken:")
        for entry in broken:
            say(f"    {entry}")
    refused = payload.get("refused")
    if isinstance(refused, list) and refused:
        say("  warning: sources NOT in this backup, refused as unsafe to read:")
        for entry in refused:
            say(f"    {entry}")
    wide = payload.get("wide_paths")
    if isinstance(wide, list) and wide:
        say("  warning: lab-data paths readable or writable beyond their owner:")
        for entry in wide:
            say(f"    {entry}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
