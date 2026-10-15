# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The audit chain under concurrency — the property it had no test for.

``AuditLogger.record`` was an unlocked read-modify-write: ``_last()`` reads
``(last_seq, prev_hash)``, the entry hash is computed from them, then the line
is appended. Two writers therefore chose the same ``seq`` and the same
``prev_hash`` and forked a chain that is append-only, so the fork cannot be
repaired. Measured before the fix: ``n=2`` produced seqs ``[0, 0]`` and ``n=8``
three duplicate seqs, ``intact=False`` every time.

A fork is not one bad record. Verification stops at the first break, so every
entry after it carries no evidentiary weight — which is why this is locked
rather than tolerated, and why the lock blocks rather than skipping.

**Processes, not only threads.** The writers that actually share a chain are
separate processes: ``scripts/run_retention.py`` and ``scripts/run_backup.py``
both write ``data/events/audit.log`` while holding *different* pass locks
(``retention.lock`` and ``backup.lock``), so their own flocks serialise each
CLI against itself and not against the other. A thread-only test would not
exercise the case the defect was found in.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from itertools import pairwise
from pathlib import Path

import pytest

from agents.policies.audit import AuditLogger

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: A writer in its own interpreter, as the scheduled CLIs are.
_WRITER = """
import sys
sys.path.insert(0, {repo!r})
from agents.policies.audit import AuditLogger
log = AuditLogger({path!r})
for i in range({count}):
    log.record(
        actor="w{tag}", action=f"a{{i}}", action_class="read_only",
        decision="allow", reason=f"writer {tag} entry {{i}}",
    )
"""


def _seqs(path: Path) -> list[int]:
    """Every seq across every segment, oldest segment first."""
    out: list[int] = []
    for segment in AuditLogger(path)._segments_in_order():
        for line in segment.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(int(json.loads(line)["seq"]))
    return out


def _run_writers(path: Path, tmp_path: Path, *, writers: int, each: int) -> None:
    scripts = []
    for tag in range(writers):
        script = tmp_path / f"writer{tag}.py"
        script.write_text(
            _WRITER.format(repo=str(_REPO_ROOT), path=str(path), count=each, tag=tag),
            encoding="utf-8",
        )
        scripts.append(script)
    # S603: argv is this test's own generated script, not external input.
    procs = [
        subprocess.Popen(  # noqa: S603
            [sys.executable, str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for script in scripts
    ]
    for proc in procs:
        _, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err.decode()[:400]


@pytest.mark.security
@pytest.mark.parametrize("writers", [2, 6])
def test_concurrent_processes_cannot_fork_the_chain(tmp_path: Path, writers: int) -> None:
    """The defect itself, in the shape it was found: separate processes.

    Before the lock, ``n=2`` gave seqs ``[0, 0]``. The assertion is on the seq
    *sequence* rather than on ``intact`` alone, because a fork and a dropped
    entry are different failures and only the sequence distinguishes them.
    """
    path = tmp_path / "audit.log"
    each = 12
    _run_writers(path, tmp_path, writers=writers, each=each)

    seqs = _seqs(path)
    assert len(seqs) == writers * each, (
        f"{writers * each - len(seqs)} record(s) were lost, not forked"
    )
    assert sorted(seqs) == list(range(writers * each)), f"seqs are not 0..n-1: {seqs}"
    assert len(set(seqs)) == len(seqs), "a seq was issued twice"
    assert AuditLogger(path).verify_report().intact


@pytest.mark.security
def test_a_record_cannot_be_forked_by_a_concurrent_rotation(tmp_path: Path) -> None:
    """One writer is enough, which is why the lock spans more than the append.

    ``_last`` builds ``(self.path, *reversed(self._archive_paths()))``, so the
    archive list is evaluated **before** the active log is read. A rotation
    landing in that window makes it fall through to a stale, empty list and
    return ``(-1, genesis)``, restarting the chain at ``seq 0``.

    Measured against the real competitor — ``apply_retention`` from another
    thread, which is what ``scripts/audit_maintenance.py`` runs — the unlocked
    code forked in **6 of 6** trials with 19-28 restarts and 35-57 duplicate
    seqs each. That rotator takes no lock of its own, so every chain in the
    platform sits on this path, not only the one with two scheduled writers.
    """
    path = tmp_path / "audit.log"
    writer = AuditLogger(path)
    for i in range(3):
        writer.record(
            actor="seed",
            action=f"s{i}",
            action_class="read_only",
            decision="allow",
            reason=f"seed {i}",
        )

    stop = threading.Event()
    rotations = 0

    def rotator() -> None:
        nonlocal rotations
        # Exactly what scripts/audit_maintenance.py does, including max_bytes=1
        # so every pass rotates.
        maintenance = AuditLogger(path, max_bytes=1, retain_segments=200)
        while not stop.is_set():
            try:
                if maintenance.apply_retention()["rotated"]:
                    rotations += 1
            except OSError:
                pass

    thread = threading.Thread(target=rotator)
    thread.start()
    try:
        for i in range(60):
            writer.record(
                actor="writer",
                action=f"w{i}",
                action_class="read_only",
                decision="allow",
                reason=f"write {i}",
            )
    finally:
        stop.set()
        thread.join()

    assert rotations, "the rotator never rotated, so this test proves nothing"
    seqs = _seqs(path)
    restarts = [b for a, b in pairwise(seqs) if b <= a]
    assert not restarts, f"the chain restarted at {restarts[:5]} under a concurrent rotation"
    assert len(set(seqs)) == len(seqs), (
        f"duplicate seqs under rotation: {len(seqs) - len(set(seqs))}"
    )


@pytest.mark.security
def test_a_reader_never_sees_a_broken_chain_that_is_not_broken(tmp_path: Path) -> None:
    """``audit-chains-intact`` grades this against a target of 1.0 every 5 minutes.

    Two separate defects produced false alarms on an intact chain with a
    *single* writer. ``_sign_head`` truncated the signature sidecar before
    rewriting it, so a reader saw a malformed one; and the reader read the chain
    and the signature as two unsynchronised steps, so it could pair a chain with
    a signature for a head it had not seen. Measured: 151 of 606 reads reported
    the chain broken — 137 ``malformed``, 14 ``stale`` — with no defect present.
    Atomic replacement removed the first (137 to 0) and the shared read lock the
    second.
    """
    path = tmp_path / "audit.log"
    key = b"k" * 32
    writer = AuditLogger(path, signing_key=key)
    for i in range(5):
        writer.record(
            actor="seed",
            action=f"s{i}",
            action_class="read_only",
            decision="allow",
            reason=f"seed {i}",
        )
    assert AuditLogger(path, signing_key=key).verify_report().intact, "fixture is not intact"

    stop = threading.Event()
    verdicts: list[str] = []

    def reader() -> None:
        checker = AuditLogger(path, signing_key=key)
        while not stop.is_set():
            try:
                report = checker.verify_report()
                verdicts.append("intact" if report.intact else f"broken:{report.signature}")
            except Exception as exc:  # an exception is also a failure here
                verdicts.append(f"raised:{type(exc).__name__}")

    thread = threading.Thread(target=reader)
    thread.start()
    try:
        for i in range(120):
            writer.record(
                actor="writer",
                action=f"w{i}",
                action_class="read_only",
                decision="allow",
                reason=f"write {i}",
            )
    finally:
        stop.set()
        thread.join()

    assert len(verdicts) > 20, f"the reader only managed {len(verdicts)} reads; too few to judge"
    assert AuditLogger(path, signing_key=key).verify_report().intact, "the chain really did break"
    bad = [v for v in verdicts if v != "intact"]
    assert not bad, (
        f"{len(bad)} of {len(verdicts)} reads called an intact chain broken: {sorted(set(bad))[:4]}"
    )


@pytest.mark.security
def test_the_lock_is_owner_only_lazy_and_invisible_to_the_chain(tmp_path: Path) -> None:
    """Three properties the lock must have, each costing tests if it does not.

    *Lazy*: four call sites build an ``AuditLogger`` purely to read, and
    ``test_a_measurement_creates_nothing`` asserts a measurement creates
    nothing — eager creation in ``__init__`` costs seven tests rather than one.

    *Owner-only*: the chain is ``0o600`` and its directory ``0o700``; a lock
    created through a plain ``open()`` lands ``0o644`` under the permission
    suite's deliberate ``umask(0o000)``.

    *Invisible*: the archive regex is ``^audit\\.log\\.(\\d+)$``, so
    ``audit.log.lock`` is not a segment. If it were, ``exists()`` would answer
    ``True`` on a path that holds no chain and ``audit_maintenance`` would stop
    exiting 2 on a typo.
    """
    path = tmp_path / "audit.log"
    lock = tmp_path / "audit.log.lock"

    reader = AuditLogger(path)
    assert reader.verify_report() is not None
    assert reader.exists() is False
    assert not lock.exists(), "constructing a reader created the lock file"
    assert not list(tmp_path.iterdir()), f"a read created {list(tmp_path.iterdir())}"

    previous = os.umask(0o000)
    try:
        AuditLogger(path).record(
            actor="w",
            action="a",
            action_class="read_only",
            decision="allow",
            reason="first write",
        )
    finally:
        os.umask(previous)
    assert lock.is_file(), "record() did not create the lock beside the chain"
    assert lock.stat().st_mode & 0o777 == 0o600, oct(lock.stat().st_mode & 0o777)

    logger = AuditLogger(path)
    assert lock not in logger._archive_paths(), "the lock is being counted as an archive"
    assert lock not in logger._segments_in_order(), "the lock is being verified as a segment"
    assert logger.verify_report().intact
    assert int(logger.apply_retention()["archives"]) == 0


@pytest.mark.security
def test_retention_on_a_path_that_is_not_a_chain_still_creates_nothing(
    tmp_path: Path,
) -> None:
    """A mistyped path must not materialise artifacts, lock included.

    The first version of the lock took it unconditionally in
    ``apply_retention``, which created ``<dir>.lock`` beside a directory handed
    in by mistake. ``tests/security/test_audit_maintenance_failclosed.py``
    caught it — this pins the property at the library level too, because that
    is the ``--root ""`` shadow-tree class and the reason ``_should_rotate``
    tests ``_is_segment`` rather than ``exists()``.
    """
    directory = tmp_path / "not-a-chain"
    directory.mkdir()
    before = {child.relative_to(tmp_path) for child in tmp_path.rglob("*")}

    result = AuditLogger(directory, max_bytes=1, retain_segments=1).apply_retention()

    assert result == {"rotated": False, "archives": 0}
    assert {child.relative_to(tmp_path) for child in tmp_path.rglob("*")} == before


@pytest.mark.security
def test_the_signature_sidecar_is_never_observed_half_written(tmp_path: Path) -> None:
    """The atomic replace, pinned by the one reader the shared lock does not cover.

    Added because a plant exposed a gap: reverting ``_write_text_owner_only``
    to ``open(path, "w")`` — truncate, then write — left all 71 tests in this
    area green, because ``verify_report`` now takes a shared lock and is the
    only reader the suite exercised. That made the atomicity look like
    decoration.

    It is not. The shared lock is taken *only if the lock file exists*, so a
    chain written before the lock existed, or one whose sidecars are read by
    anything other than ``verify_report`` — ``verify_signature``, an operator,
    an external tool — is unsynchronised. And no lock helps a crash: truncate
    then write leaves a permanently empty signature if the process dies in
    between, where a replace leaves the previous one whole.

    So this reader deliberately bypasses ``verify_report`` and reads the
    sidecar's bytes directly. Measured before the fix, through
    ``verify_report``: 137 of 606 reads saw a malformed signature.
    """
    path = tmp_path / "audit.log"
    sig = tmp_path / "audit.log.sig"
    key = b"k" * 32
    writer = AuditLogger(path, signing_key=key)
    writer.record(
        actor="seed",
        action="s",
        action_class="read_only",
        decision="allow",
        reason="seed",
    )
    assert sig.is_file(), "the fixture produced no signature to read"

    stop = threading.Event()
    observations: list[str] = []

    def peek() -> None:
        while not stop.is_set():
            try:
                raw = sig.read_bytes()
            except FileNotFoundError:
                observations.append("absent")
                continue
            if not raw:
                observations.append("empty")
                continue
            try:
                payload = json.loads(raw)
            except ValueError:
                observations.append("partial")
                continue
            observations.append(
                "whole" if {"seq", "head_hash", "algo", "signature"} <= payload.keys() else "short"
            )

    thread = threading.Thread(target=peek)
    thread.start()
    try:
        for i in range(120):
            writer.record(
                actor="writer",
                action=f"w{i}",
                action_class="read_only",
                decision="allow",
                reason=f"write {i}",
            )
    finally:
        stop.set()
        thread.join()

    assert len(observations) > 50, f"only {len(observations)} reads; too few to judge"
    torn = [state for state in observations if state != "whole"]
    assert not torn, (
        f"{len(torn)} of {len(observations)} reads saw a half-written signature "
        f"({sorted(set(torn))}) — the sidecar write is not atomic"
    )
