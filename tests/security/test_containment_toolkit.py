# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the lab-scoped containment toolkit.

Covers the layered controls promised in agents/tools/containment.py: policy
gating (fail closed, audited), input validation against traversal and hostile
targets, reversibility of every primitive, and honest failure when the lab
executor is absent or does not confirm execution.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from agents.policies import AuditLogger, PolicyEngine
from agents.tools.containment import (
    QUARANTINE_DIRNAME,
    ContainmentError,
    ContainmentToolkit,
)
from agents.tools.guarded import ToolBlockedError
from agents.tools.validation import ValidationError


class RecordingExecutor:
    """Fake lab executor: records calls; confirms unless told otherwise."""

    def __init__(self, confirm: bool = True) -> None:
        self.confirm = confirm
        self.calls: list[tuple[str, str]] = []

    def perform(self, capability: str, target: str) -> bool:
        self.calls.append((capability, target))
        return self.confirm


@pytest.fixture
def toolkit(tmp_path: Path) -> ContainmentToolkit:
    return ContainmentToolkit(tmp_path, executor=RecordingExecutor())


# --- file quarantine ---------------------------------------------------------


@pytest.mark.security
def test_quarantine_moves_and_neuters_the_payload(tmp_path: Path) -> None:
    payload = tmp_path / "dropper.sh"
    payload.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    payload.chmod(0o755)

    action = ContainmentToolkit(tmp_path).quarantine_file("dropper.sh")

    assert not payload.exists()
    vault = tmp_path / QUARANTINE_DIRNAME
    entries = [p for p in vault.iterdir() if not p.name.endswith(".meta.json")]
    assert len(entries) == 1
    mode = stat.S_IMODE(entries[0].stat().st_mode)
    assert mode == 0o400  # read-only, no execute — preserved but inert
    assert action.executed is True
    assert action.reversible is True
    assert "T1486" in action.attack_techniques


@pytest.mark.security
def test_release_restores_without_execute_permission(tmp_path: Path) -> None:
    payload = tmp_path / "sub" / "tool.bin"
    payload.parent.mkdir()
    payload.write_bytes(b"\x7fELF-fake")
    payload.chmod(0o755)
    kit = ContainmentToolkit(tmp_path)
    entry_name = kit.quarantine_file("sub/tool.bin").rollback.split("'")[1]

    action = kit.release_file(entry_name)

    restored = tmp_path / "sub" / "tool.bin"
    assert restored.read_bytes() == b"\x7fELF-fake"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600  # never restored executable
    assert action.capability == "release_file"
    # The vault entry and its sidecar are gone.
    assert list((tmp_path / QUARANTINE_DIRNAME).iterdir()) == []


@pytest.mark.security
def test_release_refuses_to_overwrite(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("evil", encoding="utf-8")
    kit = ContainmentToolkit(tmp_path)
    entry_name = kit.quarantine_file("app.py").rollback.split("'")[1]
    (tmp_path / "app.py").write_text("legit replacement", encoding="utf-8")
    with pytest.raises(ContainmentError, match="refusing to overwrite"):
        kit.release_file(entry_name)


@pytest.mark.security
def test_release_fails_closed_on_tampered_sidecar(tmp_path: Path) -> None:
    (tmp_path / "x.bin").write_bytes(b"x")
    kit = ContainmentToolkit(tmp_path)
    entry_name = kit.quarantine_file("x.bin").rollback.split("'")[1]
    sidecar = tmp_path / QUARANTINE_DIRNAME / f"{entry_name}.meta.json"
    sidecar.write_text(json.dumps({"original": "../../etc/cron.d/backdoor"}), encoding="utf-8")
    with pytest.raises(ValidationError):  # traversal in sidecar → fail closed
        kit.release_file(entry_name)


@pytest.mark.security
def test_quarantine_blocks_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ContainmentToolkit(tmp_path).quarantine_file("../../etc/passwd")


@pytest.mark.security
def test_quarantine_refuses_symlinks(tmp_path: Path) -> None:
    """A planted symlink must not redirect quarantine to a different file."""
    victim = tmp_path / "config" / "settings.json"
    victim.parent.mkdir()
    victim.write_text("{}", encoding="utf-8")
    link = tmp_path / "malware.bin"
    link.symlink_to(victim)  # in-root redirect: resolve_within alone allows it
    kit = ContainmentToolkit(tmp_path)
    with pytest.raises(ContainmentError, match="symlink"):
        kit.quarantine_file("malware.bin")
    assert victim.exists()  # the aliased target was never touched
    outside = tmp_path / "esc.bin"
    outside.symlink_to("/etc/hostname")  # out-of-root target fails closed too
    with pytest.raises(ValidationError):
        kit.quarantine_file("esc.bin")


@pytest.mark.security
def test_release_refuses_symlink_at_original_path(tmp_path: Path) -> None:
    """A planted symlink at the restore path must not redirect the release."""
    (tmp_path / "mal.bin").write_bytes(b"payload")
    kit = ContainmentToolkit(tmp_path)
    entry_name = kit.quarantine_file("mal.bin").rollback.split("'")[1]
    (tmp_path / "mal.bin").symlink_to(tmp_path / "redirected_here")  # dangling
    with pytest.raises(ContainmentError):
        kit.release_file(entry_name)
    assert not (tmp_path / "redirected_here").exists()


@pytest.mark.security
def test_quarantine_rejects_non_files_and_vault_entries(tmp_path: Path) -> None:
    kit = ContainmentToolkit(tmp_path)
    (tmp_path / "adir").mkdir()
    with pytest.raises(ContainmentError, match="not a file"):
        kit.quarantine_file("adir")
    (tmp_path / "p.bin").write_bytes(b"p")
    entry_name = kit.quarantine_file("p.bin").rollback.split("'")[1]
    with pytest.raises(ContainmentError, match="already inside"):
        kit.quarantine_file(f"{QUARANTINE_DIRNAME}/{entry_name}")


@pytest.mark.security
def test_duplicate_quarantine_fails_closed(tmp_path: Path) -> None:
    kit = ContainmentToolkit(tmp_path)
    (tmp_path / "same.bin").write_bytes(b"identical")
    kit.quarantine_file("same.bin")
    (tmp_path / "same.bin").write_bytes(b"identical")  # same name, same content
    with pytest.raises(ContainmentError, match="already exists"):
        kit.quarantine_file("same.bin")


# --- process containment -----------------------------------------------------


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[bytes]]:
    proc = subprocess.Popen(  # fixed argv, test-owned child process
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


@pytest.mark.security
def test_stop_process_suspends_reversibly(tmp_path: Path, sleeper: subprocess.Popen[bytes]) -> None:
    kit = ContainmentToolkit(tmp_path)
    action = kit.stop_process(sleeper.pid)
    assert action.reversible is True
    assert "resume_process" in action.rollback
    assert sleeper.poll() is None  # suspended, not dead
    resumed = kit.resume_process(sleeper.pid)
    assert resumed.executed is True


@pytest.mark.security
def test_stop_process_force_kills(tmp_path: Path, sleeper: subprocess.Popen[bytes]) -> None:
    action = ContainmentToolkit(tmp_path).stop_process(sleeper.pid, force=True)
    assert action.reversible is False
    assert sleeper.wait(timeout=10) == -signal.SIGKILL


@pytest.mark.security
@pytest.mark.parametrize("bad_pid", [0, 1, -7, True])
def test_stop_process_rejects_protected_pids(tmp_path: Path, bad_pid: int) -> None:
    with pytest.raises(ContainmentError):
        ContainmentToolkit(tmp_path).stop_process(bad_pid)


@pytest.mark.security
def test_stop_process_refuses_own_process_tree(tmp_path: Path) -> None:
    kit = ContainmentToolkit(tmp_path)
    with pytest.raises(ContainmentError, match="own process tree"):
        kit.stop_process(os.getpid())
    with pytest.raises(ContainmentError, match="own process tree"):
        kit.stop_process(os.getppid())


@pytest.mark.security
def test_stop_process_missing_pid_fails_closed(
    tmp_path: Path, sleeper: subprocess.Popen[bytes]
) -> None:
    sleeper.kill()
    sleeper.wait(timeout=10)  # reaped: the pid no longer exists
    with pytest.raises(ContainmentError, match="no such process"):
        ContainmentToolkit(tmp_path).stop_process(sleeper.pid)


# --- executor-backed actions -------------------------------------------------


@pytest.mark.security
def test_executor_actions_fail_closed_without_executor(tmp_path: Path) -> None:
    kit = ContainmentToolkit(tmp_path)  # no executor wired
    with pytest.raises(ContainmentError, match="failing closed"):
        kit.isolate_host("web-01.lab")


@pytest.mark.security
def test_unconfirmed_execution_raises(tmp_path: Path) -> None:
    kit = ContainmentToolkit(tmp_path, executor=RecordingExecutor(confirm=False))
    with pytest.raises(ContainmentError, match="NOT contained"):
        kit.block_indicator("203.0.113.7")


@pytest.mark.security
def test_isolate_and_restore_round_trip(toolkit: ContainmentToolkit) -> None:
    action = toolkit.isolate_host("Web-01.Lab")
    assert action.target == "web-01.lab"  # normalized
    assert action.reversible is True
    assert toolkit.restore_host("web-01.lab").executed is True
    executor = toolkit.executor
    assert isinstance(executor, RecordingExecutor)
    assert executor.calls == [("isolate_host", "web-01.lab"), ("restore_host", "web-01.lab")]


@pytest.mark.security
@pytest.mark.parametrize(
    "indicator",
    ["203.0.113.7", "evil.example.com", "a" * 64, "d41d8cd98f00b204e9800998ecf8427e"],
)
def test_valid_indicators_are_accepted(toolkit: ContainmentToolkit, indicator: str) -> None:
    action = toolkit.block_indicator(indicator)
    assert action.executed is True
    assert "T1071" in action.attack_techniques


@pytest.mark.security
@pytest.mark.parametrize(
    "hostile",
    ["", "  ", "evil.com; rm -rf /", "$(reboot)", "a" * 300, "bad_host!", "..", "host name"],
)
def test_hostile_targets_are_rejected_before_the_executor(
    toolkit: ContainmentToolkit, hostile: str
) -> None:
    for method in (toolkit.isolate_host, toolkit.block_indicator, toolkit.disable_account):
        with pytest.raises(ContainmentError):
            method(hostile)
    executor = toolkit.executor
    assert isinstance(executor, RecordingExecutor)
    assert executor.calls == []  # validation failed closed before any execution


@pytest.mark.security
def test_disable_and_enable_account_round_trip(toolkit: ContainmentToolkit) -> None:
    action = toolkit.disable_account("Mallory")
    assert action.target == "mallory"
    assert "T1078" in action.attack_techniques
    assert toolkit.enable_account("mallory").executed is True


# --- policy gate + audit -----------------------------------------------------


@pytest.mark.security
def test_re_gated_policy_blocks_before_any_effect(tmp_path: Path) -> None:
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"p")
    audit = AuditLogger(tmp_path / "audit.log")
    kit = ContainmentToolkit(
        tmp_path,
        engine=PolicyEngine(policy={"containment": "require_approval"}),
        audit=audit,
    )
    with pytest.raises(ToolBlockedError):
        kit.quarantine_file("p.bin")
    assert payload.exists()  # nothing happened — the gate ran first
    log = audit.path.read_text(encoding="utf-8")
    assert "tool:quarantine_file" in log
    assert "require_approval" in log
    assert audit.verify() is True


@pytest.mark.security
def test_force_kill_is_separately_deny_listable(
    tmp_path: Path, sleeper: subprocess.Popen[bytes]
) -> None:
    """Operators can deny the irreversible SIGKILL while keeping the suspend."""
    kit = ContainmentToolkit(tmp_path, engine=PolicyEngine(deny=["stop_process_force"]))
    with pytest.raises(ToolBlockedError):
        kit.stop_process(sleeper.pid, force=True)
    assert sleeper.poll() is None  # never signaled — the gate ran first
    assert kit.stop_process(sleeper.pid).executed is True  # suspend still allowed
    kit.resume_process(sleeper.pid)


@pytest.mark.security
def test_deny_listed_capability_is_blocked(tmp_path: Path) -> None:
    kit = ContainmentToolkit(
        tmp_path,
        engine=PolicyEngine(deny=["stop_process"]),
        executor=RecordingExecutor(),
    )
    with pytest.raises(ToolBlockedError):
        kit.stop_process(99999)
    # Other capabilities still work under the same engine.
    assert kit.isolate_host("web-01.lab").executed is True


@pytest.mark.security
def test_successful_action_records_decision_and_outcome(tmp_path: Path) -> None:
    (tmp_path / "p.bin").write_bytes(b"p")
    audit = AuditLogger(tmp_path / "audit.log")
    ContainmentToolkit(tmp_path, audit=audit).quarantine_file("p.bin")
    entries = [
        json.loads(line)
        for line in audit.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    actions = [e["action"] for e in entries]
    assert "tool:quarantine_file" in actions  # the policy decision
    assert any(a.startswith("containment:quarantine_file:") for a in actions)  # the outcome
    assert audit.verify() is True


@pytest.mark.security
def test_root_must_be_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ContainmentError, match="not a directory"):
        ContainmentToolkit(tmp_path / "missing")


# --- validate-then-act races on quarantine paths ------------------------------


@pytest.mark.security
def test_quarantine_chmod_does_not_follow_a_symlink_swapped_in_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The symlink check runs before the rename; the chmod after it must not follow one.

    Measured before the fix: a vault entry replaced by a link to a file outside
    the root took that file from 0o644 to 0o400 and the action reported executed.
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("victim", encoding="utf-8")
    outside.chmod(0o644)
    (root / "mal.bin").write_bytes(b"evil")
    real_rename = os.rename

    def swap_after_rename(src: str, dst: str, **dir_fds: int | None) -> None:
        real_rename(src, dst, **dir_fds)
        placed = root / QUARANTINE_DIRNAME / dst
        placed.unlink()  # the race, made deterministic: the path now aliases `outside`
        placed.symlink_to(outside)

    monkeypatch.setattr(os, "rename", swap_after_rename)
    with pytest.raises(ContainmentError, match="symlink"):
        ContainmentToolkit(root).quarantine_file("mal.bin")
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644


@pytest.mark.security
def test_quarantine_refuses_an_entry_that_is_not_the_hashed_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different regular file swapped in after hashing must not be sealed under the digest."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "mal.bin").write_bytes(b"evil")
    real_rename = os.rename

    def swap_after_rename(src: str, dst: str, **dir_fds: int | None) -> None:
        real_rename(src, dst, **dir_fds)
        placed = root / QUARANTINE_DIRNAME / dst
        placed.unlink()
        placed.write_bytes(b"something else entirely")  # a new inode at the vault path

    monkeypatch.setattr(os, "rename", swap_after_rename)
    with pytest.raises(ContainmentError, match="NOT contained"):
        ContainmentToolkit(root).quarantine_file("mal.bin")


@pytest.mark.security
def test_release_chmod_does_not_follow_a_symlink_swapped_in_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured before the fix: the aliased outside file went from 0o444 to 0o600."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("victim", encoding="utf-8")
    outside.chmod(0o444)
    (root / "mal.bin").write_bytes(b"evil")
    kit = ContainmentToolkit(root)
    entry = root / QUARANTINE_DIRNAME / kit.quarantine_file("mal.bin").rollback.split("'")[1]
    real_resolve = ContainmentToolkit._resolve_no_symlink

    def swap(base: Path, candidate: str) -> Path:
        result = real_resolve(base, candidate)
        if candidate == "mal.bin":  # the restore path has just been validated
            entry.unlink()
            entry.symlink_to(outside)
        return result

    monkeypatch.setattr(ContainmentToolkit, "_resolve_no_symlink", staticmethod(swap))
    with pytest.raises(ContainmentError, match="symlink"):
        kit.release_file(entry.name)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o444


@contextlib.contextmanager
def _fail_if_blocked(seconds: int = 5) -> Iterator[None]:
    """Fail instead of hanging when an open blocks; raises a BaseException, since a TimeoutError is an OSError."""

    class Blocked(BaseException):
        pass

    def on_alarm(*_: object) -> None:
        raise Blocked

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(seconds)
    try:
        yield
    except Blocked:
        pytest.fail(f"blocked for {seconds}s in an open that must not block")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _swap_after_is_file(
    monkeypatch: pytest.MonkeyPatch, victim: Path, swap: Callable[[], None]
) -> None:
    """Run ``swap`` right after ``is_file()`` has said yes to ``victim`` (the race, deterministic)."""
    real_is_file = Path.is_file

    def hooked(self: Path) -> bool:
        result = real_is_file(self)
        if result and self == victim:
            swap()
        return result

    monkeypatch.setattr(Path, "is_file", hooked)


@pytest.mark.security
def test_quarantine_refuses_a_hard_link_to_a_file_outside_the_root(tmp_path: Path) -> None:
    """No symlink anywhere: measured before the fix, the outside file went 0o644 -> 0o400."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("victim", encoding="utf-8")
    outside.chmod(0o644)
    os.link(outside, root / "mal.bin")
    with pytest.raises(ContainmentError, match="2 links"):
        ContainmentToolkit(root).quarantine_file("mal.bin")
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert (root / "mal.bin").exists()  # nothing moved


@pytest.mark.security
def test_release_refuses_a_vault_entry_that_is_a_hard_link(tmp_path: Path) -> None:
    """Measured before the fix: the outside file went 0o444 -> 0o600 and was moved into the root."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("victim", encoding="utf-8")
    outside.chmod(0o444)
    (root / "mal.bin").write_bytes(b"evil")
    kit = ContainmentToolkit(root)
    entry = root / QUARANTINE_DIRNAME / kit.quarantine_file("mal.bin").rollback.split("'")[1]
    entry.unlink()
    os.link(outside, entry)
    with pytest.raises(ContainmentError, match="2 links"):
        kit.release_file(entry.name)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o444
    assert not (root / "mal.bin").exists()


@pytest.mark.security
def test_a_fifo_swapped_in_after_validation_fails_closed_instead_of_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured before the fix: ``os.open`` blocked forever before the regular-file check ran — at
    the target on quarantine (pre-existing) and at the vault entry on release (introduced)."""
    root = tmp_path / "root"
    root.mkdir()
    target = root / "mal.bin"
    target.write_bytes(b"evil")
    kit = ContainmentToolkit(root)

    def to_fifo(victim: Path) -> Callable[[], None]:
        def swap() -> None:
            victim.unlink()
            os.mkfifo(victim)

        return swap

    _swap_after_is_file(monkeypatch, target, to_fifo(target))
    with _fail_if_blocked(), pytest.raises(ContainmentError, match="not a regular file"):
        kit.quarantine_file("mal.bin")

    monkeypatch.undo()  # the first hook would turn the recreated target into a FIFO again
    target.unlink()
    target.write_bytes(b"evil")
    entry = root / QUARANTINE_DIRNAME / kit.quarantine_file("mal.bin").rollback.split("'")[1]
    _swap_after_is_file(monkeypatch, entry, to_fifo(entry))
    with _fail_if_blocked(), pytest.raises(ContainmentError, match="not a regular file"):
        kit.release_file(entry.name)


@pytest.mark.security
def test_overlong_entry_name_is_a_containment_error_not_a_raw_oserror(tmp_path: Path) -> None:
    """Measured before the fix: ``ENAMETOOLONG`` escaped ``is_file()`` unwrapped."""
    (tmp_path / "x.bin").write_bytes(b"x")
    kit = ContainmentToolkit(tmp_path)
    kit.quarantine_file("x.bin")  # the vault exists, so the long name reaches the stat
    with pytest.raises(ContainmentError, match="no such vault entry"):
        kit.release_file("a" * 300)


# --- the vault, the sidecar and the restore directory are acted on by descriptor --


def _swap_after_validation(
    monkeypatch: pytest.MonkeyPatch, candidate: str, swap: Callable[[], None]
) -> None:
    """Run ``swap`` right after ``_resolve_no_symlink`` has validated ``candidate``."""
    real = ContainmentToolkit._resolve_no_symlink

    def hooked(base: Path, cand: str) -> Path:
        result = real(base, cand)
        if cand == candidate:
            swap()
        return result

    monkeypatch.setattr(ContainmentToolkit, "_resolve_no_symlink", staticmethod(hooked))


@pytest.mark.security
def test_quarantine_sidecar_is_created_exclusively_never_through_a_planted_link(
    tmp_path: Path,
) -> None:
    """Measured before the fix: ``write_text`` followed the link; the JSON overwrote an outside file."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("victim", encoding="utf-8")
    (root / "mal.bin").write_bytes(b"evil")
    vault = root / QUARANTINE_DIRNAME
    vault.mkdir(mode=0o700)
    sha12 = hashlib.sha256(b"evil").hexdigest()[:12]
    (vault / f"{sha12}__mal.bin.meta.json").symlink_to(outside)
    with pytest.raises(ContainmentError, match="already exists"):
        ContainmentToolkit(root).quarantine_file("mal.bin")
    assert outside.read_text(encoding="utf-8") == "victim"
    assert (root / "mal.bin").exists()


@pytest.mark.security
@pytest.mark.parametrize("how", ["symlink", "world-writable"])
def test_quarantine_refuses_a_vault_it_did_not_create_privately(tmp_path: Path, how: str) -> None:
    """Measured before the fix, ``mkdir(exist_ok=True)`` accepted both: a symlink moved the payload
    and its sidecar into a directory outside the root; a 0o777 directory served as the vault."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "mal.bin").write_bytes(b"evil")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    vault = root / QUARANTINE_DIRNAME
    if how == "symlink":
        vault.symlink_to(outside_dir)
    else:
        vault.mkdir()
        vault.chmod(0o777)
    with pytest.raises(ContainmentError, match="vault"):
        ContainmentToolkit(root).quarantine_file("mal.bin")
    assert list(outside_dir.iterdir()) == []
    assert (root / "mal.bin").exists()


@pytest.mark.security
def test_release_refuses_a_restore_parent_swapped_to_a_symlink_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured before the fix: ``mkdir``/``rename`` followed it; the payload landed outside, 0o600."""
    root = tmp_path / "root"
    root.mkdir()
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (root / "sub").mkdir()
    (root / "sub" / "tool.bin").write_bytes(b"evil")
    kit = ContainmentToolkit(root)
    entry_name = kit.quarantine_file("sub/tool.bin").rollback.split("'")[1]

    def swap_parent() -> None:
        (root / "sub").rmdir()
        (root / "sub").symlink_to(outside_dir)

    _swap_after_validation(monkeypatch, "sub/tool.bin", swap_parent)  # the restore path
    with pytest.raises(ContainmentError, match="not a directory inside the root"):
        kit.release_file(entry_name)
    assert list(outside_dir.iterdir()) == []
    assert (root / QUARANTINE_DIRNAME / entry_name).exists()  # still in the vault


@pytest.mark.security
def test_quarantine_refuses_a_source_parent_swapped_to_a_symlink_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same class, other side. Measured on the previous commit: the open, the hash and the move all
    followed the link, and a decoy *outside* the root was quarantined with the action executed."""
    root = tmp_path / "root"
    root.mkdir()
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    decoy = outside_dir / "mal.bin"
    decoy.write_bytes(b"decoy")
    decoy.chmod(0o644)
    (root / "sub").mkdir()
    (root / "sub" / "mal.bin").write_bytes(b"evil")

    def swap_parent() -> None:
        (root / "sub" / "mal.bin").unlink()
        (root / "sub").rmdir()
        (root / "sub").symlink_to(outside_dir)

    _swap_after_validation(monkeypatch, "sub/mal.bin", swap_parent)
    with pytest.raises(ContainmentError, match="not a directory inside the root"):
        ContainmentToolkit(root).quarantine_file("sub/mal.bin")
    assert decoy.read_bytes() == b"decoy"
    assert stat.S_IMODE(decoy.stat().st_mode) == 0o644
    assert not (root / QUARANTINE_DIRNAME).exists()
