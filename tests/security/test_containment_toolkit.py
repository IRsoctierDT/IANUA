"""Security tests for the lab-scoped containment toolkit.

Covers the layered controls promised in agents/tools/containment.py: policy
gating (fail closed, audited), input validation against traversal and hostile
targets, reversibility of every primitive, and honest failure when the lab
executor is absent or does not confirm execution.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
from collections.abc import Iterator
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

    def execute(self, capability: str, target: str) -> bool:
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
