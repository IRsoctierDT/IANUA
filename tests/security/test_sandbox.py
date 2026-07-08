"""Security tests for the rootless MCP tool sandbox (Hardening Roadmap #5).

Two tiers:

* **Host-independent** — command construction, fail-closed refusal, report mode,
  audit integration, and shell-injection safety. These run everywhere (incl.
  macOS dev) because they never launch a container; they assert the *intended*
  confinement, which is exactly what a reviewer needs to see.
* **Linux + runtime gated** — real negative tests (write outside ``MCP_ROOT``,
  outbound socket, escape attempts are blocked). Skipped automatically when no
  Podman/Docker runtime is available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine
from agents.tools.guarded import ToolBlockedError
from mcp.sandbox import (
    SandboxConfig,
    SandboxRunner,
    SandboxUnavailableError,
)
from mcp.server import ToolRegistry, sandboxed_command_tool


@pytest.fixture
def root(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    (d / "readme.txt").write_text("hello", encoding="utf-8")
    return d


def _runner(
    root: Path,
    *,
    mode: str = "report",
    runtime: str | None = "podman",
    audit: AuditLogger | None = None,
) -> SandboxRunner:
    cfg = SandboxConfig(root=root, mode=mode)  # type: ignore[arg-type]
    return SandboxRunner(
        config=cfg,
        audit=audit,
        _runtime_lookup=lambda name: f"/usr/bin/{name}" if name == runtime else None,
    )


# --------------------------------------------------------------- construction
@pytest.mark.security
def test_build_command_has_all_hardening_flags(root: Path) -> None:
    runner = _runner(root)
    cmd = runner.build_command(["echo", "hi"], runtime="/usr/bin/podman")
    joined = " ".join(cmd)
    # Least privilege + default-deny by construction.
    assert "--network none" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "seccomp=" in joined
    assert "apparmor=mcp-tool" in joined
    assert "--read-only" in joined
    assert "--user 65534:65534" in joined  # never root inside
    assert "--pids-limit 128" in joined
    assert f"{root}:/data:ro" in joined  # only MCP_ROOT, read-only
    assert cmd[-2:] == ("echo", "hi")  # tool argv is last


@pytest.mark.security
def test_build_command_rejects_empty_argv(root: Path) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _runner(root).build_command([], runtime="/usr/bin/podman")


@pytest.mark.security
def test_argv_is_not_shell_interpreted(root: Path) -> None:
    # A hostile argument stays a single literal token — never a shell command.
    runner = _runner(root)
    cmd = runner.build_command(["cat", "; rm -rf / #"], runtime="/usr/bin/podman")
    assert "; rm -rf / #" in cmd  # present verbatim as one element
    assert cmd.count("; rm -rf / #") == 1


@pytest.mark.security
def test_seccomp_profile_is_deny_by_default_and_denies_network() -> None:
    import json

    from mcp.sandbox import PROFILE_DIR

    prof = json.loads((PROFILE_DIR / "seccomp.json").read_text(encoding="utf-8"))
    assert prof["defaultAction"] == "SCMP_ACT_ERRNO"  # deny-by-default
    allowed = {n for block in prof["syscalls"] for n in block["names"]}
    # Network syscalls are intentionally absent (default-deny egress, in depth).
    assert not ({"socket", "connect", "bind", "listen", "accept", "accept4"} & allowed)
    # ...but the essentials a minimal tool needs are present.
    assert {"read", "write", "execve", "exit_group"} <= allowed


@pytest.mark.security
def test_profiles_are_optional_but_core_confinement_is_not(root: Path) -> None:
    # A host without a loadable AppArmor profile / seccomp still gets the core
    # confinement; only the profile flags drop out.
    cfg = SandboxConfig(root=root, mode="report", apparmor_profile="", seccomp_profile=None)
    cmd = SandboxRunner(config=cfg).build_command(["echo", "hi"], runtime="podman")
    joined = " ".join(cmd)
    assert "apparmor=" not in joined
    assert "seccomp=" not in joined
    # Core controls remain, unconditionally.
    assert "--network none" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "--read-only" in joined
    assert f"{root}:/data:ro" in joined


# ------------------------------------------------------------------ fail-closed
@pytest.mark.security
def test_enforce_fails_closed_without_runtime(root: Path) -> None:
    runner = _runner(root, mode="enforce", runtime=None)  # nothing on PATH
    with pytest.raises(SandboxUnavailableError):
        runner.run(["echo", "hi"], name="probe")


@pytest.mark.security
def test_enforce_refusal_is_audited(root: Path, tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.jsonl")
    runner = _runner(root, mode="enforce", runtime=None, audit=log)
    with pytest.raises(SandboxUnavailableError):
        runner.run(["echo", "hi"], name="probe")
    assert log.verify()  # hash chain intact
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert any('"decision": "deny"' in ln and "sandbox:probe" in ln for ln in lines)


# --------------------------------------------------------------- report mode
@pytest.mark.security
def test_report_mode_does_not_execute(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def _boom(*_a: object, **_k: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run in report mode")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = _runner(root, mode="report").run(["echo", "hi"], name="probe")
    assert called is False
    assert result.executed is False
    assert result.command  # the intended hardened command is still materialised
    assert "report-only" in result.reason


@pytest.mark.security
def test_report_mode_without_runtime_is_informational(root: Path) -> None:
    result = _runner(root, mode="report", runtime=None).run(["echo", "hi"], name="probe")
    assert result.executed is False
    assert "would refuse in enforce mode" in result.reason


# --------------------------------------------------------------- config guards
@pytest.mark.security
def test_config_rejects_nonexistent_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        SandboxConfig(root=tmp_path / "nope")


@pytest.mark.security
@pytest.mark.parametrize("bad", [{"timeout_s": 0}, {"pids_limit": 0}])
def test_config_rejects_nonpositive_limits(root: Path, bad: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        SandboxConfig(root=root, **bad)  # type: ignore[arg-type]


# --------------------------------------------------- enforce plumbing (mocked)
@pytest.mark.security
def test_enforce_invokes_runtime_without_shell(
    root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured_cmd: list[str] = []
    captured_shell: list[object] = []

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(cmd: Sequence[str], **kwargs: object) -> _Proc:
        captured_cmd.extend(cmd)
        captured_shell.append(kwargs.get("shell"))
        return _Proc()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    log = AuditLogger(tmp_path / "audit.jsonl")
    result = _runner(root, mode="enforce", audit=log).run(["echo", "hi"], name="probe")
    assert result.executed is True
    assert result.returncode == 0
    assert captured_shell == [False]  # never a shell
    assert captured_cmd[0].endswith("podman")  # resolved runtime leads the argv
    assert log.verify()


@pytest.mark.security
def test_enforce_timeout_is_bounded_and_audited(
    root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _timeout(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="podman", timeout=1.0)

    monkeypatch.setattr(subprocess, "run", _timeout)
    log = AuditLogger(tmp_path / "audit.jsonl")
    result = _runner(root, mode="enforce", audit=log).run(["sleep", "999"], name="hang")
    assert result.reason == "timeout"
    assert result.returncode is None
    assert log.verify()
    assert '"reason": "timeout"' in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


@pytest.mark.security
def test_explicit_runtime_is_honored(root: Path) -> None:
    cfg = SandboxConfig(root=root, mode="report", runtime="docker")
    runner = SandboxRunner(config=cfg, _runtime_lookup=lambda n: f"/usr/bin/{n}")
    assert runner.resolve_runtime() == "/usr/bin/docker"


# ----------------------------------------------- registry wiring (policy + sandbox)
@pytest.mark.security
def test_registry_dispatch_routes_command_tool_through_sandbox(root: Path, tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.jsonl")
    runner = _runner(root, mode="report")  # report mode: nothing executes
    # external_network tools are default-deny; the operator must allow-list it
    # (policy layer) — only then does the sandbox layer confine execution.
    registry = ToolRegistry(root=root, policy=PolicyEngine(allow=["grep_data"]), audit=log)
    registry.register(
        sandboxed_command_tool(
            "grep_data",
            "grep within the mounted data root (sandboxed)",
            lambda args: ["grep", "-r", str(args["pattern"]), "/data"],
            runner,
        )
    )
    out = registry.dispatch("grep_data", {"pattern": "hello"})
    assert out["executed"] is False  # report mode audited, did not run
    assert "report-only" in out["reason"]
    assert log.verify()


@pytest.mark.security
def test_registry_blocks_sandboxed_tool_without_allowlist(root: Path) -> None:
    runner = _runner(root, mode="report")
    registry = ToolRegistry(root=root, policy=PolicyEngine())  # default-deny
    registry.register(sandboxed_command_tool("run_x", "d", lambda _a: ["echo", "hi"], runner))
    # Policy gate blocks before the sandbox is ever reached (fail closed).
    with pytest.raises(ToolBlockedError):
        registry.dispatch("run_x", {})


# --------------------------------------------- real-container enforcement (Linux)
# These run only when explicitly enabled (MCP_SANDBOX_ENFORCE_TESTS=1) on a Linux
# host with a runtime — i.e. the dedicated CI job, never the generic test job.
# Gating them keeps them from *vacuously* passing where the container cannot
# start (a failed `run` also yields a non-zero rc); the positive control below
# fails loudly if the sandbox cannot execute at all. AppArmor is disabled here
# (apparmor_profile="") because loading a profile is host-dependent; the network
# and filesystem confinements proven here do not depend on it.
_ENFORCE = os.environ.get("MCP_SANDBOX_ENFORCE_TESTS") == "1"
_RUNTIME = shutil.which("podman") or shutil.which("docker")
_needs_enforce = pytest.mark.skipif(
    not (_ENFORCE and _RUNTIME and sys.platform.startswith("linux")),
    reason="set MCP_SANDBOX_ENFORCE_TESTS=1 on a Linux host with podman/docker",
)
_IMAGE = "docker.io/library/busybox:stable"


def _enforce_runner(root: Path) -> SandboxRunner:
    # Disable AppArmor (host profile-load dependent) and seccomp (enforcing its
    # allow-list against arbitrary busybox syscalls is arch-dependent; the
    # profile's intent is validated structurally in
    # test_seccomp_profile_is_deny_by_default). The network / filesystem / user /
    # capability confinement proven below is runtime-native and reliable.
    cfg = SandboxConfig(
        root=root, mode="enforce", image=_IMAGE, apparmor_profile="", seccomp_profile=None
    )
    return SandboxRunner(config=cfg)


@pytest.mark.security
@_needs_enforce
def test_real_sandbox_positive_control(root: Path) -> None:
    # Guards the negative tests below from vacuously passing: the container must
    # actually start and run a command under all the confinement flags.
    result = _enforce_runner(root).run(["sh", "-c", "echo ok"], name="control")
    assert result.executed is True
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


@pytest.mark.security
@_needs_enforce
def test_real_sandbox_runs_as_non_root(root: Path) -> None:
    result = _enforce_runner(root).run(["id", "-u"], name="whoami")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "65534"  # never uid 0 inside


@pytest.mark.security
@_needs_enforce
def test_real_sandbox_blocks_network_egress(root: Path) -> None:
    # --network=none => name resolution / connect must fail; the command reports
    # a non-zero rc from inside the container (distinct from a failed run).
    result = _enforce_runner(root).run(
        ["sh", "-c", "wget -T3 -q -O- http://example.com >/dev/null 2>&1; echo rc=$?"],
        name="egress",
    )
    assert result.returncode == 0, result.stderr  # the shell itself ran
    assert "rc=0" not in result.stdout  # ...but the network call failed


@pytest.mark.security
@_needs_enforce
def test_real_sandbox_data_is_read_only(root: Path) -> None:
    # /data is mounted read-only; a write must fail from inside the container.
    result = _enforce_runner(root).run(
        ["sh", "-c", "echo x > /data/attack 2>/dev/null; echo rc=$?"], name="write-probe"
    )
    assert result.returncode == 0, result.stderr
    assert "rc=0" not in result.stdout
    assert not (root / "attack").exists()  # nothing leaked to the host
