"""Rootless, seccomp/AppArmor-confined sandbox for MCP tool execution.

Hardening Roadmap **#5** (``docs/HARDENING_ROADMAP.md``). Runs an MCP tool's
*external command* inside a locked-down, rootless container so a compromised or
buggy tool cannot reach the host, the network, or data outside its lane.

Threat model addressed
----------------------
Tool escape, host filesystem access beyond the allow-listed root (``MCP_ROOT``),
unexpected network egress, and privilege escalation.

Design (AGENTS.md §3/§5, DESIGN.md trust boundaries)
----------------------------------------------------
* **Rootless runtime** — Podman (preferred; daemonless) or rootless Docker,
  auto-detected. No dependency on a root-owned daemon.
* **Default-deny network** — ``--network=none``: zero egress unless a profile
  explicitly opts in.
* **Drop all privilege** — ``--cap-drop=ALL`` and ``--security-opt
  no-new-privileges`` so a tool cannot acquire capabilities it was not given.
* **Confined syscalls / filesystem** — committed **seccomp** (deny-by-default)
  and **AppArmor** profiles under ``profiles/``.
* **Read-only rootfs** — ``--read-only``; the only writable area is a size-capped
  ``tmpfs`` work dir, wiped when the container exits.
* **Least-privilege mount** — only ``MCP_ROOT`` is mounted, **read-only**, at
  ``/data``. Nothing else on the host is visible.
* **Resource bounds** — memory, PID, and CPU limits cap a runaway or fork-bomb
  tool.
* **Fail closed** — if no container runtime is available the run is **refused**
  (:class:`SandboxUnavailableError`); a tool is *never* executed unsandboxed.
* **Staged rollout** — :data:`SandboxMode` ``"report"`` audits the *intended*
  hardened command without executing it, mirroring the ``report_only`` flag in
  :mod:`agents.tools.guarded`. Promote to ``"enforce"`` once validated.

The command handed to :meth:`SandboxRunner.run` is executed with ``shell=False``
(argument vector, never a shell string), so tool arguments cannot be
shell-injected regardless of content.
"""

from __future__ import annotations

import enum
import re
import shutil
import subprocess  # nosec B404 - the whole point of this module is to confine subprocess use
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final, Literal

from agents.policies import AuditLogger


class _Keep(enum.Enum):
    """Sentinel: 'leave this profile unchanged' in :meth:`SandboxRunner.with_profiles`."""

    TOKEN = enum.auto()


#: Passed as a ``with_profiles`` default to distinguish "not provided" from an
#: explicit ``None`` / ``""`` (which *disable* a profile).
_KEEP: Final = _Keep.TOKEN

__all__ = [
    "PROFILE_DIR",
    "SandboxConfig",
    "SandboxMode",
    "SandboxResult",
    "SandboxRunner",
    "SandboxUnavailableError",
]

#: Directory holding the committed seccomp / AppArmor profiles.
PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
_SECCOMP_PROFILE = PROFILE_DIR / "seccomp.json"
_APPARMOR_PROFILE_NAME = "mcp-tool"

#: ``"enforce"`` runs the tool inside the sandbox; ``"report"`` audits the
#: intended run without executing it (staged rollout).
SandboxMode = Literal["enforce", "report"]

#: Container runtimes we accept, most-preferred first. Podman is rootless and
#: daemonless by default, so it is the safer default.
_RUNTIME_PREFERENCE: tuple[str, ...] = ("podman", "docker")


class SandboxUnavailableError(RuntimeError):
    """Raised when no container runtime is available to confine a tool.

    Surfacing this (rather than silently running the tool on the host) is the
    fail-closed guarantee: a tool that cannot be sandboxed does not run.
    """


@dataclass(frozen=True)
class SandboxConfig:
    """Confinement policy for a sandboxed tool execution.

    All defaults are the *safe* configuration (AGENTS.md §3, "secure defaults"):
    no network, all capabilities dropped, read-only rootfs, tight resource caps.
    """

    #: Host directory exposed to the tool (read-only) at ``/data``. Ties to
    #: ``MCP_ROOT``; must be an existing directory.
    root: Path
    #: Minimal OCI image the tool runs in. Pin by digest (``name@sha256:...``) in
    #: production so a mutable tag cannot be swapped under you; see
    #: ``require_pinned_image``.
    image: str = "docker.io/library/python:3.12-slim"
    #: ``"enforce"`` (run confined) or ``"report"`` (audit-only, no execution).
    mode: SandboxMode = "report"
    #: Explicit runtime ("podman"/"docker"); ``None`` auto-detects.
    runtime: str | None = None
    #: Container network. ``"none"`` = default-deny egress.
    network: str = "none"
    #: Memory ceiling (container ``--memory``).
    memory: str = "256m"
    #: Max process/thread count (``--pids-limit``) — caps fork bombs.
    pids_limit: int = 128
    #: CPU quota (``--cpus``).
    cpus: str = "1.0"
    #: Wall-clock timeout for the whole run, in seconds. Fail-closed on hang.
    timeout_s: float = 30.0
    #: Writable tmpfs work dir mounted at ``/work`` (the only writable path).
    tmpfs_size: str = "64m"
    #: Path to the seccomp profile (deny-by-default). ``None`` omits the flag
    #: (e.g. a host/runtime where the profile cannot be applied).
    seccomp_profile: Path | None = _SECCOMP_PROFILE
    #: Loaded AppArmor profile name (``apparmor_parser``-loaded out of band). An
    #: empty string omits the flag where AppArmor is unavailable.
    apparmor_profile: str = _APPARMOR_PROFILE_NAME
    #: When ``True``, reject an ``image`` that is not pinned by digest
    #: (``…@sha256:<64 hex>``) — a supply-chain guard for production so a mutable
    #: tag cannot be repointed to a different image between builds.
    require_pinned_image: bool = False

    def __post_init__(self) -> None:
        if not self.root.is_dir():
            raise ValueError(f"sandbox root is not a directory: {self.root}")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if self.pids_limit <= 0:
            raise ValueError("pids_limit must be positive")
        if self.require_pinned_image and not self.is_pinned_image:
            raise ValueError(f"image must be pinned by digest (name@sha256:...): {self.image!r}")

    @property
    def is_pinned_image(self) -> bool:
        """True if ``image`` carries an explicit ``@sha256:<64 hex>`` digest."""
        _, _, digest = self.image.partition("@")
        return bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest))


@dataclass(frozen=True)
class SandboxResult:
    """Outcome of a (real or reported) sandboxed run."""

    #: Whether the command actually executed (False in report mode / on refusal).
    executed: bool
    #: Process exit code, or ``None`` if it did not execute.
    returncode: int | None
    #: Captured stdout (empty if not executed).
    stdout: str
    #: Captured stderr (empty if not executed).
    stderr: str
    #: The fully-materialised container argv that was (or would be) run.
    command: tuple[str, ...]
    #: Human-readable note (e.g. "report-only", "timeout", "ok").
    reason: str


@dataclass
class SandboxRunner:
    """Builds and runs the hardened container invocation for a tool command.

    Pass an :class:`~agents.policies.AuditLogger` to record every run decision
    (reported, executed, refused, timed-out) to the tamper-evident trail — the
    same log the policy engine writes to, so sandbox events sit alongside policy
    decisions (Roadmap #5 ties to #1/#2).
    """

    config: SandboxConfig
    audit: AuditLogger | None = None
    actor: str = "mcp-sandbox"
    #: Injectable ``PATH`` lookup (defaults to ``shutil.which``); overridden in
    #: tests to simulate a host with or without a container runtime.
    _runtime_lookup: Callable[[str], str | None] = field(default=shutil.which, repr=False)

    def resolve_runtime(self) -> str:
        """Return the container runtime executable, or fail closed.

        Honors an explicit ``config.runtime`` if set, otherwise probes
        :data:`_RUNTIME_PREFERENCE` in order. Raises
        :class:`SandboxUnavailableError` if none is on ``PATH`` — the
        fail-closed guard so a tool is never run unconfined.
        """
        candidates: Sequence[str] = (
            (self.config.runtime,) if self.config.runtime else _RUNTIME_PREFERENCE
        )
        for name in candidates:
            path = self._runtime_lookup(name)
            if path:
                return path
        raise SandboxUnavailableError(
            "no rootless container runtime found (looked for "
            f"{', '.join(candidates)}); refusing to run tool unsandboxed"
        )

    def with_profiles(
        self,
        *,
        seccomp_profile: Path | None | _Keep = _KEEP,
        apparmor_profile: str | _Keep = _KEEP,
    ) -> SandboxRunner:
        """Return a copy of this runner with per-tool seccomp/AppArmor profiles.

        Lets one base runner confine different tools under different profiles
        (least privilege per capability). Only the profiles given are changed —
        every other setting (image, limits, audit sink, runtime lookup) is
        preserved. Pass ``seccomp_profile=None`` / ``apparmor_profile=""`` to
        *disable* a profile for that tool; omit an argument to keep the base's.
        """
        cfg = replace(
            self.config,
            seccomp_profile=(
                self.config.seccomp_profile
                if isinstance(seccomp_profile, _Keep)
                else seccomp_profile
            ),
            apparmor_profile=(
                self.config.apparmor_profile
                if isinstance(apparmor_profile, _Keep)
                else apparmor_profile
            ),
        )
        return replace(self, config=cfg)

    def build_command(self, argv: Sequence[str], *, runtime: str) -> tuple[str, ...]:
        """Materialise the full hardened ``<runtime> run ...`` argument vector.

        Pure and side-effect free, so it is unit-testable on any OS (the syscall
        confinement itself only takes effect on a Linux host with the runtime).
        ``argv`` is the command to run *inside* the container.
        """
        if not argv:
            raise ValueError("argv must be a non-empty command vector")
        cfg = self.config
        cmd: list[str] = [
            runtime,
            "run",
            "--rm",
            "--network",
            cfg.network,  # default-deny egress
            "--cap-drop",
            "ALL",  # no capabilities
            "--security-opt",
            "no-new-privileges",  # cannot regain privilege via setuid
        ]
        # Profile flags are the secure default but are *optional*: an unset value
        # omits the flag so the sandbox still runs (with its other controls) on a
        # host where that profile cannot be applied — e.g. a rootless runtime or
        # runner without a loaded AppArmor profile. The core confinement
        # (no network, no capabilities, read-only rootfs, non-root, MCP_ROOT-only
        # mount) never depends on these.
        if cfg.seccomp_profile is not None:
            cmd += ["--security-opt", f"seccomp={cfg.seccomp_profile}"]  # deny-by-default syscalls
        if cfg.apparmor_profile:
            cmd += ["--security-opt", f"apparmor={cfg.apparmor_profile}"]  # FS/network MAC
        cmd += [
            "--read-only",  # immutable rootfs
            "--tmpfs",
            f"/work:rw,noexec,nosuid,nodev,size={cfg.tmpfs_size}",
            "--workdir",
            "/work",
            "--user",
            "65534:65534",  # nobody:nogroup — never root inside
            "--memory",
            cfg.memory,
            "--pids-limit",
            str(cfg.pids_limit),
            "--cpus",
            cfg.cpus,
            "--volume",
            f"{cfg.root}:/data:ro",  # only MCP_ROOT, read-only
            cfg.image,
            *argv,
        ]
        return tuple(cmd)

    def run(self, argv: Sequence[str], *, name: str) -> SandboxResult:
        """Run ``argv`` inside the sandbox (or audit it, in report mode).

        * ``report`` mode: records the intended hardened command and returns
          without executing — the command is **not** run on the host.
        * ``enforce`` mode: resolves the runtime (fail-closed) and executes the
          container with ``shell=False`` and a wall-clock timeout.

        Every outcome is audited when an ``AuditLogger`` is configured.
        """
        # In report mode we still resolve the runtime opportunistically so the
        # audit note reflects whether enforcement *would* be possible, but we
        # never execute. A missing runtime in report mode is informational.
        if self.config.mode == "report":
            try:
                runtime = self.resolve_runtime()
                note = "report-only (runtime available)"
            except SandboxUnavailableError:
                runtime = _RUNTIME_PREFERENCE[0]
                note = "report-only (no runtime; would refuse in enforce mode)"
            command = self.build_command(argv, runtime=runtime)
            self._audit(name, decision="report", reason=note)
            return SandboxResult(
                executed=False,
                returncode=None,
                stdout="",
                stderr="",
                command=command,
                reason=note,
            )

        # enforce mode — fail closed if we cannot confine the tool.
        try:
            runtime = self.resolve_runtime()
        except SandboxUnavailableError as exc:
            self._audit(name, decision="deny", reason=f"no runtime: {exc}")
            raise

        command = self.build_command(argv, runtime=runtime)
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
                command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_s,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            self._audit(name, decision="deny", reason="timeout")
            return SandboxResult(
                executed=True,
                returncode=None,
                stdout="",
                stderr="",
                command=command,
                reason="timeout",
            )
        decision = "allow" if proc.returncode == 0 else "deny"
        self._audit(name, decision=decision, reason=f"exit={proc.returncode}")
        return SandboxResult(
            executed=True,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            command=command,
            reason=f"exit={proc.returncode}",
        )

    def _audit(self, name: str, *, decision: str, reason: str) -> None:
        if self.audit is None:
            return
        self.audit.record(
            actor=self.actor,
            action=f"sandbox:{name}",
            action_class="external_network",
            decision=decision,
            reason=reason,
        )
