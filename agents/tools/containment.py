"""Defensive containment toolkit — stop or contain an active payload (lab-scoped).

Gives agents the sanctioned ability to contain or shut down malicious payloads
during a ransomware or extortion incident, when waiting for a human defeats the
control (encryption completes in minutes). Standing human authorization for this
class is recorded in the DESIGN.md decision log (2026-08-21).

| | |
|---|---|
| **Purpose** | Time-critical, defensive incident response: quarantine a payload, stop its process, isolate a lab host, block an indicator, disable a compromised account |
| **Risk level** | Medium — actions change lab state, but every primitive is reversible by design, policy-gated, input-validated, and audited |
| **Skill level required** | SOC analyst / detection engineer |
| **Deployment complexity** | Low for file/process actions (stdlib only); host/network/account actions additionally require a lab-scoped :class:`ContainmentExecutor` |

Layered controls (AGENTS.md §3 defense in depth):

1. **Policy gate** — every capability calls :func:`agents.tools.guarded.enforce`
   with ``action_class="containment"`` before touching anything; operators can
   re-gate the class or deny-list individual capabilities in the policy bundle.
2. **Input validation** — paths resolve through
   :func:`agents.tools.validation.resolve_within` (no traversal out of the lab
   root); pids, hostnames, accounts, and indicators pass strict format checks
   before they reach the OS or an executor (untrusted/LLM-derived input,
   DESIGN.md §5).
3. **Reversibility** — quarantine has ``release_file``, suspend has
   ``resume_process``, isolate/block/disable have restore/unblock/enable
   counterparts. The only irreversible primitive, ``stop_process(force=True)``
   (SIGKILL), is opt-in per call, says so in its returned action, and is gated
   under its own ``stop_process_force`` policy label so operators can deny-list
   the kill while keeping the suspend. Anything truly destructive (deleting
   data, wiping hosts) is *not* in this class — it stays ``destructive`` and
   keeps its human approval gate.
4. **Audit** — the policy decision *and* the execution outcome are recorded to
   the tamper-evident, hash-chained audit trail when a logger is configured.
5. **Fail closed** — a missing executor, an executor that does not confirm
   execution, or any validation failure raises; a containment action that did
   not happen can never look contained.

Every capability is mapped to the MITRE ATT&CK techniques it counters in
:mod:`agents.tools.attack_mapping`; the returned :class:`ContainmentAction`
carries those technique IDs, and :meth:`ContainmentToolkit.attack_coverage`
exposes the full described catalog.

POSIX-only for process signals (SIGSTOP/SIGCONT/SIGKILL), matching the
repository's Linux lab baseline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agents.policies import AuditLogger, PolicyEngine
from agents.tools.attack_mapping import attack_coverage as _attack_coverage
from agents.tools.attack_mapping import get_mapping
from agents.tools.guarded import enforce
from agents.tools.validation import ValidationError, resolve_within

#: Vault directory (inside the lab root) that holds quarantined payloads.
QUARANTINE_DIRNAME = ".quarantine"

_HASH_CHUNK = 1 << 20  # 1 MiB streaming-hash chunks — bounded memory on large payloads
_MAX_TARGET_LEN = 253  # hostname length ceiling (RFC 1035); reused as a general cap

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
_ACCOUNT_RE = re.compile(r"^[a-z_][a-z0-9._-]{0,31}$", re.IGNORECASE)
_HEX_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)


class ContainmentError(ValidationError):
    """Raised when a containment action cannot be performed safely (fail closed)."""


class ContainmentExecutor(Protocol):
    """Lab-scoped executor for actions the process itself cannot perform.

    Implementations carry out host isolation, indicator blocking, and account
    disabling against **owned lab infrastructure only** (AGENTS.md §5 lawful-lab
    scope) — e.g. a lab firewall or directory adapter. They must be idempotent
    and return ``True`` only when the action verifiably took effect; the toolkit
    treats anything else as not contained and raises.
    """

    def execute(self, capability: str, target: str) -> bool:
        """Perform ``capability`` against ``target``; return ``True`` on success."""
        ...


@dataclass(frozen=True)
class ContainmentAction:
    """The auditable record of one containment action.

    ``attack_techniques`` holds the MITRE ATT&CK technique IDs this capability
    counters (see :mod:`agents.tools.attack_mapping` for full descriptions).
    """

    capability: str
    target: str
    executed: bool
    reversible: bool
    rollback: str
    detail: str
    attack_techniques: tuple[str, ...]


class ContainmentToolkit:
    """Policy-gated, reversible containment primitives for the lab scope.

    Args:
        root: Trusted lab root; file actions are confined inside it.
        engine: Policy engine deciding the ``containment`` class (defaults to the
            in-code default policy, which allows it — see
            ``agents/policies/approval.py``).
        audit: Optional tamper-evident audit logger; records every policy
            decision and execution outcome.
        executor: Optional lab executor for host/network/account actions;
            without one those capabilities fail closed.
        actor: Actor label recorded on audit entries.
    """

    def __init__(
        self,
        root: Path,
        *,
        engine: PolicyEngine | None = None,
        audit: AuditLogger | None = None,
        executor: ContainmentExecutor | None = None,
        actor: str = "containment",
    ) -> None:
        resolved = Path(root).resolve()
        if not resolved.is_dir():
            raise ContainmentError(f"containment root is not a directory: {root}")
        self.root = resolved
        self.engine = engine or PolicyEngine()
        self.audit = audit
        self.executor = executor
        self.actor = actor

    # --- shared plumbing ----------------------------------------------------

    @staticmethod
    def attack_coverage() -> dict[str, Any]:
        """MITRE ATT&CK mapping (with descriptions) for every capability here."""
        return _attack_coverage()

    def _gate(self, capability: str) -> None:
        """Policy-gate ``capability`` (records the decision; raises unless allowed)."""
        enforce(
            action_class="containment",
            name=capability,
            engine=self.engine,
            audit=self.audit,
            actor=self.actor,
        )

    def _record_outcome(self, capability: str, target: str, detail: str) -> None:
        """Append the execution outcome to the audit trail (decision ≠ execution)."""
        if self.audit is not None:
            self.audit.record(
                actor=self.actor,
                action=f"containment:{capability}:{target[:120]}",
                action_class="containment",
                decision="allow",
                reason=detail[:200],
            )

    def _action(
        self,
        capability: str,
        target: str,
        *,
        reversible: bool,
        rollback: str,
        detail: str,
    ) -> ContainmentAction:
        self._record_outcome(capability, target, detail)
        return ContainmentAction(
            capability=capability,
            target=target,
            executed=True,
            reversible=reversible,
            rollback=rollback,
            detail=detail,
            attack_techniques=get_mapping(capability).technique_ids(),
        )

    @property
    def _vault(self) -> Path:
        return self.root / QUARANTINE_DIRNAME

    @staticmethod
    def _resolve_no_symlink(base: Path, candidate: str) -> Path:
        """Resolve ``candidate`` inside ``base``, refusing any symlink component.

        ``resolve_within`` alone follows symlinks, which would let a planted
        in-root symlink redirect a quarantine or release to a different file
        (an attacker-controlled aliasing primitive). Comparing the resolved
        path against the purely lexical normalization detects any symlink in
        the path — including a dangling one at the final component — and fails
        closed. ``base`` must already be fully resolved.
        """
        target = resolve_within(base, candidate)
        lexical = Path(os.path.normpath(base / candidate))
        if lexical != target:
            raise ContainmentError(
                f"path contains a symlink — refusing to act through it: {candidate!r}"
            )
        return target

    # --- file quarantine (stdlib, reversible) -------------------------------

    def quarantine_file(self, path: str) -> ContainmentAction:
        """Quarantine a suspected payload file inside the lab root.

        The file is moved into the permission-stripped vault
        (``<root>/.quarantine/``, mode ``0o400`` — preserved for forensics, no
        longer executable) with a sidecar recording its origin for
        :meth:`release_file`. Validates ``path`` against traversal out of the
        root; refuses non-files, files already in the vault, and duplicate
        vault entries (fail closed).
        """
        self._gate("quarantine_file")
        target = self._resolve_no_symlink(self.root, path)
        if self._vault in (target, *target.parents):
            raise ContainmentError("file is already inside the quarantine vault")
        if not target.is_file():
            raise ContainmentError(f"not a file: {path!r}")

        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()

        self._vault.mkdir(mode=0o700, exist_ok=True)
        entry = self._vault / f"{sha256[:12]}__{target.name}"
        if entry.exists():
            raise ContainmentError(f"vault entry already exists: {entry.name!r}")

        meta = {
            "original": target.relative_to(self.root).as_posix(),
            "sha256": sha256,
        }
        # Sidecar first: a crash between the two steps leaves the original intact
        # plus a stale sidecar — never a stranded payload with no way back.
        entry.with_name(entry.name + ".meta.json").write_text(
            json.dumps(meta, sort_keys=True), encoding="utf-8"
        )
        target.rename(entry)
        entry.chmod(0o400)
        return self._action(
            "quarantine_file",
            meta["original"],
            reversible=True,
            rollback=f"release_file({entry.name!r})",
            detail=f"moved to {QUARANTINE_DIRNAME}/{entry.name} (sha256={sha256})",
        )

    def release_file(self, entry_name: str) -> ContainmentAction:
        """Restore a quarantined file to its original path (confirmed false positive).

        The file is restored with mode ``0o600`` — never with execute
        permission; a human re-enables execution deliberately. Fails closed if
        the vault entry or its sidecar is missing/invalid, or if a file now
        exists at the original path.
        """
        self._gate("release_file")
        entry = self._resolve_no_symlink(self._vault, entry_name)
        if entry.parent != self._vault or not entry.is_file():
            raise ContainmentError(f"no such vault entry: {entry_name!r}")
        sidecar = entry.with_name(entry.name + ".meta.json")
        try:
            meta = json.loads(sidecar.read_text(encoding="utf-8"))
            original_rel = meta["original"]
            if not isinstance(original_rel, str):
                raise TypeError("'original' must be a string")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ContainmentError(f"vault sidecar missing or invalid: {entry_name!r}") from exc

        original = self._resolve_no_symlink(self.root, original_rel)
        if original.exists():
            raise ContainmentError(f"refusing to overwrite existing file: {original_rel!r}")
        original.parent.mkdir(parents=True, exist_ok=True)
        entry.chmod(0o600)
        entry.rename(original)
        sidecar.unlink()
        return self._action(
            "release_file",
            original_rel,
            reversible=True,
            rollback=f"quarantine_file({original_rel!r})",
            detail="restored without execute permission (mode 0o600)",
        )

    # --- process containment (stdlib, POSIX) --------------------------------

    def _validate_pid(self, pid: int) -> int:
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise ContainmentError("pid must be an integer")
        if pid <= 1:
            raise ContainmentError(f"refusing to signal pid {pid} (init/kernel range)")
        if pid in (os.getpid(), os.getppid()):
            raise ContainmentError(f"refusing to signal own process tree (pid {pid})")
        return pid

    def _signal(self, capability: str, pid: int, sig: signal.Signals) -> None:
        try:
            os.kill(self._validate_pid(pid), sig)
        except ProcessLookupError as exc:
            raise ContainmentError(f"{capability}: no such process: {pid}") from exc
        except PermissionError as exc:
            # Least privilege: an unprivileged lab process can only signal its
            # own user's processes — surface that honestly instead of escalating.
            raise ContainmentError(
                f"{capability}: not permitted to signal pid {pid} (outside lab privilege)"
            ) from exc

    def stop_process(self, pid: int, *, force: bool = False) -> ContainmentAction:
        """Stop a payload process: suspend it (default) or kill it (``force=True``).

        The default ``SIGSTOP`` freezes the process reversibly (evidence stays in
        memory; undo with :meth:`resume_process`). ``force=True`` sends
        ``SIGKILL`` for a payload actively encrypting or exfiltrating — final
        for that process, and labeled irreversible in the returned action. The
        force path is gated under its own ``stop_process_force`` policy label,
        so operators can deny-list the kill while keeping the suspend.
        Refuses pid ≤ 1 and this process's own tree.
        """
        self._gate("stop_process_force" if force else "stop_process")
        sig = signal.SIGKILL if force else signal.SIGSTOP
        self._signal("stop_process", pid, sig)
        if force:
            return self._action(
                "stop_process",
                str(pid),
                reversible=False,
                rollback="none — SIGKILL is final for the target process",
                detail=f"sent SIGKILL to pid {pid}",
            )
        return self._action(
            "stop_process",
            str(pid),
            reversible=True,
            rollback=f"resume_process({pid})",
            detail=f"sent SIGSTOP to pid {pid} (suspended, memory preserved)",
        )

    def resume_process(self, pid: int) -> ContainmentAction:
        """Resume a suspended process (rollback of a non-force :meth:`stop_process`)."""
        self._gate("resume_process")
        self._signal("resume_process", pid, signal.SIGCONT)
        return self._action(
            "resume_process",
            str(pid),
            reversible=True,
            rollback=f"stop_process({pid})",
            detail=f"sent SIGCONT to pid {pid}",
        )

    # --- executor-backed containment (host / network / account) -------------

    def _run_executor(
        self,
        capability: str,
        target: str,
        *,
        reversible: bool,
        rollback: str,
    ) -> ContainmentAction:
        if self.executor is None:
            raise ContainmentError(
                f"{capability}: no containment executor configured — failing closed "
                "(wire a lab-scoped ContainmentExecutor; see DESIGN.md)"
            )
        if self.executor.execute(capability, target) is not True:
            raise ContainmentError(
                f"{capability}: executor did not confirm execution for {target!r} "
                "— treat the target as NOT contained"
            )
        return self._action(
            capability,
            target,
            reversible=reversible,
            rollback=rollback,
            detail=f"executed via lab executor: {capability} {target}",
        )

    @staticmethod
    def _validate_host(host: str) -> str:
        if not isinstance(host, str) or not (0 < len(host) <= _MAX_TARGET_LEN):
            raise ContainmentError("host must be a non-empty string (max 253 chars)")
        candidate = host.strip().lower()
        if not _HOSTNAME_RE.fullmatch(candidate):
            raise ContainmentError(f"invalid lab hostname/address: {host!r}")
        return candidate

    @staticmethod
    def _validate_account(account: str) -> str:
        if not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account.strip()):
            raise ContainmentError(f"invalid account name: {account!r}")
        return account.strip().lower()

    @staticmethod
    def _validate_indicator(indicator: str) -> str:
        if not isinstance(indicator, str) or not (0 < len(indicator) <= _MAX_TARGET_LEN):
            raise ContainmentError("indicator must be a non-empty string (max 253 chars)")
        candidate = indicator.strip().lower()
        if _HEX_HASH_RE.fullmatch(candidate) or _HOSTNAME_RE.fullmatch(candidate):
            return candidate
        raise ContainmentError(
            f"invalid indicator (expected IP/hostname/domain or MD5/SHA-1/SHA-256 "
            f"hex hash): {indicator!r}"
        )

    def isolate_host(self, host: str) -> ContainmentAction:
        """Isolate a lab host from the network (reversible via :meth:`restore_host`)."""
        self._gate("isolate_host")
        target = self._validate_host(host)
        return self._run_executor(
            "isolate_host", target, reversible=True, rollback=f"restore_host({target!r})"
        )

    def restore_host(self, host: str) -> ContainmentAction:
        """Reconnect a previously isolated lab host (rollback of :meth:`isolate_host`)."""
        self._gate("restore_host")
        target = self._validate_host(host)
        return self._run_executor(
            "restore_host", target, reversible=True, rollback=f"isolate_host({target!r})"
        )

    def block_indicator(self, indicator: str) -> ContainmentAction:
        """Block an IoC (IP/domain/hash) at the lab boundary (reversible)."""
        self._gate("block_indicator")
        target = self._validate_indicator(indicator)
        return self._run_executor(
            "block_indicator", target, reversible=True, rollback=f"unblock_indicator({target!r})"
        )

    def unblock_indicator(self, indicator: str) -> ContainmentAction:
        """Remove an IoC block (rollback of :meth:`block_indicator`)."""
        self._gate("unblock_indicator")
        target = self._validate_indicator(indicator)
        return self._run_executor(
            "unblock_indicator", target, reversible=True, rollback=f"block_indicator({target!r})"
        )

    def disable_account(self, account: str) -> ContainmentAction:
        """Disable a compromised lab account (reversible via :meth:`enable_account`)."""
        self._gate("disable_account")
        target = self._validate_account(account)
        return self._run_executor(
            "disable_account", target, reversible=True, rollback=f"enable_account({target!r})"
        )

    def enable_account(self, account: str) -> ContainmentAction:
        """Re-enable a lab account (rollback of :meth:`disable_account`)."""
        self._gate("enable_account")
        target = self._validate_account(account)
        return self._run_executor(
            "enable_account", target, reversible=True, rollback=f"disable_account({target!r})"
        )
