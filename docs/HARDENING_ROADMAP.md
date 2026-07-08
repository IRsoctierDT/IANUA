# Hardening Roadmap

Defense-in-depth workstreams that extend the platform's existing secure-by-default
posture (least privilege, auditability, human-in-the-loop). Each item is scoped as an
independent, reviewable increment consistent with [`AGENTS.md`](../AGENTS.md) and
[`DESIGN.md`](../DESIGN.md).

> Status: all five workstreams are **implemented** (see `agents/policies/`,
> `tests/security/`, `security/sbom/`, and `mcp/sandbox/`). Item 5 ships in the safe
> **report mode** by default; kernel enforcement (seccomp/AppArmor) applies on a Linux
> host with a rootless runtime and otherwise fails closed. Nothing here weakens an
> existing control; every item is additive and fail-closed by design.

---

## Priority sequence

Ordered by security value per unit of effort, respecting dependencies.

| # | Workstream | Security value | Effort | Risk to add | Depends on | Status |
|---|---|---|---|---|---|---|
| 1 | Policy-as-code allow/deny layer (`agents/policies/`) | High | M | Low | — | **Implemented** |
| 2 | Tamper-evident audit logging + retention | High | M | Low | 1 (policy decisions are audit events) | **Implemented** |
| 3 | Property-based fuzzing of tool input validators | Medium-High | S | Low | — | **Implemented** |
| 4 | Signed SBOM + provenance attestation in CI | Medium | S–M | Low | existing SBOM gate | **Implemented** |
| 5 | Rootless seccomp/AppArmor sandbox for MCP tools | High | L | Medium | 1 (policy decides what runs sandboxed) | **Implemented** (report-mode default) |

Rationale: 1 and 2 are the backbone — a decision point (policy) and an evidence trail
(audit log) that every other control reports through. 3 and 4 are low-effort, high-signal
wins that harden existing surfaces without new runtime dependencies. 5 delivers the
strongest isolation but carries the most operational weight (container runtime, profiles,
CI matrix), so it lands last and builds on the policy layer.

---

## 1. Policy-as-code allow/deny layer — implemented

**Objective.** Move authorization decisions out of imperative `if` checks scattered across
agents and MCP tools into a single declarative, testable policy set under
`agents/policies/`, evaluated at every tool-call boundary. Deny-by-default.

**Threat addressed.** Inconsistent or missing authorization; privilege creep; an agent or
tool invoking an action it was never meant to (confused-deputy, over-broad tool access).

**Status — shipped.**
- `agents/policies/approval.py` — `PolicyEngine` (default-deny, fail-closed), `ActionClass`
  taxonomy, keyword classification, allow/deny overrides, non-negotiable §5 prohibitions.
- `agents/tools/guarded.py` — `enforce()` choke point + `GuardedCapability`; **`report_only`
  staged-rollout mode** records what would be blocked without raising.
- `agents/policies/bundle.py` + `policy.json` — **declarative JSON policy bundle** with a
  fail-closed loader (stdlib only, no new runtime dependency).
- `mcp/server.py` — every `ToolRegistry.dispatch` routes through `enforce()`.
- `tests/security/` — classification, deny-by-default, allow/deny overrides, prohibition
  non-override, bundle loader (incl. every fail-closed path), report mode, and a
  no-tool-bypass suite.

**Remaining enhancements (optional).** Hot-reload of the bundle; a policy `lint`/schema
command; richer context inputs (target path/host) surfaced into decisions.

---

## 2. Tamper-evident audit logging with retention — implemented

**Objective.** Make the audit trail append-only and verifiable, so any modification or
deletion of past events is detectable, with an explicit retention/rotation policy.

**Threat addressed.** Log tampering to hide malicious or erroneous actions; silent gaps;
unbounded or non-compliant retention.

**Status — shipped:** `agents/policies/audit.py` — hash-chained, append-only JSONL with
`verify()`; tests in `tests/security/test_audit_logger.py`. Every policy decision and blocked
tool attempt is recorded.

**Retention & rotation — shipped.** `AuditLogger(max_bytes=..., retain_segments=...)` rolls the
active log into numbered archives at a size threshold and keeps the most recent *N*. The hash
chain is **continuous across rotation** (a new segment's first entry carries the prior segment's
last hash + next seq), and retention pruning writes a `.checkpoint` recording the last pruned
`(seq, hash)` so the oldest *retained* entry stays anchored — dropping, truncating, editing, or
reordering any retained segment is caught by `verify()`. Covered by
`tests/security/test_audit_retention.py` (continuity, checkpoint-anchored pruning, and detection
of edited/dropped segments and a removed checkpoint). Defaults are unchanged (no rotation) so
existing callers are unaffected.

**Head-hash signing — shipped.** `AuditLogger(signing_key=...)` writes a detached HMAC-SHA256
signature over the current chain head to an `<log>.sig` sidecar after every append; because the
head hash chains over every prior entry, one signature attests the whole log. `verify()` (and
`verify_signature()`) require the signature to be present, authentic, and cover the *current*
head — so an attacker who recomputes a self-consistent chain without the key is still rejected
(`tests/security/test_audit_signing.py`). The key is read from the environment
(`signing_key_from_env()`, `AUDIT_HMAC_KEY`), never the repo; unsigned loggers are unchanged.

**Remaining (optional).**
- **Asymmetric / keyless signing:** Ed25519 or sigstore-cosign so a verifier needs only a public
  key (HMAC verification currently needs the shared secret).
- **Scheduled enforcement:** a cron/job to apply the size/retention policy to the deployed log
  location (the mechanism is in place; wiring it to a schedule is deployment-specific).

---

## 3. Property-based fuzzing of tool input validators — implemented

**Objective.** Prove the input validators guarding every MCP tool and agent entry point hold
under adversarial and malformed inputs, not just the hand-written examples.

**Threat addressed.** Injection, path traversal, integer/format edge cases, and validator
bypass reaching tool execution.

**Status — shipped:** `tests/security/test_fuzz_validators.py` uses **Hypothesis** to assert
invariants over generated inputs, deterministically in CI (`derandomize=True`) with
counterexamples pinned via `@example`:
- `resolve_within` either returns a path confined to the base or raises `ValidationError` —
  no other exception type may escape.
- `classify_action` is total (returns a valid `ActionClass` for any string).
- `PolicyEngine.evaluate` returns a valid structured decision for any non-blank action and
  fails closed (raises) on blank input.

The fuzzer surfaced a real leak — `resolve_within` let a raw `ValueError` escape on an
embedded NUL byte — now hardened to reject NUL bytes and oversized candidates as
`ValidationError`. Hypothesis is pinned in the `dev` extra.

**Remaining enhancements (optional).** Extend property coverage as new tool validators are
added; seed strategies directly from each tool's declared argument schema.

---

## 4. Signed SBOM + dependency provenance attestation in CI — implemented

**Status.** Implemented and verified on the public repo. On push to `main` the `build` job
produces both a **signed SBOM attestation** (`actions/attest-sbom`, CycloneDX predicate) and a
**SLSA build-provenance attestation** (`actions/attest-build-provenance`), keyless via GitHub
OIDC. Verified end-to-end with `gh attestation verify` (SBOM predicate `https://cyclonedx.org/bom`;
provenance via the default predicate) — see [`security/sbom/README.md`](../security/sbom/README.md).
Both steps are guarded (push-to-`main`, non-private-user-repo) and fail closed, not
`continue-on-error`.

**Objective.** Extend the existing CycloneDX SBOM step into signed, verifiable build provenance,
so consumers can confirm what was built, from which sources, by which workflow.

**Threat addressed.** Supply-chain tampering; unverifiable artifacts; dependency substitution.

**Approach.**
- Keep the current CycloneDX SBOM and drift gate.
- Add **SLSA**-style provenance via **in-toto** attestations, signed keylessly with
  **sigstore/cosign** using GitHub OIDC (`id-token: write`) — no long-lived keys.
- Attest both the SBOM and the build artifact; publish attestations alongside releases.
- Note: GitHub's attestation API rejects user-owned **private** repos (already handled by a skip
  guard in CI). This repo is public, so keyless attestation is available on `main`.

**Acceptance criteria.**
- CI produces a signed SBOM attestation and a build-provenance attestation on release/`main`.
- A documented `verify` step (cosign) confirms signature + workflow identity.
- Provenance records the source commit, builder (GitHub Actions), and materials.
- Fail-closed: a signing/attestation failure fails the release job (not `continue-on-error`).

**Risks / trade-offs.** OIDC/permissions fiddliness; keep `id-token: write` scoped to the
attestation job only. Minimal new runtime surface — CI-side only.

**Effort.** Small–Medium.

---

## 5. Rootless seccomp/AppArmor sandbox for MCP tool execution — implemented

**Status.** Implemented in [`mcp/sandbox/`](../mcp/sandbox/README.md). `SandboxRunner` builds
the hardened `podman`/`docker run` invocation (`--network=none`, `--cap-drop=ALL`,
`no-new-privileges`, `--read-only`, tmpfs work dir, non-root user, `seccomp=` + `apparmor=`
committed profiles, `MCP_ROOT` mounted read-only, memory/PID/CPU caps). `mcp.server.
sandboxed_command_tool` wires it into `ToolRegistry.dispatch`, so a policy-allowed call is
then confined. Ships in **report mode** by default (audits the intended run without executing);
**enforce mode** runs on a Linux host with a rootless runtime and **fails closed** (refuses)
where a tool cannot be confined. Covered by `tests/security/test_sandbox.py` (host-independent
construction/fail-closed/report tests everywhere; real syscall/network negative tests gated to
Linux + runtime). Sandbox decisions are recorded to the same tamper-evident audit log as #2.

**Objective.** Execute MCP tools inside a locked-down, rootless container so a compromised or
buggy tool cannot affect the host, the network, or data outside its lane.

**Threat addressed.** Tool escape, host file access beyond the allow-listed root, unexpected
network egress, privilege escalation.

**Approach.**
- Run tool execution in a **rootless** container (Podman or rootless Docker).
- Apply a restrictive **seccomp** profile (deny by default, allow-list syscalls the tools need)
  and an **AppArmor** (or SELinux) profile confining filesystem/network.
- Harden the runtime: `--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only root FS,
  a tmpfs work dir, and default-deny egress with an explicit allow-list.
- Mount only the allow-listed data root (ties to `MCP_ROOT`), read-only where possible.
- The policy layer (#1) decides which tools run and under which profile; sandbox failures are
  audit events (#2).

**Acceptance criteria.**
- MCP `tools/call` executes inside the sandbox with cap-drop, no-new-privileges, read-only rootfs,
  and default-deny egress.
- Seccomp + AppArmor profiles committed and version-controlled; documented syscall/path allow-lists.
- Negative tests: attempts to read outside `MCP_ROOT`, spawn a shell, or open an outbound socket
  are blocked and audited.
- Graceful degradation documented for hosts without a container runtime (e.g. refuse to run rather
  than run unsandboxed).

**Risks / trade-offs.** Highest operational complexity: container runtime dependency, profile
maintenance, and CI coverage across environments. macOS dev vs Linux CI differences in seccomp
support — document the supported matrix. Start in an audit/report mode before hard enforce.

**Effort.** Large.

---

## Cross-cutting notes

- **Fail-closed everywhere:** missing policy bundle, unverifiable audit chain, or absent sandbox
  runtime should refuse the action, never silently proceed.
- **Everything is an audit event:** #1, #4, and #5 all emit into the #2 trail, giving one
  verifiable record of decisions, builds, and executions.
- **Sequencing:** 1 → 2 → 3 are implemented; next is 4 (cheap, high-signal), then 5 (strongest
  isolation, heaviest lift).
