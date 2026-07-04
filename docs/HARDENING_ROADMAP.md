# Hardening Roadmap

Defense-in-depth workstreams that extend the platform's existing secure-by-default
posture (least privilege, auditability, human-in-the-loop). Each item is scoped as an
independent, reviewable increment consistent with [`AGENTS.md`](../AGENTS.md) and
[`DESIGN.md`](../DESIGN.md).

> Status: mixed. Items 1, 2, and 3 are **implemented** (see `agents/policies/` and
> `tests/security/`); items 4-5 are **planned**. Nothing here weakens an existing
> control; every item is additive and fail-closed by design.

---

## Priority sequence

Ordered by security value per unit of effort, respecting dependencies.

| # | Workstream | Security value | Effort | Risk to add | Depends on | Status |
|---|---|---|---|---|---|---|
| 1 | Policy-as-code allow/deny layer (`agents/policies/`) | High | M | Low | — | **Implemented** |
| 2 | Tamper-evident audit logging + retention | High | M | Low | 1 (policy decisions are audit events) | **Implemented** (retention pending) |
| 3 | Property-based fuzzing of tool input validators | Medium-High | S | Low | — | **Implemented** |
| 4 | Signed SBOM + provenance attestation in CI | Medium | S–M | Low | existing SBOM gate | Planned |
| 5 | Rootless seccomp/AppArmor sandbox for MCP tools | High | L | Medium | 1 (policy decides what runs sandboxed) | Planned |

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

## 2. Tamper-evident audit logging with retention — implemented (retention pending)

**Objective.** Make the audit trail append-only and verifiable, so any modification or
deletion of past events is detectable, with an explicit retention/rotation policy.

**Threat addressed.** Log tampering to hide malicious or erroneous actions; silent gaps;
unbounded or non-compliant retention.

**Status — shipped:** `agents/policies/audit.py` — hash-chained, append-only JSONL with
`verify()`; tests in `tests/security/test_audit_logger.py`. Every policy decision and blocked
tool attempt is recorded.

**Remaining (planned).**
- **Signing:** sign the head hash periodically (HMAC / Ed25519 / keyless sigstore-cosign).
- **Retention:** documented rotation policy (e.g. hot 90 days, cold archive, then purge)
  enforced by a scheduled job; archived segments keep their terminal hash so the chain
  stays verifiable across rotations.

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

## 4. Signed SBOM + dependency provenance attestation in CI

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

## 5. Rootless seccomp/AppArmor sandbox for MCP tool execution

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
