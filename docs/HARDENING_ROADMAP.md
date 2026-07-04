# Hardening Roadmap

Defense-in-depth workstreams that extend the platform's existing secure-by-default
posture (least privilege, auditability, human-in-the-loop). Each item is scoped as an
independent, reviewable increment consistent with [`AGENTS.md`](../AGENTS.md) and
[`DESIGN.md`](../DESIGN.md).

> Status: planned. Nothing here weakens an existing control; every item is additive
> and fail-closed by design.

---

## Priority sequence

Ordered by security value per unit of effort, respecting dependencies.

| # | Workstream | Security value | Effort | Risk to add | Depends on |
|---|---|---|---|---|---|
| 1 | Policy-as-code allow/deny layer (`agents/policies/`) | High | M | Low | — |
| 2 | Tamper-evident audit logging + retention | High | M | Low | 1 (policy decisions are audit events) |
| 3 | Property-based fuzzing of tool input validators | Medium-High | S | Low | — |
| 4 | Signed SBOM + provenance attestation in CI | Medium | S–M | Low | existing SBOM gate |
| 5 | Rootless seccomp/AppArmor sandbox for MCP tools | High | L | Medium | 1 (policy decides what runs sandboxed) |

Rationale: 1 and 2 are the backbone — a decision point (policy) and an evidence trail
(audit log) that every other control reports through. 3 and 4 are low-effort, high-signal
wins that harden existing surfaces without new runtime dependencies. 5 delivers the
strongest isolation but carries the most operational weight (container runtime, profiles,
CI matrix), so it lands last and builds on the policy layer.

---

## 1. Policy-as-code allow/deny layer

**Objective.** Move authorization decisions out of imperative `if` checks scattered across
agents and MCP tools into a single declarative, testable policy set under
`agents/policies/`, evaluated at every tool-call boundary. Deny-by-default.

**Threat addressed.** Inconsistent or missing authorization; privilege creep; an agent or
tool invoking an action it was never meant to (confused-deputy, over-broad tool access).

**Approach.**
- Model policies as declarative rules (OPA **Rego**, or a pure-Python rules engine if
  keeping the zero-external-binary constraint matters more than Rego's ecosystem).
- Single choke point: a `PolicyDecision = evaluate(subject, action, resource, context)`
  called by the orchestrator before any tool dispatch and by the MCP server before
  `tools/call`. Default result is `deny`.
- Inputs: acting agent, tool name, argument shape, target path/host, and whether the action
  is irreversible/external (ties into the existing human-in-the-loop gate).
- Ship a small, versioned bundle: `agents/policies/*.rego` (or `.yaml`) + a loader that
  fails closed if the bundle is missing or unparseable.

**Acceptance criteria.**
- Every tool dispatch and `tools/call` passes through `evaluate()`; no direct tool invocation
  bypasses it (enforced by a test that greps for bypass patterns).
- Deny-by-default proven: an unknown action returns `deny` with a reason string.
- Policies are unit-tested with allow and deny fixtures; coverage counts toward the 85% gate.
- Decisions are structured objects (allow/deny + rule id + reason) suitable for audit (feeds #2).

**Risks / trade-offs.** OPA adds a binary/WASM dependency (mitigate with pinned version +
checksum, or choose the pure-Python engine). Poorly-scoped rules can over-block — ship with
a dry-run/report mode before enforce mode.

**Effort.** Medium.

---

## 2. Tamper-evident audit logging with retention

**Objective.** Make the audit trail append-only and verifiable, so any modification or
deletion of past events is detectable, with an explicit retention/rotation policy.

**Threat addressed.** Log tampering to hide malicious or erroneous actions; silent gaps;
unbounded or non-compliant retention.

**Approach.**
- **Hash chaining:** each record stores `hash = H(prev_hash || canonical(entry))`, forming a
  Merkle-style chain; a broken link proves tampering. Verifiable offline with a `verify` command.
- **Signing:** periodically (or per-entry) sign the head hash. Options, cheapest first:
  HMAC with a protected key; asymmetric signature (Ed25519); or keyless **sigstore/cosign**
  if you want transparency-log backing.
- **Retention:** documented policy (e.g. hot 90 days, cold archive N months, then purge),
  enforced by a rotation job; archived segments keep their terminal hash so the chain stays
  verifiable across rotations. Write-once semantics where the FS/storage supports it.

**Acceptance criteria.**
- Append-only writer + `audit verify` that recomputes the chain and reports the first broken link.
- Every policy decision (#1), gated human approval, and tool execution emits an audit event.
- Retention/rotation policy documented in this file and implemented by a scheduled task; rotation
  preserves verifiability.
- Tests cover: valid chain verifies; a mutated middle entry fails at the right index.

**Risks / trade-offs.** Key management for signing (store outside the repo; rotate). Hash chaining
alone proves integrity, not confidentiality — pair with access controls on the log store.

**Effort.** Medium.

---

## 3. Property-based fuzzing of tool input validators

**Objective.** Prove the input validators guarding every MCP tool and agent entry point hold
under adversarial and malformed inputs, not just the hand-written examples.

**Threat addressed.** Injection, path traversal, integer/format edge cases, and validator
bypass reaching tool execution.

**Approach.**
- Use **Hypothesis** (Python property-based testing) in `tests/security/`.
- For each validator, assert invariants over generated inputs: rejects paths escaping the
  sandbox root, rejects oversized or control-character payloads, never raises unhandled
  exceptions, and output always conforms to the declared schema/type.
- Seed strategies from real tool schemas so generation stays relevant; add a regression corpus
  for any failing case Hypothesis finds (`@example`).

**Acceptance criteria.**
- Each tool input validator has at least one property test with explicit invariants.
- CI runs the fuzz suite deterministically (fixed seed/`derandomize`) so failures reproduce.
- A found counterexample becomes a pinned regression example.
- Suite is part of `tests/security/` and counts toward coverage.

**Risks / trade-offs.** Flaky/slow generation if strategies are too broad — bound example counts
and pin the seed in CI. Low risk to add; no runtime dependency.

**Effort.** Small.

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
- **Sequencing:** land 1 → 2 first (decision + evidence), then 3 and 4 (cheap, high-signal),
  then 5 (strongest isolation, heaviest lift).
