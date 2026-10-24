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

**Scheduled enforcement — shipped.** `AuditLogger.apply_retention()` applies the size/rotation +
retention policy on demand (idempotent; appends no entry, so the head signature is unchanged),
and `scripts/audit_maintenance.py` is a fail-closed CLI for a scheduler: it verifies the chain
(and signature) first and **aborts without rotating** if verification fails, then applies the
policy and prints a JSON summary. The script docstring carries crontab / systemd-timer examples.
Covered by `tests/unit/test_audit_maintenance.py`.

**Two ways it was not fail-closed — found by a later survey, both now shut.** A *nonexistent*
log verified as intact, because an empty chain is a valid chain: a job pointed at a typo
printed `{"verified": true}`, exited `0`, and built the wrong path on the way out through
`apply_retention`'s `mkdir(parents=True)`. Its own documented cron line pointed at
`data/audit.log`, which no writer in the platform creates — there is one chain per subsystem —
so the example *was* the typo. Separately, it resolved only `AUDIT_HMAC_KEY`, so on an
Ed25519-signed chain (the scheme whose whole point is that a verifier holds only the public
key) it configured no signer, reported the head signature as `unsigned`, verified the chain
alone, and rotated — a stale or forged signature could not stop the one job in the platform
that *deletes* evidence. Both now resolve through the same
`agents/policies/audit.py::verifier_from_env` the read-only verifier uses, so this job cannot
rotate a log `scripts/audit_verify.py` would reject; a missing log exits `2` with the
verifier's own `failure` text and is **not** skipped by `--no-verify`, and key material that
exists but cannot be used exits `3` instead of degrading to a chain-only pass.

**A third way, found in review, and the most destructive.** Chain discovery used
`Path.exists()`, which is true of a *directory*, and `apply_retention` acts on what it
discovers: a `--log` one component short of the log made `_rotate` **rename the whole
subsystem directory** to `<name>.1` — audit chain and pipeline cursor with it — reporting
`{"rotated": true, "archives": 1}` at exit `0`, and with `--log …/data` it took the entire
lab-data root including the event store. The next run then tracebacked out of `_prune`'s
`unlink()` at exit 1, so the rename was always discovered too late. A chain is made of
files and nothing said so; every discovery now requires a regular, non-symlink file
(`AuditLogger._is_segment`), in the library rather than in the CLI because `AuditLogger` is
public API — a plant proved that necessary, since the CLI-level test stayed green when
`_should_rotate` alone was reverted. Both CLIs now distinguish "nothing was ever logged
here" from "this path is not a log", because a mistyped path is the reachable cause and
"not found" sends the operator looking for the wrong thing. Covered by
`tests/security/test_audit_maintenance_failclosed.py`.

**Asymmetric signing — shipped.** Signing is now pluggable (`agents/policies/signing.py`,
`Signer` protocol): `HmacSigner` (symmetric, default) and **`Ed25519Signer` / `Ed25519Verifier`**
(asymmetric). With Ed25519 a verifier confirms the head with only the **public** key — no shared
secret to also forge with — via `AuditLogger(signer=Ed25519Verifier(public_key))`. Ed25519 uses
the optional `[crypto]` extra (`cryptography`), lazy-imported so the core audit module keeps no
hard crypto dependency; keys come from `AUDIT_ED25519_PRIVATE_KEY` / `AUDIT_ED25519_PUBLIC_KEY`.
Covered by `tests/security/test_ed25519_signing.py`.

**Correction: no writer signed with Ed25519 until `signer_from_env`.** The paragraph above
described the signer classes, and every chain writer (`run_backup`, `run_retention`,
`run_pipeline`, `run_collector` and `compliance.evidence`) still resolved the HMAC-only
`signing_key_from_env`. So an Ed25519 deployment wrote unsigned heads that its public-key
verifiers reported broken. Writers now resolve `agents.policies.audit.signer_from_env`, with
`verifier_from_env`'s precedence: HMAC, then the Ed25519 private key. A node holding only the
private key also verifies with it, and a mismatched pair is refused on both sides. Covered by
`tests/security/test_audit_writer_signer.py`, including each writer end to end, plus an AST
guard that no production `AuditLogger` call passes the HMAC-only `signing_key=`.

**Remaining (optional).** Nothing outstanding — the audit trail is hash-chained, signed
(HMAC or Ed25519), rotated, retained (checkpoint-anchored), and enforceable on a schedule.
A sigstore-cosign / transparency-log backend is a possible future direction.

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

**Coverage-guided fuzzing — added 2026-10-24.** Hypothesis draws inputs from strategies and
does not learn from what they reach. The parsers that read untrusted bytes are now also
fuzzed under **Atheris**, which keeps the inputs that reach new code.
`tests/fuzz/targets.py` holds one target per surface: `ingest.normalize`,
`ingest.keyvalue.decode`, the egress address and port checks, `EgressAllowlist.load`, and
`NormalizedEvent.from_dict`. Each asserts what its module already documents.
`.github/workflows/fuzz.yml` runs each target for one minute on a pull request or push that
touches what it imports, and for ten minutes weekly. `tests/fuzz/test_fuzz_corpus.py` replays
every seed through the same targets in the ordinary suite, including on platforms Atheris
does not support. The first run found that an unclaimed record's excerpt escapes non-ASCII
characters (`json.dumps` defaults to `ensure_ascii=True`), so a non-ASCII indicator is not a
substring of the excerpt it was extracted from. The target accepts the escaped form until
that is fixed; the fix is its own change, because it alters `event_id` for every such record.
Atheris is pinned in the `fuzz` extra, which installs only on Linux x86_64 with Python ≥ 3.12.

**Remaining enhancements (optional).** Extend property coverage as new tool validators are
added; seed strategies directly from each tool's declared argument schema. Add each contract
`tests/fuzz/targets.py` lists as not yet holding to its target, together with the fix that
makes it hold. Keep a fuzz corpus between scheduled runs, so coverage accumulates instead of
restarting from the seeds each week.

---

## 4. Signed SBOM + dependency provenance attestation in CI — implemented

**Status.** Implemented and verified on the public repo. On push to `main` the `build` job
produces both a **signed SBOM attestation** (`actions/attest`, explicit CycloneDX predicate) and a
**SLSA build-provenance attestation** (`actions/attest-build-provenance`), keyless via GitHub
OIDC. Verified end-to-end with `gh attestation verify` (SBOM predicate `https://cyclonedx.org/bom`;
provenance via the default predicate) — see [`security/sbom/README.md`](../security/sbom/README.md).
Both steps are guarded (push-to-`main`, non-private-user-repo) and fail closed, not
`continue-on-error`.

"Publish attestations alongside releases" is implemented by
[`release.yml`](../.github/workflows/release.yml). A maintainer can publish a
GitHub Release to attach assets, or manually run **Release assets** from the
default branch with a canonical tag such as `v2.1.0`. Both are explicit human
approval actions (AGENTS.md §5.1); push and PR events never publish.

For a new release, merge the release preparation and wait for CI to pass, then:

```bash
gh workflow run release.yml --ref main -f tag=v2.1.0
gh run list --workflow release.yml
gh release view v2.1.0
```

The dispatch uses the selected default-branch commit when the tag is absent.
For an existing tag it checks out that exact tag and verifies the commit belongs
to default-branch history; it never moves tags. The version-chain check rejects
mismatched tags. Lint, formatting, typing and tests run before building. The
workflow builds wheel + sdist, stages the drift-gated CycloneDX SBOM and Sigstore
bundles (where supported), adds `SHA256SUMS`, and retains a downloadable Actions
artifact before publication. It then creates a release **with assets**, or
repairs a published release with idempotent uploads, and verifies asset names.
An existing draft is refused rather than silently published.

**Release immutability: enabled 2026-10-23.** The owner turned on GitHub's
repository setting, so every release published from that date locks its tag and
assets when it is published. What was a convention of this workflow ("tags are never
moved") is now also refused by GitHub. The repair above therefore applies only to a
release published before that date (v2.3.0 and earlier). For a later one,
`release.yml` reads `isImmutable` and does not upload. It checks that every asset
is attached, and if one is missing it fails and names it, because nothing can be
attached afterwards. `tests/security/test_release_immutability.py` runs that step's
script against a stand-in `gh`. A release published from the web page is now a dead
end, not a way to release: it locks with no assets, and the remedy is the next patch
version (`docs/RELEASING.md`).

A release created with `GITHUB_TOKEN` does not trigger another release workflow;
this path performs the build, signing and attachment in the same run. If upload
fails, use the retained Actions artifact for diagnosis, fix access, and rerun
**Release assets** with the same tag. Hosted API access and signing cannot be
validated by a local package build. Missing tag/version, signing, or upload
failures remain blocking; no control uses `continue-on-error`.

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
