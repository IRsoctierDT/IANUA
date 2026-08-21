# DESIGN.md — IANUA

> Architecture, trust boundaries, and decision record for this repository.
> Read this **before** any change (see [`AGENTS.md`](./AGENTS.md) §2). Update it whenever the
> architecture, a trust boundary, or a major dependency changes.

---

## 1. Executive Summary

IANUA is a **local-first, security-hardened platform** for
running AI/agent workloads, RAG pipelines, and defensive cybersecurity automation. It is
built so that the **safe configuration is the default configuration**: least privilege,
auditable actions, layered validation, and human approval for anything irreversible or
externally visible.

This document describes the intended architecture so that agents and humans make changes
that *fit the design* rather than eroding it.

---

## 2. Objectives

1. Serve and orchestrate **local LLMs** (e.g. via Ollama) with no dependence on external
   inference for core workflows.
2. Provide a **RAG subsystem** for grounding agents in trusted, local document corpora.
3. Expose capabilities to agents through **MCP servers** with strict, validated tool
   surfaces.
4. Support **defensive, lab-scoped** cybersecurity automation (detection content, log
   enrichment, triage helpers).
5. Keep every component **portfolio-grade**: typed, tested, documented, and reviewable.

**Non-objectives:** offensive tooling against unowned systems; any workflow that requires
hard-coded secrets or unaudited external network access (see `AGENTS.md` §5).

---

## 3. Architecture Overview

```
                        ┌──────────────────────────────────────────┐
                        │                 Human                     │
                        │  (approves gates, owns secrets, reviews)  │
                        └───────────────┬──────────────────────────┘
                                        │ approval gates (AGENTS.md §5.1)
                                        ▼
┌───────────────┐   plans/tasks   ┌──────────────────┐   validated tool calls
│   Planner /   │ ───────────────▶│   Orchestrator   │ ─────────────────────────┐
│   Reviewer    │◀─────────────── │  (agents/)       │                          │
└───────────────┘   findings      └────────┬─────────┘                          ▼
                                           │                              ┌─────────────┐
                          ┌────────────────┼──────────────────┐          │  MCP tools  │
                          ▼                ▼                  ▼          │  (mcp/)     │
                   ┌────────────┐   ┌────────────┐    ┌────────────┐     │ allow-listed│
                   │  Local LLM │   │    RAG     │    │ Detections │     └──────┬──────┘
                   │  (Ollama)  │   │  (rag/)    │    │(detections/)│            │
                   └────────────┘   └─────┬──────┘    └────────────┘            ▼
                                          │                              ┌─────────────┐
                                          ▼                              │  Filesystem │
                                   ┌────────────┐                        │  / lab data │
                                   │ Vector store│   ◀── trust boundary ─│  (data/)    │
                                   └────────────┘                        └─────────────┘
```

**Layers:**

- **Orchestration (`agents/`)** — role logic (planner/builder/reviewer/security), policy
  enforcement, and tool wiring. This is the control plane.
- **Capability surfaces (`mcp/`, `agents/tools/`)** — every tool validates its own input,
  enforces an allow-list, and is the *only* sanctioned way for an agent to reach the
  filesystem, network, or a model.
- **Knowledge (`rag/`)** — ingestion → chunking → embedding → retrieval over **trusted local
  corpora** only.
- **Inference** — local LLMs by default; any remote model is an explicit, gated decision.
- **Domain content (`detections/`)** — defensive, lab-scoped detection engineering.

---

## 4. Module Responsibilities

| Path | Responsibility | Key invariants |
|---|---|---|
| `agents/roles/` | Role definitions and their mandates | A role announces itself; honors its review priorities |
| `attack/` | Pinned local MITRE ATT&CK corpus (committed shards + pin) | Never fetched at runtime; zero first-party imports; integrity-verified fail-closed before parse; revocation surfaced, never rewritten |
| `intel/` | Local threat-intel library (first-party behavioral + synthetic atomic seed) | No live feed; TLP:CLEAR only; expiring, decaying, never-flag enforced at ingest and query; single-source network verdicts capped |
| `agents/tools/` | Adapters from agent intent → real capability | Each adapter validates input and enforces least privilege |
| `agents/policies/` | Guardrails, allow/deny lists, approval logic | Default deny; gates fail closed |
| `rag/` | Document ingestion and retrieval | Only trusted local sources; no PII/client data |
| `mcp/` | MCP servers exposed to agents | Minimal, typed, validated tool surface; sandboxed execution |
| `dashboard/` | Streamlit command center over the agent pipeline | Local-only backends; fails soft with honest degradation labels |
| `compliance/` | Control registry, framework mappings, evidence engine | Checks are read-only/offline and fail closed; evidence carries no secrets; manual controls surface as attestations, never silent passes |
| `knowledge-base/` | Local retrieval corpus (NIST/MITRE/OWASP notes) | Trusted local content only; grounds citations |
| `security/sbom/` | CycloneDX SBOMs + exported hash-pinned locks | Derived from `uv.lock`; CI drift gates verify, never auto-commit |
| `detections/` | Defensive detection content | Lab-scoped; no offensive payloads |
| `scripts/` | Operational CLI entrypoints | Idempotent; dry-run for destructive ops |
| `infra/` | IaC / containers / deploy manifests | No real secrets; deploy behind approval gate |
| `tests/security/` | Authz, validation, injection, secret-leak tests | Must pass before any boundary change merges |

---

## 5. Trust Boundaries & Data Flows

A **trust boundary** is any point where data or control crosses from a less-trusted zone to
a more-trusted one. Crossing one requires validation and (often) an approval gate.

1. **Human → Orchestrator** — the human is the root of trust; only the human owns secrets
   and approves gates.
2. **Orchestrator → Tools/MCP** — agent intent is *untrusted input*. Tools validate
   arguments, enforce allow-lists, and sandbox execution. Never pass LLM-generated strings
   to a shell, file path, or query without sanitization.
3. **External/LLM data → RAG/Logic** — model output and ingested documents are untrusted.
   Validate schemas; never deserialize untrusted data unsafely; guard against prompt
   injection influencing tool calls.
4. **System → Filesystem/Network** — filesystem reach is scoped to the project and lab
   `data/`; network egress is default-deny and limited to lab hosts. Any other egress is a
   gated action.

5. **External ATT&CK STIX bundle → local `attack/` store** — the upstream bundle is
   untrusted third-party data. A human stages it (no code egress, AGENTS.md §5.1);
   `scripts/update_attack.py --build` enforces a size ceiling and a nesting-depth scan,
   verifies the streaming SHA-256 against the committed pin, and only then parses with
   `RecursionError` handled explicitly. The pin is Ed25519-signable; `--check` verifies
   signature (when present), per-shard hashes, canonical rendering, and the
   revocation/successor invariants. A rejected bundle gets a `.REJECTED` forensic
   marker and an audit record; previously committed shards stay authoritative.
   Tampering hard-fails (`AttackIntegrityError`); absence degrades soft to an explicit
   `AttackUnavailableError` — never a guess.

6. **Third-party intel feed → `intel/` indicator store** — no live feed ships; committed
   content is first-party or synthetic only, and any future vendored snapshot lands in
   gitignored `data/intel/`. Whole-store fail-closed validation: unlisted `source_id` or
   non-allow-listed license rejects; TLP above CLEAR is refused at ingest (an intel hit's
   restricted datum IS the indicator value, and reports are tracked); every atomic
   indicator carries a mandatory expiry with per-type exponential decay; the explicit
   never-flag CIDR list (never `ipaddress.is_private`, which is wrong in both directions)
   is enforced at ingest AND query; network-observable indicators need two sources with
   distinct declared upstreams for a `malicious` verdict — one poisoned feed caps at
   `suspicious`. `as_of` is always injected (no module reads a clock); ATT&CK anchors on
   behavioral records degrade to `stale-anchor` on deprecation/revocation rather than
   letting an external taxonomy switch off a working local detection.

**Sensitive data** (logs, legal docs, client info, credentials, PII) never crosses outward
across these boundaries and is never committed.

---

## 6. Security Architecture

- **Least privilege** at every layer — tools request the minimum scope; processes run with
  the minimum permissions.
- **Defense in depth** — input validation *and* allow-lists *and* sandboxing *and*
  monitoring; no single point of trust.
- **Secure defaults** — safe behavior with zero flags; opting into risk is explicit and
  logged.
- **Auditability** — security-relevant actions emit structured logs suitable for review.
- **Secret management** — secrets live in environment/secret stores, documented as keys only
  in `.env.example`; never in source, tests, or logs.
- **Encryption** — in transit (TLS for any network call) and at rest for any sensitive
  store.
- **Fail closed** — on ambiguity, missing config, or failed validation, deny and halt rather
  than proceed.

---

## 7. Implementation Notes

- Python is the baseline, fully type-annotated and `mypy`-clean. Bash for glue; Swift only
  for macOS-specific targets.
- All configuration is environment-driven and documented in `.env.example`.
- Use the shared structured logger; never `print()` security events.
- New dependencies are pinned and justified (purpose, maintenance, license, risk) per
  `AGENTS.md` §4.
- Quality gates (`compileall`, `pytest`, `ruff`, `mypy`, `bandit`, plus SCA and secret
  scanning) run locally and in CI per `AGENTS.md` §7–§8.

---

## 8. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Prompt injection steering tool calls | Unauthorized action | Allow-listed tools, input validation, human gates |
| Secret leakage in code/logs | Credential compromise | Secret scanning in pre-commit + CI; `.env.example` only |
| Unsafe shell/exec from LLM output | RCE / data loss | Sanitize inputs; avoid shell where possible; sandbox |
| Dependency vulnerability | Supply-chain compromise | `pip-audit` SCA; pinned, justified deps |
| Scope creep into offensive tooling | Legal/ethical exposure | Lawful-lab boundary (§5); escalate ambiguous cases |
| Architectural drift | Erosion of trust boundaries | This doc is authoritative; reviewers enforce it |
| Poisoned/tampered ATT&CK corpus drives wrong mappings | Confidently incorrect SOC output | Boundary 5 control stack: size ceiling → depth scan → SHA-256 → parse; signable pin; stdlib `json` only; nothing executed |
| Silent ATT&CK staleness — dead techniques persist in content | Coverage claims drift from reality | Revoked/deprecated retained with successors; append-only tombstone ledger; merge-blocking reference gate in the Navigator builder; expiring MAN-03 attestation |
| Solo-maintainer decay of the "ongoing" corpus | Currency claim becomes false | Version-distance freshness (advisory, never a gate); expiring attestation flips to "attestation due"; refresh is one documented human command ~2×/year — and if it stops, the dashboard says so |
| Intel-feed poisoning causes analyst DoS or whitewashing | Alert flood, or attacker infrastructure branded clean | Never-flag denylist at ingest and query; two-source corroboration with declared upstream independence; per-type decay with hard expiry; no atomic indicator can authorize any action; no live feed at all |

---

## 9. Cost Considerations

Local-first and open-source by default keeps recurring cost near zero (compute is the
existing workstation/lab). Remote inference, paid APIs, or cloud infrastructure are
**explicit, gated decisions** with documented cost justification — never an unannounced
default.

---

## 10. Future Enhancements

- Formalize a policy-as-code layer in `agents/policies/` (e.g. OPA-style allow/deny).
- Add signed, tamper-evident audit logging with retention policy.
- Expand `tests/security/` with property-based fuzzing on tool input validators.
- Container-level sandboxing (rootless, seccomp/AppArmor) for MCP tool execution.
- Optional SBOM generation and dependency provenance attestation in CI.

---

## 11. Decision Log

| Date | Decision | Rationale |
|---|---|---|
| _initial_ | Local-first inference (Ollama) as default | Cost, privacy, no external dependency for core flows |
| _initial_ | Default-deny network egress | Minimize attack surface and data-exfil risk |
| _initial_ | Allow-listed, self-validating tool surfaces | Contain prompt-injection blast radius |
| _initial_ | `AGENTS.md` as platform-neutral charter | One rule set across Codex/Claude/other agents |
| 2026-06-17 | KnowledgeBaseAgent uses deterministic term-overlap retrieval, not the vector RAG pipeline | Incident-report grounding must be reproducible, network-free, and CI-testable. The vector pipeline (`rag/`) remains the path for semantic search via a local model; the two are complementary, not redundant. Both load the corpus through `rag.ingest` for shared path-traversal safety. |
| 2026-06-17 | Advisory agents (Legal/Compliance, Business Proposal, Knowledge Curator) are deterministic, network-free, and *draft-only* | These agents touch higher-stakes domains (legal, client-facing, knowledge-base content). Each classifies/structures input and returns a reviewable artifact, but never fabricates authority, invents pricing, or publishes/writes — humans own those actions (AGENTS.md §5.1). Each ships a mandatory disclaimer and a per-agent doc under `docs/agents/`. |
| 2026-06-17 | `OrchestratorAgent.process_log` takes a `report_path` parameter | Removes a hidden CWD dependency: the report destination is explicit, so tests write to a temp path instead of mutating the tracked sample report. |
| 2026-06-18 | KnowledgeBaseAgent gains an opt-in `semantic` mode with lexical fallback | Semantic (local-embedding cosine) retrieval improves relevance, but must not compromise the default. `lexical` stays the default — deterministic and CI-safe; `semantic` is opt-in and **falls back to lexical** if the loopback-only, fail-closed `OllamaEmbedder` is unreachable, so the agent pipeline never breaks. The embedder is injectable for deterministic tests. |
| 2026-06-19 | Policy/audit layer (`agents/policies/`) codifies §5/§5.1; MCP `ToolRegistry` enforces it | Approval gates and auditability were documentation only. The PolicyEngine (default-deny, fail-closed; §5 prohibitions non-negotiable) and a hash-chained AuditLogger make them executable. `ToolRegistry.dispatch` now gates every tool by its declared `action_class`: only `allow` runs, `require_approval`/`deny` fail closed, and decisions are auditable — making the control load-bearing at the capability surface, not just available. |
| 2026-06-20 | Opt-in local LLM generation (`agents/tools/llm.py`, default `qwen3.5:9b`) | Agents are deterministic by default; LLM use is opt-in so the core pipeline stays reproducible and network-free (CI uses an injected fake transport). `OllamaGenerator` mirrors `OllamaEmbedder`'s posture (loopback-only allow-list, bounded timeout, fail-closed). The incident report's "Analyst Narrative" is clearly labeled AI-generated, constrained to the supplied facts, and **fails soft** if the model is unreachable. Default model `qwen3.5:9b` (Apache-2.0); `LLM_MODEL` reconciled across `.env.example` and dashboard. |
| 2026-06-20 | LLM narrative on-by-default (`LLM_NARRATIVE=auto`) + pluggable backend (`LLM_BACKEND`) | A `Generator` protocol with two adapters — `OllamaGenerator` and `LlamaCppGenerator` (llama-server OpenAI-compatible `/v1`) — keeps the backend swappable; both enforce the same loopback/fail-closed posture. `resolve_generator()` reads env and returns a generator (auto/on) or `None` (off / invalid host → degrade to deterministic). The orchestrator enables it by default; tests force `LLM_NARRATIVE=off` (conftest) to stay hermetic. |

| 2026-07-24 | Compliance layer (`compliance/`) with dashboard tab and published trust page | Vanta-style continuous posture monitoring, self-hosted: a registry of deterministic, offline controls evaluates the repository's own security posture, maps results to NIST CSF 2.0 / SOC 2 / ISO 27001 (labeled *indicative* — not an audit), and records evidence to the gitignored `data/compliance/` through the existing hash-chained `AuditLogger` so history tampering is detectable. Properties that cannot be verified offline (branch protection, Pages approval gate) are explicit **manual attestation** controls — they hold framework coverage below 100% rather than silently passing. The public trust page follows the status-page pattern exactly: committed snapshot (`docs/trust.data.json`, schema with no field for check details, so internals cannot leak), deterministic renderer, `--check` drift gate in CI and pre-commit, publishing behind the human-gated Pages deploy. |

| 2026-07-24 | Attestations for manual controls are committed, expiring, and fail-closed | A manual control passes only via a reviewable entry in `compliance/attestations.json` (validated fail-closed; duplicates, bad dates, or extra fields reject the whole store). Attestations expire and revert the control to "attestation due" — no stale claim passes forever. Attested controls count in framework rollups but never in the automated posture score, and attestor names never reach the public trust page. Posture trend history derives purely from the recorded evidence trail. |

| 2026-08-21 | ATT&CK is a committed, pruned, pinned index (`attack/`) — never a fetched bundle, never a code ladder | The enterprise STIX bundle is ~54 MB against a ~6 MiB repo pack, so committing it is out and fetching at analysis time would violate default-deny egress and make the suite network-dependent. A human stages the versioned file in gitignored `data/attack/`; `scripts/update_attack.py --build` verifies size and SHA-256 against the pin *before* parsing, then distils sub-1 MB shards plus an append-only tombstone ledger. There is **no `--fetch` mode**: routing one through `guarded.enforce()` cannot express per-invocation human approval — the only paths to success (an allow-list label, `report_only=True`) are permanent unscoped downgrades of the control. CI does not have the bundle, so `--check` is an integrity/invariant gate, not regenerate-and-diff: pin signature (when present), per-shard hashes, canonical rendering, tombstone invariants, size ceilings. Freshness is *version distance* against a committed collection-index snapshot — advisory only, never an exit code (a time-dependent gate turns `main` red with no commit and invites bulk-extended expiry dates, which destroys the control). The pin is Ed25519-signable via `agents/policies/signing.py` from the gate script (never from `attack/`, which has zero first-party imports); a hash-only pin honestly claims corruption-detection, not tamper-detection. |
| 2026-08-21 | Revocation is surfaced, never silently rewritten — and a stale reference cannot merge | The index retains every technique the pinned bundle knows, including revoked and deprecated objects, so `lookup("T1064")` answers "deprecated, no replacement" instead of the indistinguishable-from-a-typo `None`. Revoked objects resolve successors through the `revoked-by` STIX relationship; deprecated objects carry no replacement pointer and the invariant check tolerates that asymmetry (it is MITRE's, not ours). The teeth: `scripts/build_attack_navigator.py` previously hard-coded `"attack": "16"` in a *published* artifact and validated tags by regex shape only (accepting `T9999` and every dead ID). It now reads the version from the pin and fails closed on any unresolvable, revoked, or deprecated Sigma tag — a rule pinned to a dead technique cannot merge. ATT&CK v19's restructures (Defense Evasion split into Stealth/Defense Impairment; detection prose moved from `x_mitre_detection` to detection-strategy/analytic objects) landed via the distiller with zero code assumptions broken — the validation of pinning the vocabulary instead of hard-coding it. |

| 2026-08-21 | Event-to-technique mapping moves from Python control flow into a reviewed data store under `agents/mapping/` | `MitreMapperAgent` becomes a thin facade over a committed, ordered ruleset; `map_event()` keeps its exact signature and legacy dict shape (additive keys: `techniques`, `matched_rules`, `attack_version`). The predicate language is literal-only by schema — no regex operator exists, so ReDoS over attacker-influenced log text is structurally impossible — with bounded rule/clause/value counts, validated fail-closed in the attestations style; every output string is a store- or corpus-declared constant, so log text can never transit into a result. The ruleset lives under `agents/mapping/` (not `detections/`) so the engine parsing untrusted text sits inside the bandit and coverage scopes by construction and a built wheel ships its rules (`detections` is absent from `packages.find.include`). Rules resolve against `attack/` at load: unknown → reject; revoked → reject naming the successor; deprecated → reject (operational content re-anchors deliberately); each rule declares its tactic, validated as a member of the technique's tactics, because techniques are multi-tactic and deriving would drift on version bumps. Integrity is a committed canonicalized digest (`rules.sha256`) verified by `scripts/check_mapping_rules.py --check` in CI and pre-commit — not per-event audit writes, which would give a pure function a clock and unbounded chain growth. Deliberate visible consequences of sourcing names from the pinned corpus: T1557 reads "Adversary-in-the-Middle" (the old compound label belonged to T1557.002) and T1070.003 sits under "Stealth" (v19 split Defense Evasion). |

| 2026-08-21 | Threat intelligence is first-party, behavioral, expiring, and synthetic where atomic (`intel/`) | The durable asset is a small, ATT&CK-anchored, fixture-backed behavioral library IANUA authors — no licensing exposure, no decay clock — plus a synthetic atomic seed built only from RFC 5737/3849/2606 values and clearly fabricated hashes, so lookup/decay/corroboration are exercisable from a clean clone without publishing accusations about real third-party infrastructure. No live feed ships: a useful atomic corpus needs an API key (§5.1 secret gate) and non-loopback egress (§5.1 network gate) to buy indicators stale within days. Aging differs in kind by Pyramid-of-Pain level: atomic indicators decay exponentially (per-type half-life; URL 14d → hash 365d) with a hard expiry; behavioral records age on a human review interval and on ATT&CK revisions — a deprecated/revoked anchor degrades the record to `stale-anchor`, never rejects it. `as_of` is injected everywhere (the store's newest retrieval date is the deterministic fallback); no module in `intel/` reads a clock or opens a socket, enforced by security tests. `ThreatIntelAgent` now classifies with stdlib `ipaddress` (explicit internal CIDRs, deliberately not `is_private`, which returns True for the RFC 5737 documentation ranges the seed occupies) and consults the library fail-soft. |

> Append new architectural decisions here (date, decision, rationale) so the history stays
> auditable.
