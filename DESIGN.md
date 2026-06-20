# DESIGN.md — AI Operator Cyber Command Center

> Architecture, trust boundaries, and decision record for this repository.
> Read this **before** any change (see [`AGENTS.md`](./AGENTS.md) §2). Update it whenever the
> architecture, a trust boundary, or a major dependency changes.

---

## 1. Executive Summary

The AI Operator Cyber Command Center is a **local-first, security-hardened platform** for
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
| `agents/tools/` | Adapters from agent intent → real capability | Each adapter validates input and enforces least privilege |
| `agents/policies/` | Guardrails, allow/deny lists, approval logic | Default deny; gates fail closed |
| `rag/` | Document ingestion and retrieval | Only trusted local sources; no PII/client data |
| `mcp/` | MCP servers exposed to agents | Minimal, typed, validated tool surface |
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

> Append new architectural decisions here (date, decision, rationale) so the history stays
> auditable.
