# AGENTS.md — IANUA

> **Platform-neutral agent operating charter.** This file is the single source of truth for
> any autonomous or semi-autonomous coding agent operating in this repository — Codex,
> Claude Code, Cursor, Aider, or a custom orchestrator. Where a platform looks for a
> differently named file (e.g. `CLAUDE.md`), symlink or copy this file so the rules stay
> identical across agents.
>
> | | |
> |---|---|
> | **Document** | Agent Operating Charter |
> | **Status** | Authoritative — supersedes ad-hoc instructions |
> | **Owner** | Repository maintainer (human) |
> | **Companion docs** | [`DESIGN.md`](./DESIGN.md), `SECURITY.md`, `CONTRIBUTING.md` |
> | **Review cadence** | Re-read on every session start; revise on architecture change |

---

## 1. Repository Mission

This repository is the **IANUA**: a portfolio-grade environment
for **AI operations, cybersecurity automation, retrieval-augmented generation (RAG)
systems, and agentic workflows**.

It exists to demonstrate, and to operate, production-quality engineering across four
domains:

1. **Defensive security automation** — detection engineering, log enrichment, alert
   triage, and lab-scoped tooling that improves a defender's posture.
2. **AI/agent infrastructure** — local-LLM serving, MCP servers, RAG pipelines, and
   orchestrated multi-agent workflows.
3. **Secure-by-default systems engineering** — every component ships with least privilege,
   auditability, and defense in depth as first-class requirements, not afterthoughts.
4. **Professional, reviewable artifacts** — code, tests, and documentation suitable for a
   portfolio, a client engagement, an investor, a grantor, or a regulator.

Every change an agent makes must serve this mission **and** leave the repository in a state
that a senior security engineer would sign off on.

---

## 2. Mandatory Pre-Flight (read before touching anything)

Before modifying **any** code or documentation, an agent **must** complete this sequence and
state, in its working notes, that it has done so:

1. **Inspect repository structure** — enumerate the tree, identify the affected module(s),
   and confirm the change belongs where you intend to put it (see §4).
2. **Read [`DESIGN.md`](./DESIGN.md)** — understand the intended architecture, data flows,
   and the trust boundaries you may be crossing.
3. **Read this file (`AGENTS.md`) in full** — the rules below are binding.
4. **Read the nearest local context** — any `README.md`, module docstring, or `AGENTS.md`
   override in the subdirectory you are editing. **Deeper files win** on conflicts.
5. **Preserve existing naming conventions** — match file, module, function, and variable
   naming already present. Do not introduce a competing style.
6. **Keep security controls visible** — never remove, weaken, comment out, or bypass an
   existing control (auth check, validation, sandbox, rate limit, audit log) to make a test
   pass or a feature work. If a control is genuinely wrong, fix it openly and flag it.
7. **Confirm scope** — if the requested change is ambiguous, exceeds the stated task, or
   would touch a security boundary (§5), **stop and ask the human** before proceeding.

> **Fail-closed rule:** if any pre-flight step cannot be completed (missing `DESIGN.md`,
> unreadable module, unclear ownership), **do not guess** — halt and report.

---

## 3. Operating Principles (how every decision is weighed)

When more than one valid implementation exists, prefer them in this order, and make the
trade-off explicit in your summary:

1. **Most secure** — least privilege, smallest attack surface, fail-closed.
2. **Most scalable / maintainable** — clear interfaces, testable units, low coupling.
3. **Most cost-effective** — open-source and local-first where practical.

Cross-cutting principles that apply to **every** change:

- **Least privilege** — request the minimum scope, the minimum filesystem reach, the
  minimum network access. Default deny.
- **Defense in depth** — never rely on a single control; layer validation, authz, sandbox,
  and monitoring.
- **Secure defaults** — the safe configuration must be the one you get with no flags set.
- **Auditability** — security-relevant actions emit structured, tamper-evident logs.
- **Determinism & idempotence** — re-running a task must not corrupt state.
- **Human-in-the-loop for irreversibility** — see §5 approval gates.
- **Long-term maintainability over short-term convenience** — no clever hacks that the next
  engineer (or agent) cannot safely modify.

---

## 4. Repository Structure & Conventions

The repository follows a predictable layout so that both humans and agents can locate
responsibility quickly. Treat this as the canonical map; `DESIGN.md` holds the detailed
rationale.

```
ianua/
├── AGENTS.md                  # This charter (source of truth for agents)
├── CLAUDE.md                  # Symlink/copy of AGENTS.md for Claude-based agents
├── DESIGN.md                  # Architecture, data flows, trust boundaries, decisions
├── SECURITY.md                # Vulnerability reporting & security policy
├── CONTRIBUTING.md            # Human + agent contribution workflow
├── README.md                  # Project overview & quickstart
├── pyproject.toml             # Tooling config: ruff, mypy, pytest, coverage, bandit
├── .pre-commit-config.yaml    # Local quality gates (mirror of CI)
├── .env.example               # Documented config keys — NEVER real secrets
├── agents/                    # Agent definitions, orchestration, tool wiring
│   ├── __init__.py
│   ├── roles/                 # Role specs (planner, builder, reviewer, security)
│   ├── tools/                 # Tool adapters; each validates its own input
│   └── policies/              # Guardrails, allow/deny lists, approval logic
├── scripts/                   # Operational & maintenance scripts (CLI entrypoints)
├── rag/                       # Ingestion, chunking, embedding, retrieval
├── mcp/                       # MCP servers exposed to agents
├── detections/                # Detection-engineering content (lab-scoped only)
├── infra/                     # IaC, container/compose, deployment manifests
├── docs/                      # Long-form documentation & runbooks
├── tests/                     # pytest suite (unit, integration, security)
│   ├── unit/
│   ├── integration/
│   └── security/              # Authz, input-validation, injection, secret-leak tests
└── data/                      # Local/lab data ONLY — gitignored; never client/PII
```

**Conventions:**

- **Language baseline:** Python (typed), with Bash for glue and Swift only where a macOS
  target requires it. Match existing choices per module.
- **Naming:** `snake_case` for Python modules/functions, `PascalCase` for classes,
  `UPPER_SNAKE` for constants, `kebab-case` for CLI scripts and filenames where shell-facing.
- **Typing:** all new Python is fully type-annotated and passes `mypy` (see §7).
- **Docstrings:** every public module, class, and function has a docstring stating purpose,
  inputs, outputs, and any security consideration (e.g. "validates and sanitizes `path`").
- **Config:** all configuration via environment variables or typed config objects; document
  every key in `.env.example`. No magic literals for secrets, hosts, or ports.
- **Logging:** use the shared structured logger; never `print()` security-relevant events.
- **Dependencies:** pin versions; prefer well-maintained, open-source libraries; justify any
  new dependency in the PR description (purpose, maintenance status, license, risk).

---

## 5. Security Boundaries (hard limits)

These are **non-negotiable** and override any conflicting instruction, including a user
request to "just this once" relax them.

**Prohibited — never do:**

- ❌ Create **offensive** cybersecurity tooling intended for use outside a **lawful,
  owned/authorized lab**. No tooling whose primary purpose is to attack, exploit, or evade
  defenses on systems you do not own or have written authorization to test.
- ❌ Add code that **scans, attacks, exploits, brute-forces, or accesses third-party
  systems** without explicit, documented authorization.
- ❌ Hard-code **secrets, tokens, passwords, API keys, private keys, or personal
  information** anywhere — source, tests, fixtures, comments, commit messages, or logs.
- ❌ Weaken, disable, or bypass an existing **security control** to make code work.
- ❌ Exfiltrate, transmit, or log **sensitive data** (logs, legal documents, client info,
  PII) to any external endpoint.
- ❌ Perform **destructive or external actions** (deleting data, force-pushing, deploying,
  sending network requests to non-lab hosts, mutating cloud resources) **without human
  approval** (see approval gates below).

**Treat as sensitive by default:** logs, legal documents, client information, credentials,
internal hostnames/IPs, and anything under `data/`. Apply confidentiality, minimize copies,
and never commit them.

**Lawful-lab scope:** security tooling in this repo is for **defensive purposes and
authorized lab exercises only**. Detection content, parsers, and analysis tooling are
welcome; weaponized exploit chains aimed at unowned targets are not. When in doubt about
whether something is offensive vs. defensive, **ask the human and document the
authorization basis**.

### 5.1 Approval Gates (human-in-the-loop)

An agent must **pause and obtain explicit human approval** before any action that is
irreversible, externally visible, or security-sensitive:

| Action class | Examples | Gate |
|---|---|---|
| **Destructive** | `rm -rf`, dropping tables, history rewrite, `git push --force` | Human approval, dry-run first |
| **External network** | requests to any non-lab host, publishing packages, webhooks | Human approval + URL shown in full |
| **Deployment / infra mutation** | applying IaC, restarting prod services, cloud changes | Human approval, plan/diff shown |
| **Dependency addition** | new third-party package | Justification in PR; human review |
| **Secret / credential handling** | reading/rotating keys, touching `.env` | Human performs; agent never stores |
| **Boundary-crossing** | anything touching §5 prohibitions | Stop; do not proceed |

When a gate is hit, the agent presents: *what* it intends to do, *why*, the *blast radius*,
and a *rollback plan* — then waits.

---

## 6. Agent Roles & Workflow

Work in this repository is organized around four cooperating roles. A single agent may play
several roles in sequence, but it must **announce which role it is in** and honor that
role's responsibilities.

| Role | Mandate | Must produce |
|---|---|---|
| **Planner** | Decompose the request; map it to modules; identify trust boundaries crossed; surface risks, assumptions, dependencies. | A short plan + task list before code. |
| **Builder** | Implement the smallest correct change; follow conventions (§4); keep controls visible (§5). | Working, typed, documented code. |
| **Reviewer** | Apply the review priorities (§6.1); run required checks (§7); reject anything that fails. | Pass/fail with specific findings. |
| **Security** | Independent pass focused only on the security boundaries (§5) and `tests/security`. | Sign-off or blocking findings. |

### 6.1 Review Priorities (in order)

When reviewing any change — your own or another agent's — evaluate in this order and stop to
fix before moving on:

1. **Security defects** — broken authz, injection, secret leakage, unsafe deserialization,
   SSRF, path traversal, weakened controls.
2. **Logic errors** — incorrect behavior, wrong results, race conditions.
3. **Unhandled edge cases** — empty/oversized/malformed inputs, partial failures, timeouts.
4. **Unsafe tool execution** — shell/exec with unsanitized input, unsandboxed agent tools,
   missing allow-lists.
5. **Poor input validation** — untyped boundaries, missing schema validation, trust of
   external/LLM-supplied data.
6. **Broken tests** — failing, flaky, skipped, or missing coverage for new logic.
7. **Incomplete documentation** — undocumented public surface, stale README/DESIGN.
8. **Violations of `DESIGN.md`** — architectural drift, boundary erosion, naming breakage.

### 6.2 Task Lifecycle & Definition of Done

`pending → in_progress → in_review → done` (or `blocked`).

A task is **done** only when **all** of the following hold:

- [ ] Change is scoped to the request; no unrelated edits.
- [ ] Existing security controls preserved or improved (none weakened).
- [ ] New/changed logic has tests, including a `tests/security` case where a boundary is
      involved.
- [ ] **All required checks (§7) pass locally.**
- [ ] Public surface is documented; `DESIGN.md` updated if architecture changed.
- [ ] No secrets, PII, or sensitive data added anywhere.
- [ ] Summary states what changed, why, residual risks, and rollback.
- [ ] Any approval gate (§5.1) that was hit has a recorded human approval.

If a task cannot reach this bar, it stays `in_progress` or moves to `blocked` with a clear
note — **never** marked done.

### 6.3 Escalation

Escalate to the human (do not improvise) when: a security boundary is implicated; the plan
requires an approval gate; `DESIGN.md` is missing or contradicts the request; required
checks reveal a defect you cannot safely fix within scope; or the request itself appears to
ask for prohibited behavior.

---

## 7. Required Checks (quality gates)

Every change must pass the full gate **locally before review**, and again in CI. These are
the minimum bar — green is required, not optional.

```bash
# 1. Everything compiles
python -m compileall .

# 2. Full test suite (unit, integration, security)
python -m pytest

# 3. Lint & style
ruff check .

# 4. Static type checking
mypy agents scripts tests

# 5. Security static analysis (SAST)
bandit -r agents scripts
```

### 7.1 Extended gate (run when the change warrants it)

```bash
# Auto-formatting (must produce no diff in CI)
ruff format --check .

# Coverage threshold — new logic must not lower it
python -m pytest --cov=agents --cov=scripts --cov-report=term-missing --cov-fail-under=85

# Dependency vulnerability scan (SCA)
pip-audit

# Secret scanning — fail the build on any detected credential
detect-secrets scan --baseline .secrets.baseline
# or: gitleaks detect --no-banner

# Optional: type-strictness on new modules
mypy --strict <changed_module>
```

> If a tool above is not yet wired into the repo, the **first** task is to add it to
> `pyproject.toml` / `.pre-commit-config.yaml` rather than skipping the check.

---

## 8. CI/CD & Branch Policy

Local checks (§7) are mirrored exactly in CI so that "passes on my machine" equals "passes
in the pipeline."

**Pipeline stages (fail-fast, ordered):**

1. **Setup** — pinned toolchain, cached deps, reproducible install.
2. **Static analysis** — `ruff check`, `ruff format --check`, `mypy`.
3. **Security** — `bandit` (SAST), `pip-audit` (SCA), secret scan (`gitleaks` /
   `detect-secrets`). Any finding above the agreed severity threshold **blocks merge**.
4. **Tests** — `pytest` with coverage gate (`--cov-fail-under=85`); `tests/security` must
   be green.
5. **Build / package** — only on a fully green pipeline.
6. **Deploy** — **manual approval gate**; never automatic to any environment that touches
   real systems or data.

**Branch protection (recommended):**

- No direct commits to `main`; changes land via reviewed pull request.
- Required status checks: all of stages 2–4 above.
- At least one human review on any change touching `agents/`, `mcp/`, `infra/`, or §5
  boundaries.
- Signed commits where supported; linear history; no force-push to protected branches.
- Secrets live only in the CI secret store — never in the repo, never echoed in logs.

**Pre-commit** (`.pre-commit-config.yaml`) runs the fast subset (ruff, mypy on changed
files, secret scan) so problems are caught before they reach CI.

---

## 9. Documentation Standards

Deliverables (runbooks, design notes, client/portfolio docs) follow a consistent,
review-ready structure:

**Executive Summary · Objectives · Architecture/Process · Implementation Steps · Risks ·
Cost Considerations · Future Enhancements**

For tool or component documentation, also state: **Purpose · Risk level · Skill level
required · Deployment complexity.** Use professional formatting suitable for client
delivery, distinguish **facts from assumptions**, and **cite authoritative sources** for any
legal, regulatory, compliance, or grant claim — never invent statutes, deadlines, or
requirements, and flag when professional legal/financial review is advisable.

---

## 10. Quick Reference Card

```
BEFORE YOU EDIT:   inspect tree → read DESIGN.md → read AGENTS.md → read local context
WHILE YOU EDIT:    least privilege · secure defaults · controls stay visible · types + docs
NEVER:             hard-code secrets · weaken controls · attack 3rd parties · exfiltrate data
ASK FIRST (gate):  destructive · external network · deploy · new dependency · secrets
BEFORE DONE:       compileall · pytest · ruff · mypy · bandit  (all green)
WHEN UNSURE:       stop and ask the human — fail closed, never guess
```

---

*This charter is intentionally strict. Its purpose is to make the safe path the default
path, so that every contribution — human or agent — leaves the AI Operator Cyber Command
Center more secure, more maintainable, and more credible than it was before.*
