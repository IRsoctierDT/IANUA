# Changelog

All notable changes to this project. Versions correspond to git tags.

## v1.9.0 — Hardening #2: tamper-evident audit, sandboxed tools, verifiable RAG

**Milestone: the policy/audit layer is enforced at the tool surface, tool
execution is containerized, the supply chain is attested end-to-end, and RAG
answers carry verifiable citations.**

### Added — policy & audit
- **Policy engine + tamper-evident audit log** — default-deny action
  classification (AGENTS.md §5.1 approval gates codified), enforced at the MCP
  tool surface via a shared policy-guard primitive; declarative policy bundle
  loader with a staged report mode; the AGENTS.md §6 operating roles codified.
- **Audit-log hardening series**: tamper-evident rotation & retention;
  HMAC head-hash signing; asymmetric **Ed25519 signing** via a pluggable
  `Signer`; on-demand retention plus a scheduled maintenance CLI.

### Added — sandboxed tool execution
- **Rootless seccomp/AppArmor container sandbox** for MCP tool execution, with
  digest-pinned image guard and per-tool profiles.
- **Real-container CI enforcement job** (`Sandbox enforcement (Linux
  container)`) with non-vacuous tests.

### Added — RAG & reporting
- **Verifiable passage-level source-citation engine** — every retrieved claim
  cites the passage it came from.
- **Persistent SQLite vector store** (`rag/` now in the mypy gate).
- **Local-LLM narrative generation** (opt-in → on-by-default): Ollama and
  llama.cpp backends, **GBNF grammar-constrained** structured output.
- **PDF export** for incident reports (reportlab, pure-Python).
- Sigma **detection rules, correlations, and structural validation** wired into
  the SOC pipeline (detection coverage in reports).

### Added — supply chain & CI
- **CycloneDX SBOM** (Python + npm, merged, purl-complete) with vulnerability
  triage; **Sigstore-signed SBOM** and **SLSA build-provenance attestations**
  on every main build.
- **`uv.lock` as dependency source of truth**; hash-pinned dev toolchain
  installed under `--require-hashes` in CI; lock/SBOM **drift gate**
  (`sbom-sync`) fails closed.
- **Deterministic lock regeneration** (`scripts/refresh_locks.py`) — constrains
  resolution to `uv.lock`'s exact pins with PEP 508 marker evaluation.
- **Daily scheduled SCA scan** of the committed lock on main
  (`security-scan.yml`) so advisory decay is detected within a day.
- **Dependabot**: daily GitHub Actions cadence; grouped uv/npm updates;
  **auto-merge for low-risk groups only** (dev-toolchain, actions — patch/minor,
  gated on required status checks). Branch ruleset requires the 7 core CI
  checks before merge.
- **Property-based fuzzing** of tool input validators (`tests/security`).

### Added — site & docs
- **Command Center status page** (`scripts/build_status_page.py`) — a
  deterministic, offline generator that renders `docs/status.html` and
  `docs/status.json` from one committed source of truth (`docs/status.data.json`).
  Input is schema-validated and fails closed on unknown status tokens; every
  dynamic field is HTML-escaped as defense in depth (covered by
  `tests/security/test_status_page_escaping.py`). Linked from the site nav.
- **CI drift gate** (`status-page-sync`) — fails the build if the committed
  status page drifts from its source data, mirroring the SBOM/lock sync gates.
- **GitHub Pages landing site** with automated (human-approved) deploy;
  dashboard **Command Center UI** (Mission Control, Agent Roster, Activity
  Timeline); **nine component case studies** + hardening roadmap; local lab
  `docker-compose` stack.

### Fixed
- **GitHub Pages deploy deadlock** — the Pages deploy is split into isolated
  build/deploy jobs and now uses `cancel-in-progress: true`, so a run left
  `waiting` on the `github-pages` environment approval can no longer hold the
  concurrency slot and jam every later deploy. The required-reviewer approval
  gate is kept intentionally (human-in-the-loop for deploys, AGENTS.md §5.1);
  only the concurrency defect was fixed. Manual `workflow_dispatch` publishes
  are restricted to `refs/heads/main` so a run can't publish `docs/` from an
  untested branch.
- **Advisory clean-up**: pillow 12.3.0 (PYSEC-2026-2254/-2256/-2257),
  setuptools 83.0.0 (PYSEC-2026-3447), torch 2.13.0 (PYSEC-2025-194) — the
  committed closure audits to **0 known vulnerabilities** at release time.
- SBOM made attestable (CycloneDX `serialNumber`); CI restored on main after an
  invalid workflow file + `uv.lock` drift.

### Quality
- Test suite expanded to **390 passing** (4 environment-gated skips); ruff +
  mypy + bandit green across `agents`, `scripts`, `tests`, `dashboard`, `mcp`,
  and `rag`; coverage gate ≥85% enforced in CI.

## v1.8.0 — Agent suite complete

**Milestone: all eight agent blueprints from `03_Agent_Blueprints.md` are built.**

### Added
- **Knowledge Base Agent** — grounds incident reports in the curated cybersecurity
  corpus; deterministic term-overlap retrieval, wired into the orchestrator and the
  incident report ("Knowledge Base References" section).
- **Opt-in semantic retrieval** for the Knowledge Base Agent (`mode="semantic"`):
  local-embedding cosine ranking via the loopback-only, fail-closed `OllamaEmbedder`,
  with automatic fallback to lexical when Ollama is unreachable.
- **Vulnerability Assessment Agent** — ranks authorized scan findings into a
  remediation priority order (no scanning; unrated findings stay "unknown").
- **Legal/Compliance Research Agent** — triages a legal inquiry into a
  verify-don't-assert authority checklist (no advice, no fabricated citations).
- **Business Proposal Agent** — structures client needs into a reviewable
  proposal / SOW draft (drafts only, no invented pricing).
- **Knowledge Curator Agent** — organizes raw notes into retrieval-ready KB entries.
- **Portfolio Documentation Agent** — drafts READMEs/case studies in the AGENTS.md
  §9 structure.
- **Executive Assistant Agent** — prioritizes tasks/notes into a reviewable plan
  with blockers and a decision-log template.
- **SOC Analyst Agent v0.2 case study** (`docs/case-studies/`).
- Expanded, **source-cited** cybersecurity knowledge base (OWASP Top 10:2025,
  MITRE ATT&CK, NIST CSF 2.0, CIS Controls v8.1, Security+ SY0-701, SOC).

### Changed
- Dashboard SOC tab shows a severity metric and surfaces KB references; dashboard
  dependencies declared (`pip install -e ".[dashboard]"`) and added to the mypy gate.
- `OrchestratorAgent.process_log` takes an explicit `report_path` (test isolation).
- CI hardened: gitleaks `pull-requests: read`, CodeQL v4 + `actions: read`, all
  GitHub Actions bumped to Node 24-native versions; `SECURITY.md` refreshed.

### Quality
- Test suite expanded to **135 passing**, **~93% coverage**; ruff + mypy + bandit
  green across `agents`, `scripts`, `tests`, and `dashboard`.

## v1.7.0
- Fix dashboard health panel integration

## v1.6.0
- Add dashboard knowledge base search

## v1.5.0
- Add category-filtered knowledge base search

## v1.4.0
- Expand chunked ingestion across the full knowledge base

## v1.3.0
- Expand cybersecurity knowledge base sources

## v1.1.0
- Add dashboard documentation and screenshot checklist

## v1.0.0
- Add v1 usage guide and release notes

## v0.9.0
- Add batch log processing CLI

## v0.8.0
- Add CLI runner for incident workflow

## v0.7.0
- Add orchestrator agent

## v0.6.0
- Add PDF incident report generation

## v0.5.0
- Added Threat Intelligence Agent
- Added indicator classification
- Added threat intelligence test suite

## v0.4.0
- Added MITRE Mapper Agent
- Integrated MITRE ATT&CK mapping into incident reports

## v0.3.0
- Added Incident Report Agent

## v0.2.0
- Added chunked RAG pipeline

## v0.1.0
- Initial local AI stack
