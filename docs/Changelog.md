# Changelog

All notable changes to this project. Versions correspond to git tags.

## Unreleased

_Nothing yet._

## v2.0.0 — Master v2 STICHES Edition: the IANUA identity era

**Milestone: the platform is IANUA everywhere (repo, docs, Pages, dashboard,
SBOM), the SOC pipeline correlates sequences end-to-end from agents through
reports to the dashboard, retrieval is rarity-weighted with verified passage
citations, audit verification produces located forensics, and the whole
platform is testable from a browser in one click. Edition identity advances
to Master v2 STICHES; every agent reports v2.0.0 automatically via the
pyproject-derived version.**

### Changed — foundations refreshed for v2
- **Charter (`AGENTS.md`) brought current** — the §4 layout tree now maps the
  real repository (dashboard, knowledge-base, security/sbom, devcontainer,
  portfolio, sample-logs…); §7 gate commands match CI's exact scopes
  (`mypy agents scripts tests dashboard mcp rag`,
  `bandit -c pyproject.toml -r agents scripts mcp`, plus the drift-gate
  checks); §8 documents the pipeline as it exists (CodeQL, dual-Python tests,
  sandbox enforcement, read-only drift gates, and the **human-gated Pages
  deploy, kept by design**). `CLAUDE.md` follows via symlink.
- **Security policy consolidated and updated for v2** — root `SECURITY.md` is
  the canonical policy (supported versions 2.0.x; components-in-scope table
  covering the policy/audit layer, sandbox, dashboard, detections, and
  verification CLIs; the full current control set: SAST+CodeQL, SCA+SBOM
  drift gates, secret scanning, tamper-evident audit with signing, sandboxed
  tool execution, least-privilege CI, human-gated deploys).
  `.github/SECURITY.md` is now a pointer with the private-reporting
  essentials, so the two copies can never diverge again.
- **`DESIGN.md` module map completed** — dashboard, knowledge-base, and
  security/sbom rows added with their invariants.

### Security
- **gitpython bumped 3.1.50 → 3.1.54** (transitive, via streamlit) — clears
  GHSA-2f96-g7mh-g2hx, GHSA-v396-v7q4-x2qj and GHSA-956x-8gvw-wg5v (all fixed
  in 3.1.51), which were failing the CI `pip-audit` SCA gate. `uv.lock` is the
  source of truth; derived pip locks, `python.cdx.json` and the merged SBOM
  were regenerated (`pip-audit` now reports no known vulnerabilities; lock and
  SBOM drift gates verified in sync).

### Added
- **One-click interactive test environment (GitHub Codespaces)** — new
  `.devcontainer/devcontainer.json`: from the repository page (Code →
  Codespaces → Create) the container installs `.[dev,dashboard]`, auto-starts
  the Streamlit dashboard, and forwards port 8501 (private to the owner), so
  every feature is testable in the browser with zero local setup. GitHub Pages
  is static and cannot run the app; this is the supported "test it from
  github.com" path (documented in the README Quickstart).
- **Bundled sample scenarios in the Batch tab** — a fixed allow-list of
  deterministic fixtures from `sample-logs/` (SSH brute force,
  failures-then-success) loadable without preparing an upload, so sequence
  correlation, verified citations, and the incident report are one click away.
- **Knowledge-base search fails soft** — `search_kb_resilient()` tries the
  Qdrant semantic backend and degrades to the offline lexical
  `KnowledgeBaseAgent` corpus when Qdrant/embeddings are unavailable, with the
  serving backend labelled in the UI (degraded results are never passed off as
  the primary path). Heavy imports are now lazy, so the dashboard starts on a
  minimal install. Covered by `tests/unit/test_kb_search.py`.

### Changed
- **Dashboard batch flow upgraded to the correlated sequence pipeline** — the
  Streamlit "Batch Processing" tab now runs `OrchestratorAgent.process_sequence`
  once over the uploaded log (one deterministic pipeline run) instead of N
  independent per-line `process_log` calls that could not see multi-event
  patterns. The tab surfaces the sequence verdict (severity, score, event
  count, summary), the **Correlated Findings** (pattern, source, severity,
  contributing event numbers), a per-event breakdown table (now including the
  extracted source), sequence-wide threat intelligence, the **verified cited
  passages** with char offsets, and the generated sequence incident report.
  Empty uploads get a friendly warning instead of the pipeline's fail-closed
  exception surfacing as a traceback.

### Fixed
- **IANUA rename completed; rename tooling repaired** — `scripts/rename_to_ianua.py`
  no longer rewrites or scans its own source (its `REPLACEMENTS` table contains
  the legacy identifiers by design, so `--apply` used to collapse the table to
  identity mappings and `--check` then flagged every occurrence of the *new*
  name — the workflow could never pass). The script now excludes itself and
  local cache directories (`.mypy_cache`, `.pytest_cache`, `.ruff_cache`,
  `__pycache__`, `htmlcov`), and is `ruff format`-clean (the unformatted file
  was failing CI static analysis for every PR). The remaining legacy
  pre-IANUA project identifiers across docs, detection content, dashboard, scripts, the status
  page, and SBOM metadata were migrated with the fixed script (deterministic,
  idempotent; `--check` is clean and drift gates — status page, SBOM, locks —
  stay green).
- **Canonical repository identity across the Pages site and dashboard** —
  the GitHub Pages landing (`docs/index.html`) now links to the renamed
  repository with its canonical casing (`github.com/IRsoctierDT/IANUA`,
  including the clone/`cd` quick-start snippet); two identity strings that the
  line-based migration missed because they were **wrapped across lines**
  (`detections/README.md`, the AGENTS.md closing charter) are fixed by hand;
  the status page tagline and the Streamlit dashboard caption now describe the
  IANUA platform (SENTINEL remains the landing page's design wordmark only).
  Status page regenerated in sync.
- **Rename workflow converted to a least-privilege guard** — the
  `Complete IANUA rename` workflow no longer checks out a fixed side branch
  with `contents: write` and auto-pushes; it now runs a read-only
  `rename_to_ianua.py --check` against the ref under test on every PR (same
  check name, so branch protection is unaffected), failing only if a legacy
  identifier is reintroduced.

### Added
- **Deepened audit-verification tooling** — `AuditLogger.verify_report()`
  returns a structured diagnosis instead of a bare bool: entry/segment counts,
  chain head, checkpoint anchor, granular head-signature status
  (`valid`/`invalid`/`stale`/`missing`/`malformed`/`unsigned`/`empty`), and —
  on failure — the first broken segment, line, and kind of break. Malformed or
  corrupted entries are now a located fail-closed *verdict* (previously the
  verifier raised on garbage lines). `verify()` is unchanged in behaviour (thin
  wrapper). New standalone `scripts/audit_verify.py` CLI: read-only chain +
  signature verification for cron/CI/auditors, auto-detecting `AUDIT_HMAC_KEY`
  or the Ed25519 **public-key-only** `AUDIT_ED25519_PUBLIC_KEY` scheme, with
  `--require-signature` to refuse chain-only verification (exit codes 0/2/3).
- **Report enrichment: sequence findings + verified passage citations** —
  incident reports gain a "Sequence Correlation" section (multi-event findings
  from `SocAnalystAgent.analyze_sequence`: pattern, source, severity,
  contributing events) and a "Cited Passages" section quoting the exact
  grounding passages with char-offset locators — labelled "(verified)" only
  when the caller attests that `verify_citations` passed
  (`citations_verified=True`; the report agent never mislabels unchecked
  citations). The orchestrator now
  attaches passage-level citations to `process_log` **only after they pass the
  anti-hallucination check** (`verify_citations`; unverifiable citations are
  dropped, fail-closed), and gains `process_sequence(events)` — the full
  pipeline over an ordered batch: sequence correlation, standard sections
  anchored on the most severe event, threat intel over the sequence-wide
  indicator union. PDF export inherits both sections automatically.

### Changed
- **RAG retrieval precision: rarity-weighted (IDF) lexical scoring** — the
  Knowledge Base Agent's lexical mode and the citation engine's passage
  selection now weight query terms by corpus/document rarity
  (`log1p(N/(1+df))`) instead of counting every term equally. Discriminative
  terms ("kerberoasting") outrank ubiquitous ones ("security") rather than
  tying and falling back to alphabetical/document order. Deterministic,
  dependency-free, same [0, 1] semantics (all-terms match still scores 1.0;
  uniform rarity reduces exactly to the previous fraction). Applies to
  `retrieve()`, `cite()`, and `best_passage()`.

### Added
- **Detection content: five new Sigma rules** (`detections/sigma/`) covering
  gaps in the agent vocabulary — `firewall_block` (base) +
  `firewall_block_burst` (≥20 blocks/source/5m — port-scan correlation, the
  SOC agent's `firewall block` event type finally has content),
  `linux_account_added_to_privileged_group` (T1098) +
  `account_created_then_privileged` (create-then-privilege chain correlation,
  critical), and `linux_command_history_cleared` (T1070.003 defense evasion).
  The existing account-creation rule gained a `name:` so chains can reference
  it. All structurally validated by `tests/test_detections.py`; the Detection
  Matcher Agent picks them up automatically via ATT&CK tags.
- **SOC Analyst Agent: multi-event sequence correlation**
  (`SocAnalystAgent.analyze_sequence`) — correlates an ordered batch of log
  events into findings a single-line analysis cannot see: **brute force**
  (≥3 authentication failures from one source; `critical` when a privileged
  account is targeted) and **possible credential compromise** (failure
  followed by a successful login from the same source; always `critical`).
  Deterministic, fail-closed input validation, no network activity —
  an enhancement of the existing agent, no new surface. Duplicated
  privileged-account logic consolidated into one helper.

### Changed
- **Agent versions now track the platform automatically** — `agents.__version__`
  resolves from `pyproject.toml` (the release source of truth; falls back to
  installed package metadata, then a conspicuous `0.0.0` sentinel), and every
  named agent derives its display name via `agents.versioned_agent_name()`.
  The SOC Analyst Agent — stuck announcing `v0.2` since the platform hit
  `v1.9.0` — and all six other named agents now report
  `"<Agent> v<platform version>"` and update on every release without manual
  edits. A drift-gate test (`tests/unit/test_agent_versioning.py`) fails the
  build if any agent hard-codes a version again.

### Fixed
- **GitHub Pages deploy failing with "No artifacts named github-pages were
  found"** — the split build/deploy design uploaded the site artifact in the
  build job, then the deploy job waited on the `github-pages` required-reviewer
  gate. When approval came later than the Pages artifact's ~1-day retention, the
  artifact had expired and the deploy failed. Combined build + deploy into a
  single environment-gated job so approval holds the whole job and, once
  approved, the artifact is built, uploaded, and deployed fresh in one shot. The
  human approval gate is unchanged; only the structure that made an approved
  deploy fail was fixed.

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
