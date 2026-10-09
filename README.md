# IANUA

A **portfolio-grade, local-first command center** for AI operations, cybersecurity
automation, RAG knowledge systems, and agentic workflows — built secure-by-default
(least privilege, auditability, defense-in-depth, human-in-the-loop for every
irreversible action).

Every component is designed to demonstrate repeatable, documented, testable, and
reviewable engineering — suitable for a portfolio, a client engagement, or a production
security operation.

<!-- BEGIN GENERATED: release -->
**Current release: v2.1.0** — see [`docs/Changelog.md`](./docs/Changelog.md).
<!-- END GENERATED: release -->

---

## What's built

| Component | Layer | Status |
|---|---|---|
| **SOC Analyst Agent v0.2** — JSON/text log triage, severity scoring (0-100), evidence table, MITRE mapping, incident report ([case study](./docs/case-studies/soc-analyst-v0.2.md)) | Agent | Complete |
| **Incident Report Agent** — Markdown incident reports from structured SOC + MITRE output | Agent | Complete |
| **MITRE Mapper Agent** — data-driven ATT&CK mapping over the pinned local corpus: reviewed ruleset, multi-technique attribution, revocation-gated | Agent | Complete |
| **Threat Intel Agent** — indicator triage over the local intel library: decayed confidence, provenance, two-source corroboration, never-flag policy | Agent | Complete |
| **Vulnerability Assessment Agent** — ranks authorized scan findings into a remediation priority order ([doc](./docs/agents/VULNERABILITY_ASSESSMENT_AGENT.md)) | Agent | Complete |
| **Knowledge Base Agent** — grounds incident reports in the cited cybersecurity corpus | Agent | Complete |
| **Business Proposal Agent** — structures client needs into a reviewable proposal / SOW draft ([doc](./docs/agents/BUSINESS_PROPOSAL_AGENT.md)) | Agent | Complete |
| **Legal/Compliance Research Agent** — triages a legal inquiry into a verify-don't-assert authority checklist ([doc](./docs/agents/LEGAL_COMPLIANCE_AGENT.md)) | Agent | Complete |
| **Knowledge Curator Agent** — organizes raw notes into retrieval-ready KB entries ([doc](./docs/agents/KNOWLEDGE_CURATOR_AGENT.md)) | Agent | Complete |
| **Portfolio Documentation Agent** — drafts GitHub-ready READMEs/case studies (AGENTS.md §9 structure) ([doc](./docs/agents/PORTFOLIO_DOCUMENTATION_AGENT.md)) | Agent | Complete |
| **Executive Assistant Agent** — prioritizes tasks/notes into a reviewable plan with blockers & decision log ([doc](./docs/agents/EXECUTIVE_ASSISTANT_AGENT.md)) | Agent | Complete |
| **Orchestrator Agent** — Multi-agent workflow coordination | Agent | Complete |
| **ATT&CK Corpus (`attack/`)** — version-pinned local MITRE ATT&CK 19.x: hash-verified shards, tombstoned revocations, merge-blocking reference gates ([plan](./docs/DETECTION_INTELLIGENCE_PLAN.md)) | Data | Complete |
| **Threat-Intel Library (`intel/`)** — first-party behavioral records (ATT&CK-anchored, review-aged) + synthetic atomic seed with per-type decay | Data | Complete |
| **Behavioral Detections (`detections/behaviors/`)** — post-compromise TTP corpus, reference-gated against the pinned corpus, each rule declaring whether its telemetry is ingested | Detection | Complete |
| **Response Layer (`agents/response/`)** — draft containment plans with per-action rollback and human owners; **no executor exists** and security tests prove it ([doc](./docs/RESPONSE_LAYER.md)) | Agent | Complete |
| **RAG Pipeline** — Local document ingestion → chunking → Ollama embeddings → in-memory retrieval | RAG | Complete |
| **MCP Server** — Model context protocol server (stdio JSON-RPC) with allow-listed, validated tools | MCP | Complete |
| **Governance system** — `AGENTS.md` operating charter, CI/CD with bandit + gitleaks + pip-audit + mypy, least-privilege job permissions | Governance | Active |
| **Dashboard** — Streamlit command center: SOC workflow (severity + KB grounding), batch processing, **Detection Intelligence** (corpus health, intel freshness, behavioral telemetry split, maintenance debt), KB search, system health, reports | Dashboard | Complete |

**Every agent in the table above is built.** Further work is enhancement, not new surface.

### Case studies

<!-- BEGIN GENERATED: case-studies -->
Eleven portfolio-grade write-ups — one per component — each following the [AGENTS.md](./AGENTS.md)
§9 standard with a worked example (real command output) and a reproduce-it-yourself section.
Full index: [`docs/case-studies/`](./docs/case-studies/README.md).

| Case study | Layer |
|---|---|
| [SOC Analyst Agent v0.2](./docs/case-studies/soc-analyst-v0.2.md) — Raw log line → triaged, scored, MITRE-mapped, human-reviewable incident | Agent |
| [MITRE ATT&CK Mapper Agent](./docs/case-studies/mitre-mapper-agent.md) — Deterministic event → ATT&CK tactic/technique with confidence & evidence | Agent |
| [Threat Intelligence Agent](./docs/case-studies/threat-intel-agent.md) — Indicator triage that returns `unknown` + "enrich first" instead of guessing | Agent |
| [Vulnerability Assessment Agent](./docs/case-studies/vulnerability-assessment-agent.md) — Ranks authorized scan findings into a defensible remediation order | Agent |
| [Knowledge Base Agent](./docs/case-studies/knowledge-base-agent.md) — Cited corpus grounding; deterministic lexical default, safe semantic fallback | Agent/RAG |
| [Incident Report Agent](./docs/case-studies/incident-report-agent.md) — Composes a safe Markdown report; opt-in, fail-soft AI narrative | Agent |
| [Detection Matcher & Orchestrator](./docs/case-studies/detection-matcher-and-orchestrator.md) — Triage→Sigma detection loop + full multi-agent pipeline in one call | Agent |
| [Local RAG Pipeline](./docs/case-studies/rag-pipeline.md) — Confined ingest → chunk → embed → cited retrieval; fully offline mode | RAG |
| [Policy-Gated MCP Tool Surface](./docs/case-studies/mcp-server.md) — Allow-listed, self-validating, path-confined, policy-gated tool calls | MCP |
| [Policy Engine & Tamper-Evident Audit Log](./docs/case-studies/policy-and-audit.md) — Default-deny policy-as-code + hash-chained, verifiable audit trail | Governance |
| [Agent Trust Broker Gate](./docs/case-studies/agent-trust-broker-gate.md) — Zero-Trust caller identity + per-action scope authorization layered on tool dispatch | MCP/Governance |
<!-- END GENERATED: case-studies -->

---

## Architecture

Ten-layer command-center model (see [`DESIGN.md`](./DESIGN.md) for full trust boundaries and decision log):

```
Human (approves gates, owns secrets)
    │
    ▼
Orchestrator (agents/)
    ├── Local LLM (Ollama, loopback-only)
    ├── RAG pipeline (rag/) ──► Vector store
    ├── MCP tools (mcp/) ──────► Filesystem / lab data
    └── Detections (detections/)
```

**Architecture rule:** agents recommend, draft, classify, summarize, and structure.
Humans approve destructive, external, legal, financial, or security-sensitive actions.

---

## Governance

| Doc | Purpose |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Operating charter for any coding agent (also `CLAUDE.md`) |
| [`DESIGN.md`](./DESIGN.md) | Architecture, trust boundaries, decision log |
| [`SECURITY.md`](./SECURITY.md) | Vulnerability reporting & security policy |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Human + agent contribution workflow |
| [`docs/HARDENING_ROADMAP.md`](./docs/HARDENING_ROADMAP.md) | Planned defense-in-depth hardening workstreams |
| [`LICENSE`](./LICENSE) | Apache License 2.0 — the terms this work is offered under |
| [`NOTICE`](./NOTICE) | Attributions, content provenance, trademark reservations |
| [`docs/IP_AND_LICENSING.md`](./docs/IP_AND_LICENSING.md) | Why Apache-2.0, copyright/entity/trademark/patent posture |

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pre-commit install --hook-type pre-push
detect-secrets scan > .secrets.baseline   # one-time, then review & commit
```

**Run the SOC Analyst Agent:**
```bash
python agents/soc_analyst_agent.py
# or pass structured JSON:
python -c "
from agents.soc_analyst_agent import SocAnalystAgent
import json, pprint
result = SocAnalystAgent().analyze_log({
    'timestamp': '2025-06-15T14:00:00Z',
    'host': 'web-01',
    'user': 'root',
    'src_ip': '10.0.0.5',
    'message': 'Accepted password for root from 10.0.0.5 port 22'
})
pprint.pprint(result)
"
```

**One-command RAG pipeline (ingest → embed → query):**
```bash
# Local Ollama embeddings:
python -m scripts.rag_cli --corpus ./corpus --query "zero trust segmentation" --k 3
# Fully offline / no Ollama (deterministic embedder — good for CI/air-gapped labs):
python -m scripts.rag_cli --corpus ./corpus --query "ids tuning" --offline
```

**Run the MCP server (stdio):**
```bash
MCP_ROOT=./data python -m mcp.transport
# Speaks line-delimited JSON-RPC 2.0; methods: initialize | tools/list | tools/call
```

**Run the dashboard (Streamlit command center):**
```bash
pip install -e ".[dashboard]"     # streamlit + qdrant-client + sentence-transformers
streamlit run dashboard/app.py
# Tabs include SOC Workflow · Batch Processing · Scan Reports · Knowledge Base Search · Reports
# KB search and health panels degrade gracefully if Qdrant/Ollama aren't running.
```

The **Scan Reports** tab imports redacted IANUA-Broker JSON reports for filtered
finding review and before/after comparison. Uploaded snapshots stay in the
session; the feature does not initiate scans. See the
[report-review walkthrough](docs/dashboard/STREAMLIT_DASHBOARD.md).

**Try the dashboard in your browser — no local setup (GitHub Codespaces):**

GitHub Pages can only serve static files, so the live dashboard can't run
there — but Codespaces runs it in your browser straight from the repository
page:

1. On github.com: **Code → Codespaces → Create codespace on main**.
2. Wait for the container build; the dashboard launches automatically and
   Codespaces offers **Open in Browser** for port 8501.
3. Every feature is exercisable out of the box: the Batch Processing tab has
   **bundled sample scenarios** (SSH brute force, failure-then-success) so
   sequence correlation, verified citations, and incident reports work in one
   click, and Knowledge Base Search fails soft to the offline lexical corpus
   when Qdrant isn't running (the results are labelled with the backend that
   served them). Forwarded ports are private to you by default.

---

## Quality gates (must be green — [`AGENTS.md`](./AGENTS.md) §7)

<!-- BEGIN GENERATED: quality-gates -->
```bash
# 1. Everything compiles
python -m compileall .

# 2. Full test suite (unit, integration, security) — CI adds an 85% coverage gate
python -m pytest

# 3. Lint & style (formatting is CI-enforced too: ruff format --check .)
ruff check .

# 4. Static type checking (full CI scope)
mypy agents attack intel ingest scripts tests dashboard mcp rag compliance

# 5. Security static analysis (SAST) — same config and scope as CI
bandit -c pyproject.toml -r agents attack intel ingest scripts mcp

# 6. Drift gates — derived artifacts must match their sources
python scripts/check_locks.py           # exported pip locks ↔ uv.lock
python scripts/build_status_page.py --check   # status page ↔ status.data.json
python scripts/build_trust_page.py --check    # trust page ↔ trust.data.json
python scripts/build_readme.py --check        # README generated sections ↔ their sources
python scripts/rename_to_ianua.py --check     # no legacy pre-IANUA identifiers
python scripts/build_attack_navigator.py --check  # Navigator layer ↔ Sigma corpus + attack/ pin
python scripts/update_attack.py --check       # ATT&CK shards ↔ signed pin; revocation invariants
python scripts/check_mapping_rules.py --check # mapping ruleset ↔ digest; techniques resolve in the pin
python scripts/check_intel_store.py --check   # intel library ↔ digest; licenses, TLP, anchors validate
python scripts/build_behavior_index.py --check # behavioral index ↔ corpus; anchors resolve active
```
<!-- END GENERATED: quality-gates -->

---

## Layout

```
agents/       orchestration, roles, tools, policies   tests/        unit | integration | security
attack/       pinned local MITRE ATT&CK corpus         intel/        local threat-intel library
rag/          ingestion → retrieval                    infra/        IaC / deploy (gated)
mcp/          MCP servers exposed to agents            detections/   defensive, lab-scoped content
scripts/      operational & RAG tooling                data/         lab data only (gitignored)
cli/          user-facing entry points — run_incident.py, batch_run_incidents.py
```

---

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](./LICENSE).
You may use, modify, and redistribute this work, including commercially,
subject to the license terms (which include an express patent grant).

Attributions, content provenance, and trademark reservations are in
[`NOTICE`](./NOTICE); the reasoning behind the license choice and the
copyright/trademark/patent posture is recorded in
[`docs/IP_AND_LICENSING.md`](./docs/IP_AND_LICENSING.md). Note that the license does **not** grant rights to the
IANUA name or marks (Apache-2.0 §6) — please brand derivative works as your
own. Third-party marks referenced descriptively (MITRE ATT&CK®, NIST, OWASP®,
CIS®) belong to their respective owners.

---

> Security tooling here is for **defensive, authorized-lab use only**.
> See [`AGENTS.md`](./AGENTS.md) §5 and [`SECURITY.md`](./SECURITY.md).