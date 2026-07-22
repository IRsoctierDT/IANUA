# Security Policy

## Scope & intent

This project is for **defensive cybersecurity and authorized lab use only**.
It must not be used to scan, attack, exploit, or access systems you do not own
or have written authorization to test. See [AGENTS.md](./AGENTS.md) §5.

## Supported versions

| Version | Status |
|---------|--------|
| 2.0.x (current — Master v2 STICHES Edition) | Supported — security fixes applied |
| 1.x | Critical security fixes only, upgrade recommended |
| < 1.0 | Not supported |

## Reporting a vulnerability

**Do not open a public GitHub issue for security defects.**

Preferred: open a **private GitHub Security Advisory** on the repository
(Security → Advisories → Report a vulnerability). Alternatively, report
privately by emailing **irozenblad@icloud.com** with:

- Affected component (e.g. `agents/policies/audit.py`, `mcp/server.py`, CI workflow)
- Steps to reproduce
- Impact assessment (data exposure, privilege escalation, denial of service, etc.)
- Suggested remediation, if any

You will receive an acknowledgement within **5 business days**. Please allow up to
**30 days** for triage and a fix before any public disclosure (coordinated disclosure).
Critical findings (CVSS ≥ 9.0) will be prioritized for an expedited patch.

## Components in scope

| Component | Path | Notes |
|-----------|------|-------|
| Agent suite | `agents/` | SOC (incl. sequence correlation), MITRE mapper, threat intel, incident reports, knowledge base, orchestrator, and supporting agents |
| Policy & audit layer | `agents/policies/` | Default-deny policy engine; tamper-evident hash-chained audit log with HMAC/Ed25519 head signing |
| MCP server + sandbox | `mcp/` | Local model-context-protocol server; containerized tool execution |
| RAG pipeline | `rag/` | Ingestion, embedding, retrieval, verified passage citations |
| Dashboard | `dashboard/` | Streamlit command center (local-only backends, fail-soft) |
| Detection content | `detections/` | Lab-scoped Sigma rules and correlations |
| Verification CLIs | `scripts/` | `audit_verify`, `audit_maintenance`, SBOM/locks/status drift checks |
| CI/CD workflows | `.github/workflows/` | Pipeline integrity, drift gates, human-gated Pages deploy |
| Tool validation | `agents/tools/validation.py` | Input sanitisation boundary |

## Out of scope

- Issues in upstream dependencies (report to the relevant upstream project;
  our `pip-audit` gate picks up published advisories)
- Vulnerabilities requiring physical access to the host machine
- Social engineering of maintainers
- Denial-of-service against GitHub Actions runners

## Security controls in place

- **SAST**: `bandit` on every push/PR; **CodeQL** analysis on the repository
- **SCA**: `pip-audit` scans the pinned dependency closure on every CI run;
  Dependabot proposes updates (security updates are never grouped)
- **Supply chain**: CycloneDX **SBOM** + exported hash-pinned locks derived from
  `uv.lock`, verified in-sync by read-only CI drift gates
- **Secret scanning**: `gitleaks` on every PR; `detect-secrets` in pre-commit
- **Tamper-evident audit**: hash-chained JSONL audit log with rotation,
  checkpoint anchoring, and HMAC or Ed25519 head signing; standalone
  read-only verifier (`scripts/audit_verify.py`) with fail-closed exit codes
- **Sandboxed tool execution**: MCP tool calls run in a Linux container;
  enforcement is tested in CI
- **Static typing**: `mypy` across agents, scripts, tests, dashboard, mcp, rag
- **Least-privilege CI**: each workflow job declares only the permissions it
  needs; drift gates are read-only and never auto-commit
- **Human-gated deploys**: the `github-pages` environment requires human
  approval **by design**; deploys are never automatic
- **No secrets in source**: all configuration keys documented in `.env.example`;
  real values live only in environment/secret stores

## Sensitive data handling

Logs, legal documents, client information, credentials, and PII are sensitive by default.
They are never committed to source, never logged in plaintext, and never transmitted to
external endpoints. The `data/` directory is gitignored. Public demo environments
(e.g. Codespaces) must only ever process the bundled lab fixtures in `sample-logs/`.
