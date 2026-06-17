# Security Policy

## Scope & intent

This project is for **defensive cybersecurity and authorized lab use only**.
It must not be used to scan, attack, exploit, or access systems you do not own
or have written authorization to test. See [AGENTS.md](./AGENTS.md) §5.

## Supported versions

| Version | Status |
|---------|--------|
| 0.1.x (current) | Supported — security fixes applied |
| < 0.1.0 | Not supported |

## Reporting a vulnerability

**Do not open a public GitHub issue for security defects.**

Report privately by emailing **irozenblad@icloud.com** with:

- Affected component (e.g. `agents/soc_analyst_agent.py`, `mcp/server.py`, CI workflow)
- Steps to reproduce
- Impact assessment (data exposure, privilege escalation, denial of service, etc.)
- Suggested remediation, if any

You will receive an acknowledgement within **5 business days**. Please allow up to
**30 days** for triage and a fix before any public disclosure (coordinated disclosure).
Critical findings (CVSS ≥ 9.0) will be prioritized for an expedited patch.

## Components in scope

| Component | Path | Notes |
|-----------|------|-------|
| SOC Analyst Agent | `agents/soc_analyst_agent.py` | Log classification and severity scoring |
| Incident Report Agent | `agents/incident_report_agent.py` | Markdown report generation |
| MITRE Mapper Agent | `agents/mitre_mapper_agent.py` | ATT&CK technique mapping |
| Threat Intel Agent | `agents/threat_intel_agent.py` | IOC enrichment |
| Orchestrator Agent | `agents/orchestrator_agent.py` | Multi-agent workflow coordination |
| MCP Server | `mcp/server.py`, `mcp/transport.py` | Local model context protocol |
| RAG pipeline | `rag/` | Ingestion, embedding, retrieval |
| CI/CD workflows | `.github/workflows/` | Pipeline integrity |
| Tool validation | `agents/tools/validation.py` | Input sanitisation boundary |

## Out of scope

- Issues in upstream dependencies (report to the relevant upstream project)
- Vulnerabilities requiring physical access to the host machine
- Social engineering of maintainers
- Denial-of-service against GitHub Actions runners

## Security controls in place

- **SAST**: `bandit` runs on every CI push and pull request
- **SCA**: `pip-audit` scans dependencies for known CVEs on every CI run
- **Secret scanning**: `gitleaks` scans every pull request; `detect-secrets` in pre-commit
- **Static typing**: `mypy` enforces type safety on all agent and script code
- **Least-privilege CI**: each workflow job declares only the permissions it needs
- **No secrets in source**: all configuration keys documented in `.env.example`;
  real values live only in environment/secret stores

## Sensitive data handling

Logs, legal documents, client information, credentials, and PII are sensitive by default.
They are never committed to source, never logged in plaintext, and never transmitted to
external endpoints. The `data/` directory is gitignored.
