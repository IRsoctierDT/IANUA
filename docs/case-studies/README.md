# Case Studies

Portfolio-grade write-ups of each component in the
[IANUA](../../README.md). Every case study follows the
[AGENTS.md](../../AGENTS.md) §9 documentation standard — Executive Summary, Objectives,
Architecture/Process, Implementation Steps, Risks, Cost Considerations, Future Enhancements —
plus a **Worked Example** using real command output and a **Reproduce It Yourself** section.

Security tooling documented here is for **defensive, authorized-lab use only** — see
[AGENTS.md](../../AGENTS.md) §5.

## Index

| # | Case Study | Layer | What it demonstrates |
|---|---|---|---|
| 1 | [SOC Analyst Agent v0.2](./soc-analyst-v0.2.md) | Agent | Raw log line → triaged, scored, MITRE-mapped, human-reviewable incident |
| 2 | [MITRE ATT&CK Mapper Agent](./mitre-mapper-agent.md) | Agent | Deterministic event → ATT&CK tactic/technique with confidence & evidence |
| 3 | [Threat Intelligence Agent](./threat-intel-agent.md) | Agent | Indicator triage that returns `unknown` + "enrich first" instead of guessing |
| 4 | [Vulnerability Assessment Agent](./vulnerability-assessment-agent.md) | Agent | Ranks authorized scan findings into a defensible remediation order |
| 5 | [Knowledge Base Agent](./knowledge-base-agent.md) | Agent/RAG | Cited corpus grounding; deterministic lexical default, safe semantic fallback |
| 6 | [Incident Report Agent](./incident-report-agent.md) | Agent | Composes a safe Markdown report; opt-in, fail-soft AI narrative |
| 7 | [Detection Matcher & Orchestrator](./detection-matcher-and-orchestrator.md) | Agent | Triage→Sigma detection loop + full multi-agent pipeline in one call |
| 8 | [Local RAG Pipeline](./rag-pipeline.md) | RAG | Confined ingest → chunk → embed → cited retrieval; fully offline mode |
| 9 | [Policy-Gated MCP Tool Surface](./mcp-server.md) | MCP | Allow-listed, self-validating, path-confined, policy-gated tool calls |
| 10 | [Policy Engine & Tamper-Evident Audit Log](./policy-and-audit.md) | Governance | Default-deny policy-as-code + hash-chained, verifiable audit trail |

## Reading order

- **New to the project?** Start with [SOC Analyst v0.2](./soc-analyst-v0.2.md), then the
  [Detection Matcher & Orchestrator](./detection-matcher-and-orchestrator.md) capstone to see how
  the agents compose.
- **Interested in the security posture?** Read the
  [MCP Tool Surface](./mcp-server.md) and the
  [Policy & Audit layer](./policy-and-audit.md).
- **Interested in the knowledge systems?** Read the
  [RAG Pipeline](./rag-pipeline.md) and the [Knowledge Base Agent](./knowledge-base-agent.md).
