"""Regenerate core Markdown files from the STICHES/DESIGN.md identity."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.strip() + "\n", encoding="utf-8")


def generate() -> None:
    if not (ROOT / "DESIGN.md").exists():
        raise FileNotFoundError("DESIGN.md is required in the project root.")
    write(
        "README.md",
        '\n# IANUA™ — Master v1 STICHES Edition\n\n## Mission\n\nBuild a disciplined AI operations and cybersecurity command-center environment.\n\n## Operating Principle\n\nDo not merely use AI. Build systems with AI.\n\n## What This Repository Contains\n\n- Master v1 architecture\n- STICHES/DESIGN.md identity system\n- Codex-ready instructions\n- Python agent scaffold\n- Governance controls\n- Documentation generator\n- CI workflow\n- Portfolio roadmap\n- Dashboard concept\n- SOC Analyst Agent starter\n\n## Primary Layers\n\n1. Local Development Workstation\n2. AI Model Layer\n3. Knowledge Management Layer\n4. RAG System Layer\n5. Agent Ecosystem\n6. Cybersecurity Lab Layer\n7. Workflow Automation Layer\n8. Governance and Audit Layer\n9. Portfolio Layer\n10. Dashboard Layer\n\n## First Execution\n\n```bash\npython3 -m venv venv\nsource venv/bin/activate\npip install -e ".[dev]"\npython agents/soc_analyst_agent.py\npytest\n```\n\n## Regenerate Markdown from STICHES/DESIGN.md\n\n```bash\npython scripts/generate_docs_from_design.py\n```\n\n## Validate DESIGN.md\n\n```bash\nnpm install\nnpm run design:lint\n```\n',
    )
    write(
        "00_Project_Charter.md",
        "\n# Project Charter\n\n## Project Name\n\nIANUA™ — Master v1 STICHES Edition\n\n## Purpose\n\nCreate a professional-grade command center for AI operations, cybersecurity automation, agentic workflows, RAG knowledge systems, governance, and portfolio development.\n\n## Strategic Position\n\nThe project develops operator capability: the ability to design, govern, secure, and document repeatable AI-enabled systems.\n\n## Objectives\n\n- Build AI agents for cybersecurity, research, documentation, and business workflows.\n- Develop a governed RAG knowledge system.\n- Produce portfolio-ready evidence of practical technical skill.\n- Maintain safety, auditability, and human approval gates.\n- Use STICHES/DESIGN.md as the canonical identity system.\n\n## Success Standard\n\nEvery major workflow must be repeatable, documented, testable, secure, explainable, and portfolio-ready.\n",
    )
    write(
        "01_Architecture.md",
        "\n# Architecture\n\n## Summary\n\nThe system is organized into ten layers: development, model, knowledge, RAG, agent, cybersecurity lab, automation, governance, portfolio, and dashboard.\n\n## Architecture Rule\n\nAgents recommend, draft, classify, summarize, and structure. Humans approve destructive, external, legal, financial, or security-sensitive actions.\n\n## STICHES Integration\n\n`DESIGN.md` controls the documentation and future UI identity. Any dashboard, report, or agent-generated artifact should follow its color, typography, layout, and governance rules.\n",
    )
    write(
        "02_90_Day_Roadmap.md",
        "\n# 90-Day Roadmap\n\n## Month 1 — Foundation\n\n- Establish repository.\n- Configure Python environment.\n- Add Codex/AGENTS.md rules.\n- Add STICHES/DESIGN.md identity.\n- Build SOC Analyst Agent v0.1.\n- Add pytest, Ruff, MyPy, and Bandit.\n- Add GitHub CI.\n\n## Month 2 — Knowledge and RAG\n\n- Build document ingestion prototype.\n- Add vector database integration.\n- Create cybersecurity knowledge base.\n- Create Legal/Compliance Agent blueprint.\n- Create Knowledge Curator Agent blueprint.\n\n## Month 3 — Portfolio Proof\n\n- Build SOC Analyst Agent v0.2.\n- Add Markdown incident report generation.\n- Add sample logs.\n- Publish first GitHub case study.\n- Prepare dashboard concept.\n",
    )
    write(
        "03_Agent_Blueprints.md",
        "\n# Agent Blueprints\n\n## SOC Analyst Agent\n\nAnalyzes logs and alerts. Produces severity, event type, indicators, recommended actions, assumptions, and evidence.\n\n## Threat Intelligence Agent\n\nSummarizes indicators, suspicious domains, threat reports, and confidence levels.\n\n## Vulnerability Assessment Agent\n\nConverts scan results into remediation priorities.\n\n## Legal/Compliance Research Agent\n\nSupports issue analysis, authority review, citation checklists, and draft preparation. It does not replace legal counsel.\n\n## Business Proposal Agent\n\nConverts client needs into structured proposals and scopes of work.\n\n## Knowledge Curator Agent\n\nOrganizes notes, transcripts, PDFs, and research into retrieval-ready knowledge.\n\n## Portfolio Documentation Agent\n\nTurns lab work into GitHub-ready README files, reports, and case studies.\n\n## Executive Assistant Agent\n\nSupports planning, prioritization, review cycles, and decision logs.\n",
    )
    write(
        "04_Environment_Setup.md",
        '\n# Environment Setup\n\n## Required Local Stack\n\n- Homebrew\n- Git\n- Python 3.12+\n- VS Code or Cursor\n- Docker or Podman\n- Ollama\n- PostgreSQL\n- Qdrant\n- Node.js\n- GitHub CLI\n\n## Setup\n\n```bash\npython3 -m venv venv\nsource venv/bin/activate\npip install --upgrade pip\npip install -e ".[dev]"\n```\n\n## Validate Local AI Stack\n\n```bash\nollama run llama3.1\ncurl http://localhost:6333\npsql postgres\npython agents/soc_analyst_agent.py\npytest\n```\n',
    )
    write(
        "05_Governance_Rules.md",
        "\n# Governance Rules\n\n## Mandatory Controls\n\n1. No secrets in GitHub.\n2. No sensitive client, legal, or personal data in public repositories.\n3. No unauthorized scanning or offensive tooling.\n4. Human approval required for destructive or external actions.\n5. High-stakes outputs must separate facts, assumptions, analysis, recommendations, and unknowns.\n6. Meaningful code changes must be tested.\n7. Agent-generated documents must follow `DESIGN.md`.\n\n## Human Approval Required Before\n\n- Sending emails\n- Filing complaints\n- Publishing reports\n- Running scans outside an authorized lab\n- Changing firewall rules\n- Deleting data\n- Installing unknown software\n- Using sensitive personal data\n",
    )
    write(
        "06_Portfolio_Tracker.md",
        "\n# Portfolio Tracker\n\n| Project | Skill Demonstrated | Status | Evidence |\n|---|---|---:|---|\n| SOC Analyst Agent | Cybersecurity automation | Active | Agent code and tests |\n| STICHES/DESIGN.md System | Design-system governance | Active | DESIGN.md |\n| RAG Knowledge Base | Retrieval systems | Planned | Architecture docs |\n| Legal/Compliance Agent | Research workflow | Planned | Blueprint |\n| Business Proposal Agent | Business automation | Planned | Blueprint |\n| Dashboard | Full-stack AI operations | Planned | Concept doc |\n| Governance System | AI safety and controls | Active | AGENTS.md and policies |\n",
    )
    write(
        "07_First_Build_Sprint.md",
        "\n# First Build Sprint\n\n## Goal\n\nMake the project executable, testable, reviewable, and design-system governed.\n\n## Tasks\n\n1. Open project in VS Code or Cursor.\n2. Create Python virtual environment.\n3. Install development dependencies.\n4. Run SOC Analyst Agent.\n5. Run pytest.\n6. Run Ruff, MyPy, and Bandit.\n7. Validate DESIGN.md.\n8. Regenerate docs from DESIGN.md.\n9. Commit baseline.\n10. Push to GitHub.\n\n## Definition of Done\n\n- `python agents/soc_analyst_agent.py` runs.\n- `pytest` passes.\n- `DESIGN.md` exists.\n- `AGENTS.md` exists.\n- GitHub CI exists.\n- Documentation regeneration script exists.\n",
    )
    write(
        "08_Codex_Review_Workflow.md",
        "\n# Codex Review Workflow\n\n## Purpose\n\nUse Codex as a disciplined review partner for bugs, edge cases, test gaps, security risks, and repository consistency.\n\n## PR Review Prompt\n\n```text\n@codex review\n\nPlease focus on security defects, logic errors, unhandled edge cases, unsafe external actions, missing tests, and violations of AGENTS.md or DESIGN.md.\n```\n\n## Required Review Areas\n\n- Security\n- Type safety\n- Test coverage\n- Documentation accuracy\n- Human approval gates\n- Repository conventions\n- STICHES/DESIGN.md consistency\n",
    )
    write(
        "09_Master_Architecture_Blueprint.md",
        "\n# Master Architecture Blueprint\n\n## Command-Center Model\n\nThis project is a layered AI operations system, not a loose collection of scripts.\n\n## Core Layers\n\n1. Development Console\n2. AI Model Layer\n3. Knowledge Layer\n4. RAG Layer\n5. Agent Layer\n6. Cybersecurity Lab Layer\n7. Automation Layer\n8. Governance Layer\n9. Portfolio Layer\n10. Dashboard Layer\n\n## STICHES/DESIGN.md Layer\n\nThe design layer governs documentation identity, dashboard styling, agent-generated report structure, and future UI token exports.\n\n## Immediate Next Build\n\nSOC Analyst Agent v0.2:\n\n- JSON input support\n- Severity scoring\n- Evidence table\n- Markdown incident report\n- Sample logs\n- Unit tests\n- Portfolio case study\n",
    )
    write(
        "architecture/SYSTEM_MAP.md",
        "\n# System Map\n\n## Main Layers\n\n- Local Development\n- AI Models\n- Knowledge Base\n- RAG\n- Agents\n- Cyber Lab\n- Automations\n- Governance\n- Portfolio\n- Dashboard\n- STICHES/DESIGN.md Identity\n\nConsult `../DESIGN.md` before generating UI, dashboard, documentation, or portfolio surfaces.\n",
    )
    write(
        "portfolio/12_Month_Portfolio_Roadmap.md",
        "\n# 12-Month Portfolio Roadmap\n\n## Quarter 1\n\nFoundation, SOC Analyst Agent, CI, tests, prompt library, STICHES/DESIGN.md integration.\n\n## Quarter 2\n\nRAG system, Knowledge Curator Agent, Legal/Compliance Research Agent.\n\n## Quarter 3\n\npfSense and Suricata workflows, incident reporting, vulnerability assessment.\n\n## Quarter 4\n\nDashboard prototype, portfolio case studies, professional presentation package.\n",
    )
    write(
        "workflows/OPERATOR_WORKFLOWS.md",
        "\n# Operator Workflows\n\n## Cyber Log to Incident Report\n\nClassify event, estimate severity, extract indicators, and generate a report.\n\n## Document to Knowledge Base\n\nIngest, summarize, tag, chunk, and store for retrieval.\n\n## Legal/Compliance Issue to Research Outline\n\nSeparate facts, authority, analysis, recommendations, and unknowns.\n\n## Lab Work to Portfolio\n\nConvert commands, screenshots, observations, and findings into a GitHub-ready case study.\n\n## Design-System Regeneration\n\nUpdate `DESIGN.md`, then run:\n\n```bash\npython scripts/generate_docs_from_design.py\n```\n",
    )
    write(
        "security/DATA_CLASSIFICATION.md",
        "\n# Data Classification\n\n## Public\n\nSafe for GitHub.\n\n## Internal\n\nPrivate planning and non-sensitive drafts.\n\n## Confidential\n\nClient data, legal facts, personal identifiers, secrets, tokens, private logs.\n\n## Rule\n\nWhen uncertain, classify as Confidential.\n",
    )
    write(
        "dashboards/DASHBOARD_CONCEPT.md",
        "\n# Dashboard Concept\n\n## Purpose\n\nCreate an operational view of agents, cyber alerts, knowledge ingestion, project status, and portfolio progress.\n\n## STICHES/DESIGN.md Guidance\n\nDashboard components should use the design tokens in `DESIGN.md` and preserve the command-center identity.\n\n## Future Modules\n\n- Agent status\n- Task queue\n- Alert queue\n- Knowledge ingestion queue\n- Portfolio progress\n- Governance warnings\n- Weekly review panel\n",
    )
    write(
        "docs/DESIGN_MD_IMPLEMENTATION.md",
        "\n# STICHES / DESIGN.md Implementation\n\n## Purpose\n\nThis project uses `DESIGN.md` as the canonical design and documentation identity.\n\n## What DESIGN.md Controls\n\n- Visual identity\n- Documentation tone\n- Color and typography tokens\n- UI and dashboard guidance\n- Agent-facing design rationale\n- Governance-aware documentation style\n\n## Regenerate Markdown\n\n```bash\npython scripts/generate_docs_from_design.py\n```\n\n## Validate DESIGN.md\n\n```bash\nnpx @google/design.md lint DESIGN.md\n```\n\n## Export Tokens\n\n```bash\nnpx @google/design.md export --format json-tailwind DESIGN.md > tailwind.theme.json\nnpx @google/design.md export --format css-tailwind DESIGN.md > theme.css\n```\n",
    )


if __name__ == "__main__":
    generate()
    print("Generated Master v1 STICHES Markdown files.")
