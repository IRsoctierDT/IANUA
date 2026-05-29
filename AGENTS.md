# AGENTS.md

## Repository Mission

This repository is the AI Operator Cyber Command Center: a portfolio-grade environment for AI operations, cybersecurity automation, RAG systems, and agentic workflows.

## Codex and Agent Operating Rules

Before modifying code or documentation:

1. Inspect repository structure.
2. Read `DESIGN.md`.
3. Read this file.
4. Preserve existing naming conventions.
5. Keep security controls visible.

## Review Priorities

1. Security defects
2. Logic errors
3. Unhandled edge cases
4. Unsafe tool execution
5. Poor input validation
6. Broken tests
7. Incomplete documentation
8. Violations of DESIGN.md

## Security Boundaries

- Do not create offensive cybersecurity tooling outside lawful lab use.
- Do not add code that scans, attacks, exploits, or accesses third-party systems.
- Do not hard-code secrets, tokens, passwords, API keys, or personal information.
- Treat logs, legal documents, and client information as sensitive.
- Require human approval before destructive or external actions.

## Required Checks

```bash
python -m compileall .
python -m pytest
ruff check .
mypy agents scripts tests
bandit -r agents scripts
```
