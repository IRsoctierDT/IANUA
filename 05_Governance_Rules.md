# Governance Rules

`AGENTS.md` is the binding operating charter; these are the operating rules
in brief.

## Mandatory Controls

1. No secrets in GitHub — enforced by gitleaks in CI and a reviewed
   detect-secrets baseline in pre-commit.
2. No sensitive client, legal, or personal data in public repositories.
3. No unauthorized scanning or offensive tooling — lawful-lab scope only.
4. Human approval required for destructive or external actions — codified
   in the default-deny policy engine (`agents/policies/`), enforced at the
   MCP tool surface, and recorded in a tamper-evident signed audit chain.
5. High-stakes outputs must separate facts, assumptions, analysis,
   recommendations, and unknowns.
6. Meaningful code changes must be tested — CI gates: pytest with ≥85%
   coverage, ruff, mypy, bandit, pip-audit, CodeQL, drift gates.
7. Agent-generated documents must follow `DESIGN.md`.

## Human Approval Required Before

- Sending emails
- Filing complaints
- Publishing reports
- Running scans outside an authorized lab
- Changing firewall rules
- Deleting data
- Installing unknown software
- Using sensitive personal data
- Deploying GitHub Pages (the `github-pages` environment gate is kept by
  design and is never to be weakened or bypassed)
