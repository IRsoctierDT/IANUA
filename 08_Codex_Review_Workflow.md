# Codex Review Workflow

## Purpose

Use Codex as a disciplined review partner for bugs, edge cases, test gaps,
security risks, and repository consistency — on top of the automated gates
(ruff, mypy, bandit, pip-audit, gitleaks, CodeQL, pytest + coverage, drift
gates), which run on every pull request.

## PR Review Prompt

```text
@codex review

Please focus on security defects, logic errors, unhandled edge cases, unsafe external actions, missing tests, and violations of AGENTS.md or DESIGN.md.
```

## Required Review Areas

- Security (AGENTS.md §6.1 priority order: security → logic → edge cases →
  unsafe execution → validation → tests → docs → design drift)
- Type safety
- Test coverage
- Documentation accuracy
- Human approval gates
- Repository conventions
- STICHES/DESIGN.md consistency

## Closing the loop

Every review finding gets a reply citing the fix commit, and the thread is
resolved once addressed — findings are never silently dismissed.
