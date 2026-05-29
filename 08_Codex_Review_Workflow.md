# Codex Review Workflow

## Purpose

Use Codex as a disciplined review partner for bugs, edge cases, test gaps, security risks, and repository consistency.

## PR Review Prompt

```text
@codex review

Please focus on security defects, logic errors, unhandled edge cases, unsafe external actions, missing tests, and violations of AGENTS.md or DESIGN.md.
```

## Required Review Areas

- Security
- Type safety
- Test coverage
- Documentation accuracy
- Human approval gates
- Repository conventions
- STICHES/DESIGN.md consistency
