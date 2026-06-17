## Summary
<!-- What changed and why. Link issues. -->

## Branch
<!-- Name of the branch and the concern it addresses (fix/, feat/, ci/, chore/) -->

## Definition of Done (AGENTS.md §6.2)
- [ ] Scoped to the request; no unrelated edits
- [ ] Existing security controls preserved or improved (none weakened)
- [ ] Tests added/updated, incl. `tests/security` if a boundary is touched
- [ ] Local gates pass: `compileall` · `pytest` (≥85%) · `ruff` · `mypy` · `bandit`
- [ ] Public surface documented; `DESIGN.md` updated if architecture changed
- [ ] No secrets, PII, or sensitive data added anywhere
- [ ] Approval gate (§5.1) recorded if one was hit

## Codex Review Checklist (08_Codex_Review_Workflow.md)
- [ ] Security — injection, path traversal, secrets, unsafe subprocess, egress
- [ ] Type safety — mypy clean, no untyped defs in library code
- [ ] Test coverage — meaningful changes have tests, ≥85% gate holds
- [ ] Documentation accuracy — agent-generated docs follow DESIGN.md
- [ ] Human approval gates — no gated action ran without explicit approval
- [ ] Repository conventions — ruff clean, import order, format check passes
- [ ] STITCHES/DESIGN.md consistency — new code follows the design system

@codex review

Please focus on security defects, logic errors, unhandled edge cases, unsafe external actions, missing tests, and violations of AGENTS.md or DESIGN.md.

## Residual risk & rollback
<!-- Known risks and how to revert. -->
