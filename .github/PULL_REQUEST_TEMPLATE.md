## Summary
<!-- What changed and why. Link issues. -->

## Definition of Done (AGENTS.md §6.2)
- [ ] Scoped to the request; no unrelated edits
- [ ] Existing security controls preserved or improved (none weakened)
- [ ] Tests added/updated, incl. `tests/security` if a boundary is touched
- [ ] Local gates pass: `compileall` · `pytest` (≥85%) · `ruff` · `mypy` · `bandit`
- [ ] Public surface documented; `DESIGN.md` updated if architecture changed
- [ ] No secrets, PII, or sensitive data added anywhere
- [ ] Approval gate (§5.1) recorded if one was hit

## Residual risk & rollback
<!-- Known risks and how to revert. -->
