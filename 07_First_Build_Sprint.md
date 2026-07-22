# First Build Sprint (historical record — completed)

This sprint is **done**; it bootstrapped the repository that became
IANUA v2.0.0. Kept as a record of the founding definition-of-done.

## Goal

Make the project executable, testable, reviewable, and design-system
governed.

## Definition of Done (all met)

- `python agents/soc_analyst_agent.py` runs. ✅
- `pytest` passes. ✅
- `DESIGN.md` exists. ✅
- `AGENTS.md` exists. ✅
- GitHub CI exists. ✅
- Documentation regeneration script exists. ✅

## Current cadence

Work now lands as reviewed pull requests gated by the full CI pipeline
(AGENTS.md §7-§8), tracked in `docs/PROJECT_STATUS.md`, logged in
`docs/ENGINEERING_LOG.md`, and released via tagged versions in
`docs/Changelog.md`.
