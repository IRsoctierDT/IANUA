# Contributing (humans & agents)

1. **Read first:** `DESIGN.md`, then `AGENTS.md` (binding rules).
2. **Branch:** no direct commits to `main`; open a reviewed PR.
3. **Build small:** scope the change; preserve conventions and security controls.
4. **Test:** add/extend tests; include a `tests/security` case when a boundary is touched.
5. **Gate locally:** `pre-commit run --all-files` and the §7 checks must pass.
6. **Document:** update docstrings and `DESIGN.md` if architecture changed.
7. **Definition of Done:** AGENTS.md §6.2 checklist satisfied; approval gates (§5.1) recorded.

Agents additionally announce their active role (Planner/Builder/Reviewer/Security) and stop
to ask the human at any approval gate or security boundary.
