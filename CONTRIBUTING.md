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

## Licensing of contributions

This project is licensed under the **Apache License 2.0** ([`LICENSE`](./LICENSE)).
Per Apache-2.0 §5, any contribution you intentionally submit for inclusion is
licensed under those same terms, with no additional conditions — inbound
matches outbound. No separate CLA is required.

Only submit work you have the right to license this way. If a change carries
third-party code or content, say so in the PR and name its license; anything
that would impose extra restrictions on downstream users needs a maintainer
decision before it can be merged.

Background on the license choice and the project's IP posture:
[`docs/IP_AND_LICENSING.md`](./docs/IP_AND_LICENSING.md).
