# Dashboard Concept

## Purpose

Create an operational view of agents, cyber alerts, knowledge ingestion, project status, and portfolio progress.

## Status

Shipped as the Streamlit command center (`dashboard/app.py`): SOC workflow,
batch sequence correlation, knowledge-base search (fail-soft backends),
system health, and report views. See `docs/dashboard/STREAMLIT_DASHBOARD.md`.

## STICHES/DESIGN.md Guidance

Dashboard components should use the design tokens in `DESIGN.md` and preserve the command-center identity.

## Future Modules

- Agent status
- Task queue
- Alert queue
- Knowledge ingestion queue
- Portfolio progress
- Governance warnings
- Weekly review panel
