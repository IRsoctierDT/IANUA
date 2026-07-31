# CIS Control 8 — Audit Log Management (Overview)

**Framework:** CIS Critical Security Controls v8.1, Control 8
**Authoritative source:** <https://www.cisecurity.org/controls/audit-log-management>

> Collect, alert on, review, and retain audit logs of events that could help
> detect, understand, or recover from an attack. Control 8 is the bridge
> between "systems produce logs" and "the organization can actually answer
> what happened."

## Key points

- **Establish and maintain a log management process** (8.1) — what is
  collected, where it goes, and how long it is kept, reviewed on a schedule.
- **Collect audit logs** (8.2) and **ensure adequate storage** (8.3) —
  coverage and retention before analytics.
- **Standardize time** (8.4) — synchronized clocks are a prerequisite for
  any cross-host correlation; unsynchronized timestamps silently break
  sequence analysis.
- **Collect detailed audit logs** (8.5) for sensitive data and privileged
  activity — privileged-group changes and account lifecycle events are
  exactly this class.
- **Centralize** (8.9) and **retain** (8.10) — off-host copies survive
  host-side tampering (ATT&CK T1070), and retention windows determine how
  far back an investigation can reach.
- **Review** (8.11) — scheduled human review plus tuned alerting; unreviewed
  logs detect nothing.

## How this knowledge base uses it

Grounds the platform's audit-trail design (centralized, tamper-evident,
retained) and the detection coverage for the events Control 8 says to watch:
account lifecycle, privileged changes, and audit-service tampering.

*This entry is an original summary; consult the authoritative source above
for the complete safeguard list and implementation groups.*
