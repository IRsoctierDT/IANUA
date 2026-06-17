# SOC Fundamentals

**Topic:** Security Operations Center (SOC) practice
**Related frameworks:** NIST CSF 2.0 (Detect/Respond), CIS Controls v8.1 (8, 13, 17)

> A Security Operations Center monitors, detects, investigates, and responds to
> cybersecurity events. It is the operational core where telemetry becomes triaged,
> documented, and (where warranted) escalated incidents.

## Core SOC duties

- Monitor logs and alerts across the environment
- Investigate suspicious activity
- Correlate events across systems and time
- Preserve evidence with a clear chain of custody
- Escalate high-risk incidents to the right responders
- Document findings for review and lessons learned

## Common evidence sources

- Firewall logs
- IDS/IPS alerts
- Authentication logs (e.g. SSH, VPN, directory services)
- Endpoint detection alerts
- DNS logs
- Packet captures

## The alert-triage workflow

1. **Classify** the event type from the raw signal.
2. **Score severity** — combine the event type with aggravating context (privileged
   accounts, repetition/brute-force, explicit criticality).
3. **Extract indicators** (IPs, domains, accounts) for enrichment.
4. **Map** to a shared vocabulary (e.g. MITRE ATT&CK technique).
5. **Recommend actions**, and **escalate** only when severity warrants human review.

This is exactly the pipeline implemented by the project's **SOC Analyst Agent v0.2**
(`agents/soc_analyst_agent.py`) and orchestrated with the MITRE Mapper, Threat Intel,
and Incident Report agents. See the
[case study](../../docs/case-studies/soc-analyst-v0.2.md).

## Analysis rule

Separate **facts, assumptions, analysis, recommendations, and unknowns.** An analyst
(or an agent) should never present an assumption as a fact. Agents *recommend*;
humans approve destructive, external, or escalation-worthy actions (see
[AGENTS.md](../../AGENTS.md) §5).
