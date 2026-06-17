# CIS Critical Security Controls v8.1 — Overview

**Framework:** CIS Critical Security Controls
**Version:** 8.1 (released June 2024; 18 controls, 153 safeguards)
**Authoritative source:** <https://www.cisecurity.org/controls/v8-1>

> The CIS Controls are a prioritized, prescriptive set of safeguards to mitigate the
> most common cyberattacks. v8.1 refines v8 and **aligns to NIST CSF 2.0** — including
> adding a *Governance* security function and a *Documentation* asset class.

## The 18 controls

| # | Control |
|---|---------|
| 1 | Inventory and Control of Enterprise Assets |
| 2 | Inventory and Control of Software Assets |
| 3 | Data Protection |
| 4 | Secure Configuration of Enterprise Assets and Software |
| 5 | Account Management |
| 6 | Access Control Management |
| 7 | Continuous Vulnerability Management |
| 8 | Audit Log Management |
| 9 | Email and Web Browser Protections |
| 10 | Malware Defenses |
| 11 | Data Recovery |
| 12 | Network Infrastructure Management |
| 13 | Network Monitoring and Defense |
| 14 | Security Awareness and Skills Training |
| 15 | Service Provider Management |
| 16 | Application Software Security |
| 17 | Incident Response Management |
| 18 | Penetration Testing |

## Implementation Groups (IGs)

The controls are tiered so organizations adopt them by capacity and risk:

- **IG1** — essential cyber hygiene; the baseline every organization should meet.
- **IG2** — for organizations managing more sensitive data / greater complexity.
- **IG3** — for organizations with mature security needs and higher-risk assets.

Each higher group is a superset of the one below it.

## How this knowledge base uses it

The CIS Controls serve as a practical security baseline for hardening, monitoring,
and operational checklists. Several controls map directly to this project's work:

- **Control 8 (Audit Log Management)** and **13 (Network Monitoring and Defense)** —
  the SOC Analyst and Threat Intel agents operate on these data sources.
- **Control 17 (Incident Response Management)** — the Incident Report agent produces
  the documented artifacts this control expects.
- **Control 16 (Application Software Security)** — pairs with the OWASP Top 10 KB.

> Cross-reference: CIS publishes an official **v8.1 → NIST CSF 2.0 mapping**. Confirm
> the current safeguard list at the authoritative source above.
