# Detections

Lab-scoped, **defensive** detection-engineering content for the AI Operator Cyber
Command Center. Rules here describe *adversary behavior to alert on* — they do not
attack anything (AGENTS.md §5).

## Format

Detections are written as [**Sigma**](https://sigmahq.io/) rules (`detections/sigma/`)
— a vendor-neutral, portable signature format. Convert them to your SIEM's query
language with [pySigma](https://github.com/SigmaHQ/pySigma) / the `sigma` CLI
(e.g. Splunk SPL, Elastic, Sentinel).

## Mapping to the agents

Each rule is tagged with the MITRE ATT&CK technique the **SOC Analyst** and
**MITRE Mapper** agents emit, so detection content and triage share one vocabulary
(see [`knowledge-base/mitre/`](../knowledge-base/mitre/enterprise_attack_overview.md)).

| Rule | Detects | ATT&CK | Agent event type |
|------|---------|--------|------------------|
| `sigma/ssh_brute_force.yml` | Repeated failed SSH passwords from one source | T1110 Brute Force | `authentication failure` |
| `sigma/ssh_successful_root_login.yml` | Successful interactive root SSH login | T1078 Valid Accounts | `successful login` |

## Scope & quality

- **Defensive and lab-scoped only.** No offensive payloads or unowned-target tooling.
- Every rule carries `falsepositives` and a `level`, and is validated structurally by
  `tests/test_detections.py` (parses, required Sigma fields, valid unique UUIDs,
  ATT&CK technique tag).
- `status: experimental` until validated against real telemetry in a lab.
