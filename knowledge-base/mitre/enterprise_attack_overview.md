# MITRE ATT&CK — Enterprise Matrix Overview

**Framework:** MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge)
**Matrix:** Enterprise
**Authoritative source:** <https://attack.mitre.org/>

> ATT&CK is a globally accessible, continuously updated knowledge base of adversary
> behavior based on real-world observations. **Tactics** are the adversary's *why*
> (the goal of an action); **techniques** are the *how*; **sub-techniques** are more
> specific variants; **procedures** are observed in-the-wild implementations.

## The 14 Enterprise tactics (the kill-chain ordering)

| # | Tactic | Adversary goal |
|---|--------|----------------|
| TA0043 | Reconnaissance | Gather information to plan the operation |
| TA0042 | Resource Development | Establish infrastructure/capabilities |
| TA0001 | Initial Access | Get into the network |
| TA0002 | Execution | Run adversary-controlled code |
| TA0003 | Persistence | Maintain a foothold across restarts/credentials changes |
| TA0004 | Privilege Escalation | Gain higher-level permissions |
| TA0005 | Defense Evasion | Avoid detection |
| TA0006 | Credential Access | Steal account names and secrets |
| TA0007 | Discovery | Learn the environment |
| TA0008 | Lateral Movement | Move through the environment |
| TA0009 | Collection | Gather data of interest |
| TA0011 | Command and Control | Communicate with compromised systems |
| TA0010 | Exfiltration | Steal data |
| TA0040 | Impact | Manipulate, interrupt, or destroy systems/data |

## Core uses

- Map observed behavior to adversary techniques (a shared vocabulary across teams).
- Drive **detection engineering** — write and assess coverage per technique.
- Structure **incident investigation** — pivot from one technique to likely next steps.
- Standardize defensive reporting so findings are comparable across incidents.

## Techniques mapped by this project's agents

The MITRE Mapper Agent currently emits these mappings (see
`agents/mitre_mapper_agent.py`):

| Technique ID | Technique | Tactic |
|--------------|-----------|--------|
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts | Initial Access (also Persistence / Privilege Escalation / Defense Evasion) |

> **Living framework.** ATT&CK is versioned and revised regularly; technique IDs and
> sub-techniques are added and deprecated. Confirm current IDs at the source above.
