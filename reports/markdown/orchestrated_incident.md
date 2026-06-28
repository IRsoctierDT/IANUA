# Incident Report

## Generated
2026-06-19T09:58:03.501817+00:00

## Summary
Detected probable authentication failure activity.

## Severity
high

## Event Type
authentication failure

## MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** Brute Force
- **Technique ID:** T1110
- **Confidence:** medium

### MITRE Evidence
- Authentication failure event detected.
- Repeated failed login activity may indicate brute force behavior.

### MITRE Investigation Steps
- Check source IP frequency.
- Review failed login count per account.
- Verify whether MFA or account lockout controls were triggered.

## Evidence

| Field | Value | Significance |
|-------|-------|--------------|
| privileged_account | root/administrator | Privileged account targeted — elevates severity. |
| event_signal | failed password / invalid user | Direct keyword match for authentication failure pattern. |

## Severity Score

**80 / 100**

## Indicators
- `10.0.0.5`

## Recommended Actions
- Preserve the original log evidence.
- Correlate with adjacent timestamps.
- Check whether the source IP appears repeatedly.
- Review account lockout, MFA, and SSH exposure.
- Escalate for immediate human review.

## Knowledge Base References
- **enterprise_attack_overview.md** (relevance 0.44) — # MITRE ATT&CK — Enterprise Matrix Overview **Framework:** MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge) **Matrix:** Enterprise **Author
- **soc_fundamentals.md** (relevance 0.33) — # SOC Fundamentals **Topic:** Security Operations Center (SOC) practice **Related frameworks:** NIST CSF 2.0 (Detect/Respond), CIS Controls v8.1 (8, 13, 17) > A
- **csf_2_overview.md** (relevance 0.22) — # NIST Cybersecurity Framework (CSF) 2.0 — Overview **Framework:** NIST Cybersecurity Framework **Version:** 2.0 (published February 2024) **Authoritative sourc

## Detection Coverage
- **SSH Brute Force Followed by Successful Root Login** [critical] — `ssh_bruteforce_then_success.yml` (T1110)
- **SSH Brute Force - Repeated Failed Passwords** [high] — `ssh_brute_force.yml` (T1110)
- **SSH Failed Password** [low] — `ssh_failed_password.yml` (T1110)

## Assumptions
- Analysis is based only on the supplied log input.
- No external enrichment, threat intelligence, or packet inspection was performed.
