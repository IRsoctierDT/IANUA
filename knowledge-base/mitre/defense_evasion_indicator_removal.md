# MITRE ATT&CK — Indicator Removal (Defense Evasion)

**Framework:** MITRE ATT&CK (Enterprise), Defense Evasion
**Techniques:** T1070 (Indicator Removal), T1070.002 (Clear Linux or Mac
System Logs), T1070.003 (Clear Command History)
**Authoritative sources:**
<https://attack.mitre.org/techniques/T1070/> ·
<https://attack.mitre.org/techniques/T1070/003/>

> Adversaries delete or modify the artifacts their intrusion generated —
> shell history, system logs, audit records — to frustrate investigation.
> Evidence destruction presumes there was activity worth hiding: it is a
> post-compromise behavior, not an opening move.

## Key points

- **Common Linux indicators:** `history -c`, truncating or deleting
  `~/.bash_history`, clearing `/var/log` files or wtmp/btmp records, and
  stopping or disabling the audit daemon (`auditd`).
- **Severity logic:** unlike recon events, a *single* tampering indicator
  warrants high severity — there is rarely a benign burst of evidence
  destruction, and its presence retroactively raises suspicion on all prior
  activity from that host and account.
- **The defense is off-host copies:** forwarded/centralized logs (see NIST
  SP 800-92) survive host-side clearing; detection should alert on the
  clearing action itself, not only on what was cleared.
- **Response:** treat the host as compromised until reviewed; reconstruct
  the timeline from remote log copies; review what the account did before
  the destruction event.

## How this knowledge base uses it

Grounds the "log tampering" event type (T1070.003) in the SOC pipeline and
the `linux_command_history_cleared` Sigma rule, and explains why the
platform's own audit trail is hash-chained and tamper-evident.

*This entry is an original summary; consult the authoritative sources above
for complete and current technique detail.*
