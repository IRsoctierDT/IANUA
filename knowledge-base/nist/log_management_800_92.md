# NIST SP 800-92 — Log Management (Overview)

**Framework:** NIST Special Publication 800-92, *Guide to Computer Security
Log Management* (with the SP 800-92r1 update effort, *Cybersecurity Log
Management Planning Guide*)
**Authoritative source:** <https://csrc.nist.gov/pubs/sp/800/92/final>

> Logs are only evidence if they survive the incident. The guide's central
> themes are log generation coverage, protected centralized collection, and
> defined retention — so that analysis and forensics remain possible even
> when an attacker controls the originating host.

## Key points

- **Centralize and forward:** copies of security-relevant logs should leave
  the originating host promptly; host-only logs can be destroyed by the same
  compromise they record. (This is why log tampering on a host is treated as
  a high-severity, post-compromise signal — and why recovery guidance points
  to remote/forwarded copies.)
- **Protect log integrity:** restrict access to log files, detect and alert
  on clearing or stopping of audit services, and prefer append-only or
  tamper-evident storage for security event records.
- **Define retention and rotation** by policy, balancing forensic value,
  storage, and any regulatory requirements.
- **Normalize for analysis:** consistent timestamps (synchronized clocks)
  and parseable formats are prerequisites for correlation.

## How this knowledge base uses it

The platform's audit trail follows the integrity guidance directly: security
decisions are recorded to a hash-chained, tamper-evident log, and the SOC
pipeline classifies audit-evidence destruction (history cleared, audit daemon
stopped) as its own high-severity event type mapped to ATT&CK T1070.

*This entry is an original summary; consult the authoritative source above
for complete and current guidance.*
