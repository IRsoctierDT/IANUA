# OWASP Top 10 — A09: Security Logging and Monitoring Failures

**Framework:** OWASP Top 10 (2021), category A09
**Authoritative source:**
<https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/>

> Breaches are rarely detected by the systems they occur on. A09 covers the
> failure modes that let attacks proceed unobserved: auditable events not
> logged, warnings not monitored, logs stored only locally, and alerting
> thresholds that never fire.

## Key points

- **Log the security-relevant events:** logins (success *and* failure),
  access-control failures, and input-validation failures, with enough user
  and source context to support forensics — but never secrets or session
  tokens in log content.
- **Make logs consumable:** structured formats that log-management tools can
  parse; local-only logs are a single point of destruction (see NIST SP
  800-92 and ATT&CK T1070 — attackers clear what they can reach).
- **Monitor and alert:** logging without monitoring is archival, not
  defense. Detection content (rules, correlations, thresholds) is what turns
  records into response.
- **Integrity matters:** append-only or tamper-evident storage keeps the
  audit trail credible in an investigation.

## How this knowledge base uses it

Motivates the platform's structured logging conventions, the hash-chained
audit trail, and the pairing of every log-producing surface with detection
content (Sigma rules + correlations) rather than logging alone.

*This entry is an original summary; consult the authoritative source above
for the complete category description and prevention guidance.*
