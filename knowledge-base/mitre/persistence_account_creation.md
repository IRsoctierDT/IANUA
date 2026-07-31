# MITRE ATT&CK — Account Creation & Manipulation for Persistence

**Framework:** MITRE ATT&CK (Enterprise), Persistence & Privilege Escalation
**Techniques:** T1136.001 (Create Account: Local Account), T1098 (Account
Manipulation)
**Authoritative sources:**
<https://attack.mitre.org/techniques/T1136/001/> ·
<https://attack.mitre.org/techniques/T1098/>

> Adversaries create local accounts, or add privileges to accounts they
> control, to keep access that survives password resets and session cleanup.
> Either event alone is routine administration; the *sequence* — a fresh
> account promptly gaining privileged-group membership — is the classic
> persistence chain and a high-confidence signal.

## Key points

- **T1136.001 — Create Account: Local Account.** Watch `useradd`/account
  provisioning events. Baseline expected onboarding; alert on creations
  outside approved processes, at unusual hours, or by unexpected actors.
- **T1098 — Account Manipulation.** Watch additions to privileged groups
  (`sudo`, `wheel`, `admin`), credential changes on service accounts, and
  modifications to authentication material. Privileged-group membership is a
  durable escalation primitive.
- **Detection strategy is correlation:** the create-then-privilege chain on
  the same host and account within a short window is far stronger than
  either event alone — this platform ships that exact Sigma correlation
  (`account_created_then_privileged`).
- **Response:** verify against change management; if unapproved, disable the
  account, review the creating account's session, and treat the host as
  compromised pending review.

## How this knowledge base uses it

Grounds the "account creation" (T1136.001) and "privileged group addition"
(T1098) event types in the SOC pipeline and their corresponding Sigma rules
and correlation.

*This entry is an original summary; consult the authoritative sources above
for complete and current technique detail.*
