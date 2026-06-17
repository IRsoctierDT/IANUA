# OWASP Top 10:2025 — Web Application Security Risks

**Framework:** OWASP Top 10
**Edition:** 2025 (final release January 2026; supersedes the 2021 edition)
**Authoritative source:** <https://owasp.org/Top10/2025/>

> The OWASP Top 10 is a community awareness document ranking the most critical
> security risks to web applications, derived from contributed vulnerability data
> and an industry survey. It is a *prioritization* aid, not an exhaustive checklist.

## The 2025 categories

| Rank | Category | Note |
|------|----------|------|
| A01:2025 | **Broken Access Control** | Remains #1. Server-Side Request Forgery (SSRF) is now absorbed here. |
| A02:2025 | **Security Misconfiguration** | Rose from #5 (2021) to #2 as configurations grow more complex. |
| A03:2025 | **Software Supply Chain Failures** | **New** — expands the former "Vulnerable and Outdated Components" to cover the build, distribution, and update pipeline. |
| A04:2025 | **Cryptographic Failures** | Weak, missing, or misapplied cryptography exposing data. |
| A05:2025 | **Injection** | SQL, NoSQL, OS command, LDAP, and similar; includes most XSS. |
| A06:2025 | **Insecure Design** | Flaws in architecture and threat modeling, not just implementation. |
| A07:2025 | **Authentication Failures** | Renamed; broken identity, session, and credential handling. |
| A08:2025 | **Software or Data Integrity Failures** | Unverified updates, insecure deserialization, untrusted CI/CD. |
| A09:2025 | **Security Logging & Alerting Failures** | Renamed; insufficient detection, logging, and response signal. |
| A10:2025 | **Mishandling of Exceptional Conditions** | **New** — improper error handling, failing open, and logic errors (24 CWEs). |

## What changed from 2021

- **Two new categories:** Software Supply Chain Failures (A03) and Mishandling of
  Exceptional Conditions (A10).
- **SSRF** (a standalone A10 in 2021) folded into **Broken Access Control**.
- Several re-rankings and renames (e.g. "Identification and Authentication
  Failures" → "Authentication Failures").

## How this knowledge base uses it

Supports application-security analysis, secure-code review, and AI-assisted
vulnerability triage. When an agent classifies a web-app finding, it should map it
to the relevant A0x:2025 category and cite the official entry.

> **Verify before relying on version-specific claims.** Editions change; confirm
> the current list at the authoritative source above.
