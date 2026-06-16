# Security Policy

## Scope & intent
This project is for **defensive cybersecurity and authorized lab use only**. It must not be
used to scan, attack, exploit, or access systems you do not own or have written
authorization to test. See [AGENTS.md](./AGENTS.md) §5.

## Reporting a vulnerability
Report privately to the maintainer (do not open a public issue for security defects).
Include: affected component, reproduction steps, impact, and any suggested remediation.
You will receive an acknowledgement; please allow reasonable time for a fix before any
disclosure.

## Handling of sensitive data
Logs, legal documents, client information, credentials, and PII are sensitive by default.
They are never committed, never logged in plaintext, and never sent to external endpoints.

## Secrets
No secrets in source, tests, fixtures, comments, or logs. Configuration keys are documented
in `.env.example`; real values live only in environment/secret stores. Secret scanning runs
in pre-commit and CI.
