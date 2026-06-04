# Security Policy

## Supported Versions

The following versions currently receive security updates:

| Version | Supported |
|----------|-----------|
| v1.x | Yes |
| v0.x | No |

## Reporting a Vulnerability

If you discover a security vulnerability in the AI Operator Cyber Command Center, please report it responsibly.

### Preferred Reporting Method

Open a private GitHub Security Advisory if available.

If GitHub Security Advisories are not enabled, submit a confidential report through the repository owner.

### Information to Include

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Affected components
- Suggested remediation (if known)

### Response Goals

The project aims to:

- Acknowledge reports within 7 days
- Investigate and validate findings
- Develop and test mitigations
- Publish fixes in a future release

### Scope

Examples include:

- Authentication bypass
- Sensitive data exposure
- Command injection
- Remote code execution
- Dependency vulnerabilities
- Unsafe file handling
- Improper access controls

### Out of Scope

The following are generally not considered security vulnerabilities:

- Cosmetic issues
- Documentation errors
- Denial-of-service requiring local administrative access
- Issues requiring modification of source code by the reporter

## Disclosure Policy

Please do not publicly disclose security issues until remediation has been completed and users have had an opportunity to update.

## Security Best Practices

Contributors should:

- Never commit secrets, API keys, or tokens
- Use virtual environments for development
- Validate user input
- Keep dependencies updated
- Run tests before submitting changes
- Follow the principle of least privilege