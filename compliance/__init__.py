"""Compliance layer — continuous, Vanta-style posture monitoring for IANUA.

Runs a registry of deterministic, offline control checks against the
repository's own security posture, maps each control to public frameworks
(NIST CSF 2.0, SOC 2, ISO 27001:2022), records tamper-evident evidence, and
feeds both the dashboard's Compliance tab and the published trust page.

Security considerations: every check is read-only and network-free; evidence
records never contain secrets, environment values, or absolute paths outside
the repository root (AGENTS.md §5).
"""
