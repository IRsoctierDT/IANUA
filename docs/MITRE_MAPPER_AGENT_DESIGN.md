# MITRE Mapper Agent Design

## Purpose

Map SOC findings to likely MITRE ATT&CK techniques.

## Inputs

- Event type
- Log text
- Indicators
- Severity
- SOC Analyst Agent output

## Outputs

- Likely MITRE tactic
- Likely MITRE technique
- Confidence level
- Evidence
- Recommended investigation step

## Safety Boundary

This agent maps defensive observations only. It does not execute attacks, scans, or exploitation.

## First Supported Mappings

| SOC Event | MITRE Tactic | MITRE Technique |
|---|---|---|
| Authentication failure | Credential Access | Brute Force |
| Suspicious SSH login | Initial Access | Valid Accounts |
| IDS alert | Detection-dependent | Requires review |
| Firewall block | Reconnaissance or Command and Control | Requires review |