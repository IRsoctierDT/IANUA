# IANUA Lab Command Center

**Purpose** · Practice vulnerability triage, rescan verification, PCI DSS evidence review,
SOC monitoring, and phishing reporting in the existing IANUA dashboard.
**Risk level** · Local lab. Use synthetic or redacted records and pseudonymous aliases.
**Skill level required** · Security analyst or lab operator.
**Deployment complexity** · The existing loopback Streamlit app and local SQLite.

## Run the workflow

From the repository root, run the existing dashboard command.

```sh
streamlit run dashboard/app.py --server.address 127.0.0.1
```

Open **Lab Command Center**, enable the workspace, and select a view.

1. **Vulnerability Management.** Import the baseline, assign an owner and a ticket, and
   record the time the fix was applied. Import the comparable rescan, then verify it by
   its scan ID. A missing check, an incomplete check, a different scanner or profile, or a
   pass at or before remediation cannot close a finding. A failure at or after the candidate
   pass prevents verification. A newly imported failure at or after the verified rescan
   reopens the finding and retains its historical evidence.
2. **PCI DSS Evidence.** Select a verified finding, choose the applicable requirement,
   and record the evidence reference and reviewer alias after checking the source artifact.
   The link captures the corresponding finding revision, ticket and rescan fingerprint.
   The operator determines applicability and evidence sufficiency. See the
   [PCI SSC v4.0.1 standard and testing procedures](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss).
3. **SOC Operations.** Choose the lookback and inspect telemetry volume, last ingestion,
   and correlation candidates. The view refreshes every 30 seconds while selected. It reads
   the event store already populated by IANUA's lab collector and pipeline. Displayed
   incident groups are recomputed for the selected window.
4. **Phishing.** Record authorized simulation aggregates with a campaign owner, inclusive
   UTC dates and source snapshot time. For each simulated message use one delivery and,
   where applicable, its first report. For timed reports, measure from report receipt
   to the first documented analyst response. Select the reporting period.

## Scan import dictionary

Use version 1 normalized JSON. For an actual authorized lab report, copy only
allowlisted fields and compute the SHA-256 of the original report locally. A declared
fingerprint supports manual provenance checks. The app never reads or verifies that
original file. Retain originals in your approved local evidence location.

| Field | Definition |
| --- | --- |
| `version`, `scan_id` | Integer `1` and a unique lab alias. Aliases are 1 to 64 ASCII letters, digits, underscores or hyphens, starting with a letter or digit. |
| `scanner`, `profile` | Stable scanner and equivalent coverage profile aliases. Include relevant scan vantage and authentication settings in the local profile definition. |
| `timestamp`, `sha256` | Source scan completion time in ISO 8601 with timezone and lowercase SHA-256 of the original report. |
| `checks[].asset`, `checks[].check` | Stable asset and scanner check aliases. Each pair may occur once per snapshot. |
| `checks[].outcome` | `failed`, `passed` or `incomplete`. An absent pair supplies no evidence. |
| `checks[].cvss` | Scanner-reported CVSS in the range 0 to 10, or `null`. |
| `checks[].exploit`, `checks[].exposed` | Boolean exploit availability and exposure, or `null` for unknown. |
| `checks[].criticality`, `checks[].scope` | `low`, `medium`, `high` and `out-of-scope`, `connected`, `cde`, respectively. |

Synthetic baseline for a practice run. The fingerprint here is a placeholder for the exercise.

```json
{
  "version": 1,
  "scan_id": "baseline-01",
  "scanner": "lab-scanner",
  "profile": "internal-authenticated",
  "timestamp": "2025-01-01T12:00:00Z",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "checks": [{
    "asset": "lab-web",
    "check": "lab-check-01",
    "outcome": "failed",
    "cvss": 7.5,
    "exploit": true,
    "exposed": true,
    "criticality": "high",
    "scope": "cde"
  }]
}
```

Assign `lab-owner` and `LAB-01`, then record remediation at `2025-01-02T12:00:00Z`.
Copy the baseline for a synthetic rescan. Change the scan ID to `rescan-01`, timestamp to
`2025-01-03T12:00:00Z`, the outcome to `passed`, and each fingerprint character from
`a` to `b`. Import it and verify `rescan-01`. Link a reviewed reference to `11.3.1`
for the exercise.

## Metric definitions

| Metric | Definition and reporting period |
| --- | --- |
| Lab priority score | Existing agent CVSS band base (20, 45, 70 or 90), plus 15 for exploit availability and 10 for exposure, plus 0/5/10 for asset criticality and 0/5/10 for PCI scope, capped at 100. Missing CVSS leaves the score unavailable. Missing exploit or exposure makes it provisional. These weights are lab policy choices. |
| Weekly finding activity | Distinct asset/check pairs per recorded workflow state from Monday 00:00 UTC to the following Monday, exclusive. Evidence links count distinct reviewed links by review time. |
| SOC activity | Stored events in the selected half-open source-time window, grouped by source and vendor. Undated events are excluded. If capped, the newest 500 by ingestion order are shown and totals describe that sample. Last ingestion is store-wide. |
| Reporting rate | Total unique simulated messages reported divided by total unique simulated messages delivered across campaigns wholly within the selected dates. A zero denominator is unavailable. |
| Mean response time | Total elapsed response minutes divided by reports with measured responses over the same campaigns. A zero denominator is unavailable. |

## Local storage and boundaries

The workspace stores validated records at `data/command-center/lab.sqlite3` under the
existing gitignored lab root. Use the same OS account for the single-operator workflow.
The dashboard requires an explicit loopback bind. Shared access or non-public
organizational data requires verified server-side identity, roles, and audit logging
before use. A loopback bind does not distinguish multiple local users or forwarded clients.

Scan identities and lifecycle revisions are checked transactionally. The local transition
history supports review, but has no independently verified tamper evidence. Preserve the
database and original reports according to your lab evidence plan. The SOC view uses a
read-only connection to the existing event store. Case studies are accessible from the
PCI evidence view. Career and certification tracking remain in the PCI DSS Career Command Center.

The changes use existing dependencies. To roll back the dashboard feature, revert its
commit and preserve the workspace database for later review.
