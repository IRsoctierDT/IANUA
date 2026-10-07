# Streamlit SOC Dashboard

## Purpose

A local web interface for IANUA SOC analysis and review of scanner reports.
The dashboard runs on a Python server; GitHub Pages serves documentation only.

## Run

```bash
pip install -e ".[dashboard]"
streamlit run dashboard/app.py
```

Keep it local or in a private Codespace. Authentication and multi-user isolation
must be designed before exposing the dashboard publicly.

## Scan report review

The **Scan Reports** tab accepts IANUA-Broker's JSON scan reports, schema 1.0
or 1.1. Run the scanner locally, without `--show-secrets`:

```bash
mcpscan scan --root /path/to/your/project --json /path/to/private/report.json
```

The scanner's finding gate can return a nonzero exit code while producing a
valid report; that is a scan finding, not necessarily an export failure.
Review the report before uploading it. Redacted reports can still contain
private paths, server identifiers, and prose. The dashboard cannot certify
that arbitrary uploaded text contains no secrets.

In **Scan Reports**, acknowledge the upload notice and choose a current report.
Review findings, filter by severity and server, search the report, and inspect
remediation guidance. Reports are treated as data: location paths are never
opened and their content does not launch scans or execute commands. Unsupported
schemas, malformed JSON, oversized inputs, and masked-secret output are rejected.

Add a baseline report to compare it with the current report. Comparison uses
server, check ID, and finding location; it shows new, unchanged, changed, and
resolved findings. Missing findings in an incomplete current report are labelled
**not observed**, rather than resolved. These are uploaded snapshots, not a live
assessment or authorization to act on a target.

Uploads remain in the current Streamlit session; the new feature does not save
or send them to another service. Clearing or replacing an invalid upload clears
its previous result. On a hosted deployment, uploading necessarily sends the
file to that deployment's Streamlit server.

For a safe walkthrough, upload the fictional reports
[sample-scan-after.json](sample-scan-after.json) as current and
[sample-scan-before.json](sample-scan-before.json) as baseline. The examples
contain no credential values and were generated with Broker's JSON renderer.
They show one new tool-scope finding, one resolved credential finding, and one
unchanged pinning finding.

## Other capabilities

- Single-event and batch SOC analysis with bundled scenarios.
- Detection coverage and intelligence, knowledge-base search, and system health.
- Incident Markdown and PDF reports, approval review, and compliance evidence.

## Limitations

The report-review feature does not schedule scans, initiate remote scans,
provide cross-session history, authenticate users, or publish reports. Those
features require a separate backend and an authorization design.
