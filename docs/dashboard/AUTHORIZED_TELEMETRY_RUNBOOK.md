# Authorized telemetry integration: local-first runbook

## Scope and boundary

This integration is limited to the operator's authorized local laboratory.
It introduces **no listener, outbound API calls, remote scanner or background
daemon**. IANUA-Broker is not modified. A local export is a snapshot, not a
streaming connection; a 15-second Streamlit refresh only reloads the published
data. Production-grade multi-user ingestion requires a separate reviewed
architecture and authorization decision.

## SOC: existing continuous collection path

Use IANUA's already implemented collector and pipeline rather than a second
ingestion mechanism:

1. Configure only operator-owned local log paths in the existing collector
   configuration, following `docs/PRODUCTION_SOC_PLAN.md` and the collector
   runbook.
2. Invoke `python scripts/run_collector.py --help` to inspect supported
   configuration and dry-run options; do not invent CLI arguments.
3. Run the collector on an authorized fixture, then the scheduled pipeline
   using `python scripts/run_pipeline.py --help` for supported options.
4. Confirm the event-store database exists in `data/events/`. Open the
   Streamlit Security Analytics page and check the domain counts and event IDs.
5. Verify timestamps and compare event counts with collector results. An
   empty store or missing source is *unavailable*, not a clean bill of health.

## Phishing, vulnerability and PCI evidence imports

Place the approved CSV export in `data/imports/`, with one of the exact names
`phishing.csv`, `vulnerabilities.csv`, or `pci_evidence.csv`.
The source must be a regular file, not a symlink or hardlink. Do not commit
these files, especially when they contain sensitive data.

```bash
python -m scripts.publish_analytics phishing
python -m scripts.publish_analytics vulnerabilities
python -m scripts.publish_analytics pci
streamlit run dashboard/app.py --server.address 127.0.0.1
```

The publisher checks a declared schema, timestamp freshness (24 hours),
reporting periods, logical duplicates, risk factor ranges, statuses, and
source ownership fields. Only a fully valid file is atomically published to
`data/analytics/`; rejected replacements do not overwrite a prior accepted
snapshot. **A previously accepted snapshot can become stale** and should be
clearly distinguished from the latest import failure.

Required shared fields: `source_timestamp` (timezone-aware ISO-8601),
`data_owner`, `source_system`, `reporting_period_start`,
`reporting_period_end` (ISO dates). Dataset-specific columns are defined
in `dashboard/analytics_governance.py`.

### Operational acceptance tests

- Positive: a current authorized export is published and visible in the
  corresponding dashboard with the correct source metadata.
- Negative: invalid CSV, missing provenance, stale timestamps, unsafe
  symlinks, out-of-range CVSS or negative phishing clicks are rejected.
- Recovery: a rejected replacement leaves the last verified snapshot intact,
  but operators must not treat that older snapshot as current.
- SOC: a normalized event is present in the append-only store and visible
  without duplication after an at-least-once collector replay.
- Access: internal/confidential classifications require OIDC identity and a
  server-managed role; synthetic mode must never be used with private data.

### Verification commands

```bash
pytest -q tests/unit/test_live_analytics.py tests/unit/test_analytics_governance.py tests/integration/test_analytics_pipeline.py
ruff check dashboard/live_analytics.py dashboard/analytics_governance.py dashboard/analytics_access.py scripts/publish_analytics.py tests/integration/test_analytics_pipeline.py
```

## Known gaps

There is no direct phishing-provider API, vulnerability-scanner API, or PCI
evidence service connector. Those integrations require the approved vendor,
credential model, authorization scope, rate limits, retention rules, and a
reviewed outbound network boundary. Authentication applies to this analytics
page, not automatically to every legacy Streamlit tab. Do not deploy the
application on a public interface without a complete access-control review.
