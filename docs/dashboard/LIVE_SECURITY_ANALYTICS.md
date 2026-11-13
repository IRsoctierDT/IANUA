# IANUA security analytics dashboards — initial integration

This feature adds a native multipage Streamlit view at
`dashboard/pages/1_Security_Analytics.py`. Launch using the existing command:

```bash
pip install -e ".[dashboard]"
streamlit run dashboard/app.py --server.address 127.0.0.1
```

The page refreshes every 15 seconds using Streamlit fragments. **Only the SOC
view reads the existing append-only IANUA event store.** It does not run a
collector or claim new events are being ingested. The other three views read
explicitly configured local CSV snapshots, so they are not live connectors.

## Local snapshot contracts

Place files in the existing gitignored `data/analytics/` directory:

- `phishing.csv`: `department,month,clicks,source_timestamp,data_owner`
- `vulnerabilities.csv`: `asset_id,cvss,exploitability,exposure,asset_criticality,pci_scope,status,source_timestamp`
- `pci_evidence.csv`: `requirement,evidence_id,test_procedure,owner,ticket,status,source_timestamp`

These are input contracts, not completed upstream integrations. Never use
fictional CSV records to imply live audit or PCI compliance status. The
dashboard refuses absent, oversized, or malformed CSV snapshots. Each snapshot
is capped at 2 MB / 2000 rows; SOC queries are capped at 500 events.

## Remaining work before production

1. Add server-side authentication, RBAC and per-dataset authorization. The
   existing Streamlit app is local-only and must not be exposed publicly.
2. Wire authorized phishing simulation, scanner and PCI evidence producers to
   validated ingestion pipelines with provenance, reporting periods and owners.
3. Add schema validation and quality gates for numeric and date fields.
4. Implement contextual vulnerability scoring and detailed PCI DSS v4.0.1
   sub-requirement evidence mappings using the authoritative standard.
5. Add verified source freshness SLIs and latency measurements.
6. Add CI integration tests with a populated event-store fixture and run
   existing repository quality gates.

## Test

```bash
pytest -q tests/unit/test_live_analytics.py
```

No write operation, network fetch, or automated response action is added.

## Governance and access additions

The dashboard now validates dataset provenance and freshness before calculating
phishing totals, vulnerability priorities or PCI evidence counts. Invalid rows
suppress derived metrics and show an explicit data-quality failure. The
`dashboard/analytics_governance.py` module defines metric semantics, required
columns, numeric ranges and source timestamp checks. A 24-hour freshness target
is illustrative and must be calibrated per source.

Contextual vulnerability priority is a separate **0–100 heuristic**:
35% normalized CVSS, 25% exploitability (1–4), 15% exposure (1–3),
15% asset criticality (1–4), and 10% PCI-scope flag. This is not an official
PCI DSS formula or a substitute for an approved risk analysis.

For PCI evidence, the `requirement` field accepts detailed identifiers such
as `8.3.1`; the `test_procedure`, `owner`, `ticket` and `evidence_id`
columns are mandatory. This is a traceability record, not an official
Requirements and Testing Procedures reproduction.

**Authorization:** `IANUA_ANALYTICS_CLASSIFICATION` defaults to `synthetic`.
Non-public classification (`internal` or `confidential`) requires an
authenticated Streamlit OIDC identity and an explicit server-side role mapping
under `[analytics_roles]` in Streamlit secrets. Example:

```toml
[analytics_roles]
"analyst@example.test" = "analyst"
"reviewer@example.test" = "compliance"
```

Configure Streamlit OIDC per its official documentation, with an organizational
IdP and MFA. Never commit client secrets. Do not use demo mode with non-public
records; no application-only control can safely enforce that prohibition if
an operator deliberately misclassifies a dataset.

**Important:** live source integrations for phishing platforms, vulnerability
scanners and PCI evidence systems remain pending. The current views consume
local exported snapshots, and 15-second UI refresh does not make them live.
