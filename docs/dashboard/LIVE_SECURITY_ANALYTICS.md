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
