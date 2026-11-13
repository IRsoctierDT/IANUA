# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Live analytics page for the existing IANUA Streamlit command center.

Local-first, read-only and deliberately explicit about missing or stale feeds.
"""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from dashboard.live_analytics import domain_counts, load_events, load_snapshot, numeric_counts

ROOT = Path(__file__).resolve().parents[2]
st.set_page_config(page_title="IANUA | Security Analytics", layout="wide")
st.title("IANUA · Security Analytics")
st.caption("Read-only local dashboards. A refresh is not proof that a source is current.")
st.warning(
    "Local lab only. Do not expose this page on a public interface or load "
    "non-public organizational records before server-side authentication, "
    "authorization, and data classification are implemented."
)


def _chart(rows: list[dict[str, str]], column: str, title: str) -> None:
    """Render counts or an explicit missing-field warning."""
    if not rows:
        st.info("No records available; no zero-risk inference can be made.")
    elif column not in rows[0]:
        st.warning(f"Missing required field: {column}")
    else:
        st.subheader(title)
        st.bar_chart(numeric_counts(rows, column))


@st.fragment(run_every="15s")
def refresh() -> None:
    """Re-read bounded local data every 15 seconds; never start collectors."""
    st.caption("Display refresh: every 15 seconds. Source timestamps govern freshness.")
    soc, soc_status = load_events(ROOT)
    phishing, phishing_status = load_snapshot(ROOT, "phishing")
    vulnerabilities, vuln_status = load_snapshot(ROOT, "vulnerabilities")
    pci, pci_status = load_snapshot(ROOT, "pci")

    tabs = st.tabs(["SOC telemetry", "Phishing audit", "Vulnerability risk", "PCI DSS evidence"])
    with tabs[0]:
        st.write(f"**Source:** {soc_status} · **Rows:** {len(soc)} (maximum 500)")
        if soc:
            st.bar_chart(domain_counts(soc))
            st.caption("Counts represent a bounded recent-event sample, not incident totals.")
            st.dataframe(soc, hide_index=True, use_container_width=True)
        else:
            st.info("No verified live events available. Check the configured collector and event store.")
    with tabs[1]:
        st.write(f"**Source:** {phishing_status}")
        st.caption("Required CSV: department, month, clicks, source_timestamp, data_owner.")
        _chart(phishing, "department", "Records by department")
        if phishing:
            st.dataframe(phishing, hide_index=True, use_container_width=True)
            st.warning("Record counts are not click rates; provide delivered-message denominators.")
    with tabs[2]:
        st.write(f"**Source:** {vuln_status}")
        st.caption("Required CSV: asset_id, cvss, exploitability, exposure, asset_criticality, pci_scope, status, source_timestamp.")
        _chart(vulnerabilities, "status", "Findings by remediation status")
        if vulnerabilities:
            st.dataframe(vulnerabilities, hide_index=True, use_container_width=True)
            st.warning("CVSS alone is not risk. Contextual prioritization requires validated inputs.")
    with tabs[3]:
        st.write(f"**Source:** {pci_status}")
        st.caption("Required CSV: requirement, evidence_id, test_procedure, owner, ticket, status, source_timestamp.")
        _chart(pci, "status", "Evidence records by status")
        if pci:
            st.dataframe(pci, hide_index=True, use_container_width=True)
        st.warning("This is evidence tracking, not a PCI DSS v4.0.1 assessment or compliance attestation.")


refresh()
