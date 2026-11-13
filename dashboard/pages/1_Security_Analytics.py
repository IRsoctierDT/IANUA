# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Live analytics page for the existing IANUA Streamlit command center.

Local-first, read-only and deliberately explicit about missing or stale feeds.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dashboard.analytics_access import authorized, classification, identity_from_streamlit
from dashboard.analytics_governance import METRIC_DEFINITIONS, quality_report, risk_score

import streamlit as st

from dashboard.live_analytics import domain_counts, load_events, load_snapshot, numeric_counts

ROOT = Path(__file__).resolve().parents[2]
st.set_page_config(page_title="IANUA | Security Analytics", layout="wide")
st.title("IANUA · Security Analytics")
st.caption("Read-only local dashboards. A refresh is not proof that a source is current.")
# OIDC role assignments are server-side Streamlit secrets, never user input.
try:
    assignments = dict(st.secrets.get("analytics_roles", {}))
except (FileNotFoundError, KeyError, RuntimeError):
    assignments = {}
data_class = classification()
user_email = identity_from_streamlit(st.user)
if not authorized(classification=data_class, identity=user_email, assignments=assignments):
    st.error("Access denied. Non-public analytics require OIDC sign-in and an explicit role.")
    st.stop()
if data_class == "synthetic":
    st.warning("SYNTHETIC DEMO ONLY. Never place organizational data in this mode.")
else:
    st.caption(f"Authenticated analytics role for {user_email}; classification: {data_class}")



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

    now = datetime.now(timezone.utc)
    snapshots = {"phishing": phishing, "vulnerabilities": vulnerabilities, "pci": pci}
    problems = {name: quality_report(name, rows, now=now) for name, rows in snapshots.items()}
    tabs = st.tabs(["SOC telemetry", "Phishing audit", "Vulnerability risk", "PCI DSS evidence", "Data quality"])
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
        if problems["phishing"]:
            st.error("Phishing source failed validation; metrics suppressed.")
        else:
            st.metric("Recorded clicks", sum(int(row["clicks"]) for row in phishing))
            _chart(phishing, "department", "Records by department")
        if phishing:
            st.dataframe(phishing, hide_index=True, use_container_width=True)
            st.warning("Record counts are not click rates; provide delivered-message denominators.")
    with tabs[2]:
        st.write(f"**Source:** {vuln_status}")
        st.caption("Required CSV: asset_id, cvss, exploitability, exposure, asset_criticality, pci_scope, status, source_timestamp.")
        if problems["vulnerabilities"]:
            st.error("Vulnerability source failed validation; metrics suppressed.")
        else:
            scored = [{**row, "contextual_risk": risk_score(row)} for row in vulnerabilities]
            st.metric("Open findings", sum(row["status"] in {"open", "in_progress"} for row in scored))
            st.dataframe(sorted(scored, key=lambda row: row["contextual_risk"], reverse=True),
                         hide_index=True, use_container_width=True)
            _chart(vulnerabilities, "status", "Findings by remediation status")
        if vulnerabilities:
            st.dataframe(vulnerabilities, hide_index=True, use_container_width=True)
            st.warning("CVSS alone is not risk. Contextual prioritization requires validated inputs.")
    with tabs[3]:
        st.write(f"**Source:** {pci_status}")
        st.caption("Required CSV: requirement, evidence_id, test_procedure, owner, ticket, status, source_timestamp.")
        if problems["pci"]:
            st.error("PCI evidence source failed validation; metrics suppressed.")
        else:
            _chart(pci, "status", "Evidence records by status")
        if pci:
            st.dataframe(pci, hide_index=True, use_container_width=True)
        st.warning("This is evidence tracking, not a PCI DSS v4.0.1 assessment or compliance attestation.")
    with tabs[4]:
        st.subheader("Data dictionary and metric definitions")
        st.json(METRIC_DEFINITIONS)
        for name, errors in problems.items():
            st.write(f"**{name}:** " + ("validation passed" if not errors else f"{len(errors)} issue(s)"))
            if errors:
                st.error("; ".join(errors[:10]))
        st.caption("Every snapshot must provide source timestamp, reporting period, owner and source system.")


refresh()
