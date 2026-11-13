# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Local IANUA Command Center views using plain-text widgets for imported data."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import streamlit as st

from correlation import CorrelationError
from dashboard.lab_soc import MAX_EVENTS, soc_snapshot
from store import StoreError
from store.lab_pci import (
    PCI_REQUIREMENTS,
    PCI_SOURCE,
    evidence_rows,
    link_evidence,
    weekly_scorecard,
)
from store.lab_phishing import campaign_metrics, record_campaign
from store.lab_vulnerabilities import (
    MAX_SCAN_LENGTH,
    LabInputError,
    advance,
    finding_rows,
    import_scan,
    lab_database,
)


def _vulnerabilities(db: sqlite3.Connection) -> None:
    st.subheader("Vulnerability management")
    st.caption("Import normalized scan data from an authorized lab. Use redacted aliases only.")
    with st.expander("Import a lab scan"), st.form("lab_scan_import"):
        raw = st.text_area("Version 1 lab scan JSON", height=160, max_chars=MAX_SCAN_LENGTH)
        if st.form_submit_button("Import scan"):
            st.success(
                "Scan imported."
                if import_scan(db, raw, recorded_at=datetime.now(UTC))
                else "Scan already imported."
            )
    rows = finding_rows(db)
    if not rows:
        st.info("Import a scan with a failed check to open a finding.")
        return
    st.dataframe(rows, width="stretch", hide_index=True)
    by_key = {(row["asset"], row["check_id"]): row for row in rows}
    selected = st.selectbox("Finding", list(by_key), format_func=" / ".join)
    row = by_key[selected]
    state = row["state"]
    if state == "Verified":
        st.success("Rescan verified. Link the reviewed evidence in PCI DSS Evidence.")
        return
    with st.form(f"lab_finding_{row['asset']}:{row['check_id']}:{row['revision']}"):
        owner = ticket = remediated_at = rescan = ""
        if state == "Open":
            owner = st.text_input("Owner alias", max_chars=64)
            ticket = st.text_input("Remediation ticket alias", max_chars=64)
            action = "Assign finding"
        elif state == "Assigned":
            remediated_at = st.text_input("Remediated at (ISO 8601 with timezone)", max_chars=40)
            action = "Record remediation"
        else:
            rescan = st.text_input("Comparable rescan ID", max_chars=64)
            action = "Verify rescan"
        if st.form_submit_button(action):
            advance(
                db,
                row["asset"],
                row["check_id"],
                row["revision"],
                recorded_at=datetime.now(UTC),
                owner=owner,
                ticket=ticket,
                remediated_at=remediated_at,
                rescan=rescan,
            )
            st.rerun()


def _pci(db: sqlite3.Connection) -> None:
    st.subheader("PCI DSS v4.0.1 evidence")
    st.caption("Lab evidence mappings support practice and portfolio review.")
    st.link_button("PCI SSC standard and testing procedures", PCI_SOURCE)
    st.dataframe(
        [
            {"Requirement": key, "Topic": title, "Lab review procedure": procedure}
            for key, (title, procedure) in PCI_REQUIREMENTS.items()
        ],
        width="stretch",
        hide_index=True,
    )
    verified = {
        (row["asset"], row["check_id"]): row
        for row in finding_rows(db)
        if row["state"] == "Verified"
    }
    if verified:
        chosen = st.selectbox("Verified finding", list(verified), format_func=" / ".join)
        row = verified[chosen]
        with st.form(f"lab_pci_{row['asset']}:{row['check_id']}:{row['revision']}"):
            requirement = st.selectbox("Requirement", list(PCI_REQUIREMENTS))
            evidence_id = st.text_input("Reviewed evidence reference", max_chars=64)
            reviewer = st.text_input("Reviewer alias", max_chars=64)
            if st.form_submit_button("Record evidence review"):
                link_evidence(
                    db,
                    asset=row["asset"],
                    check=row["check_id"],
                    revision=row["revision"],
                    requirement=requirement,
                    evidence_id=evidence_id,
                    reviewer=reviewer,
                    reviewed_at=datetime.now(UTC),
                )
                st.success("Evidence reference recorded.")
    else:
        st.info("Verify a rescan to link a reviewed evidence reference.")
    rows = evidence_rows(db)
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    st.subheader("Weekly lab scorecard")
    st.caption("Goal → Discovery → Strategy → Execution → Verification → Correction → Completion")
    day = st.date_input("Choose a day in the reporting week (UTC)", datetime.now(UTC).date())
    monday = day - timedelta(days=day.weekday())
    st.caption(f"{monday} to {monday + timedelta(days=6)} (UTC, inclusive)")
    st.dataframe(
        [{"Metric": name, "Count": count} for name, count in weekly_scorecard(db, monday).items()],
        width="stretch",
        hide_index=True,
    )
    st.link_button(
        "Reproducible IANUA case studies",
        "https://github.com/IRsoctierDT/IANUA/tree/main/docs/case-studies",
    )


@st.fragment(run_every="30s")
def _soc(root: Path) -> None:
    st.subheader("SOC operations")
    st.caption("Reads IANUA's local event store. Refreshes every 30 seconds.")
    hours = st.selectbox("Source-time window", [1, 6, 24, 168], index=2, format_func=str)
    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)
    st.caption(f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC (end exclusive)")
    try:
        snapshot = soc_snapshot(root, start.timestamp(), end.timestamp())
    except FileNotFoundError:
        st.info("No local event store. Run the authorized lab collector to populate this view.")
        return
    except (StoreError, CorrelationError, sqlite3.Error, OSError):
        st.error("The local event store or correlation result is unavailable.")
        return
    st.caption("Source: IANUA event store · Owner: local SOC operator")
    if snapshot.last_ingested is None:
        st.metric("Last ingestion", "Unavailable")
    else:
        last = datetime.fromtimestamp(snapshot.last_ingested, UTC)
        st.metric("Last ingestion (UTC)", last.strftime("%Y-%m-%d %H:%M:%S"))
    if snapshot.limited:
        st.warning(f"The view reached its {MAX_EVENTS}-event limit. Choose a shorter window.")
    if snapshot.counts:
        st.bar_chart(
            [{"Source": source, "Events": count} for source, count in snapshot.counts.items()],
            x="Source",
            y="Events",
            horizontal=True,
        )
    else:
        st.info("No dated events in this reporting window.")
    if snapshot.incidents:
        st.dataframe(
            [
                {
                    "Score": i.score,
                    "Events": i.event_count,
                    "Domains": ", ".join(i.domains),
                    "Vendors": ", ".join(i.vendors),
                    "Reason": "; ".join(i.reasons),
                    "Event references": ", ".join(i.event_ids[:5]),
                }
                for i in snapshot.incidents
            ],
            width="stretch",
            hide_index=True,
        )


def _phishing(db: sqlite3.Connection) -> None:
    st.subheader("Phishing simulation")
    st.caption("Use campaign totals from authorized lab simulations. Keep participant data out.")
    today = datetime.now(UTC).date()
    with st.expander("Record a campaign"), st.form("lab_phishing_campaign"):
        campaign = st.text_input("Campaign alias", max_chars=64)
        owner = st.text_input("Campaign owner alias", max_chars=64)
        start = st.date_input("Campaign start", today)
        end = st.date_input("Campaign end", today)
        stamp = st.text_input("Source snapshot time (ISO 8601 with timezone)", max_chars=40)
        delivered = st.number_input("Unique messages delivered", min_value=0, step=1)
        reported = st.number_input("Unique messages reported", min_value=0, step=1)
        handled = st.number_input("Reports with measured response time", min_value=0, step=1)
        minutes = st.number_input("Total measured response minutes", min_value=0, step=1)
        if st.form_submit_button("Save campaign"):
            record_campaign(
                db,
                campaign=campaign,
                owner=owner,
                start=start,
                end=end,
                source_at=stamp,
                delivered=delivered,
                reported=reported,
                handled=handled,
                response_minutes=minutes,
            )
            st.success("Campaign recorded.")
    since = st.date_input("Reporting period start", today - timedelta(days=30))
    until = st.date_input("Reporting period end", today)
    rows, rate, minutes_avg = campaign_metrics(db, since, until)
    st.metric("Reporting rate", "Unavailable" if rate is None else f"{rate:.1%}")
    st.metric(
        "Mean response time", "Unavailable" if minutes_avg is None else f"{minutes_avg:.1f} min"
    )
    st.caption("Reports ÷ delivered messages. Total response minutes ÷ timed reports.")
    if rows:
        st.dataframe([dict(row) for row in rows], width="stretch", hide_index=True)
    else:
        st.info("No campaigns fall entirely within the reporting period.")


def render_lab_command_center(root: Path) -> None:
    """Render the selected lab view inside IANUA's existing loopback dashboard."""
    st.subheader("Lab Command Center")
    if st.get_option("server.address") not in ("127.0.0.1", "::1"):
        st.error("The Lab Command Center requires an explicit loopback bind.")
        return
    st.caption("Single-operator workspace for synthetic and redacted lab data.")
    view = st.radio(
        "Workspace",
        ["Vulnerability Management", "PCI DSS Evidence", "SOC Operations", "Phishing"],
        horizontal=True,
        key="lab_command_center_view",
    )
    if view == "SOC Operations":
        _soc(root)
        return
    try:
        with lab_database(root) as db:
            if view == "Vulnerability Management":
                _vulnerabilities(db)
            elif view == "PCI DSS Evidence":
                _pci(db)
            else:
                _phishing(db)
    except LabInputError as exc:
        st.error(str(exc))
    except (StoreError, sqlite3.Error, OSError):
        st.error("The lab workspace could not be opened or updated.")
