from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import streamlit as st
from agents.orchestrator_agent import OrchestratorAgent
from agents.tools.ocsf import normalize as ocsf_normalize
from compliance.attestations import AttestationError, record, store_path
from compliance.attestations import load as load_attestations
from compliance.controls import ControlStatus
from compliance.engine import run_controls
from compliance.evidence import export_bundle, load_recent, record_run, verify_chain
from compliance.trends import score_history

from dashboard.compliance_view import (
    FRAMEWORK_DISCLAIMER,
    category_summary,
    control_rows,
    evidence_rows,
    framework_refs_line,
)
from dashboard.escalations import AuditChainError, load_chain_view
from dashboard.kb_search import search_kb_resilient
from dashboard.ollama_service import ensure_ollama_running
from dashboard.system_health import (
    get_git_tag,
    get_ollama_models,
    get_python_info,
    get_qdrant_collections,
)

st.set_page_config(
    page_title="IANUA",
    layout="wide",
)

st.title("IANUA")
st.caption(
    "AI operations platform — SOC automation, RAG pipelines, "
    "MITRE ATT&CK mapping, and agentic workflows for defensive cybersecurity."
)

st.sidebar.header("System Status")
st.sidebar.write("Model:", os.environ.get("LLM_MODEL", "qwen3.5:9b"))
st.sidebar.write("Vector DB: Qdrant")
st.sidebar.write("Mode: Local")

st.sidebar.subheader("Health Panel")
st.sidebar.write("Git Version:", get_git_tag())
st.sidebar.write("Python:", get_python_info())
st.sidebar.write("Qdrant Collections:", get_qdrant_collections())
st.sidebar.write("Ollama:", ensure_ollama_running())

with st.sidebar.expander("Ollama Models"):
    st.text(get_ollama_models())

agent = OrchestratorAgent()


@st.cache_data
def _load_navigator_layer() -> dict | None:
    """Return the committed ATT&CK Navigator layer, or None if absent.

    Read-only and fail-soft: a missing/unreadable layer degrades the tab to an
    informational note rather than erroring the app.
    """
    path = Path("docs/attack-navigator-layer.json")
    try:
        layer = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return layer if isinstance(layer, dict) else None


@st.cache_data
def _sigma_rule_count() -> int:
    """Count Sigma rule files in the corpus (display metric; fail-soft to 0)."""
    try:
        return len(list(Path("detections/sigma").glob("*.yml")))
    except OSError:
        return 0


(
    tab_soc,
    tab_batch,
    tab_coverage,
    tab_kb,
    tab_health,
    tab_reports,
    tab_approvals,
    tab_compliance,
) = st.tabs(
    [
        "SOC Workflow",
        "Batch Processing",
        "Detection Coverage",
        "Knowledge Base Search",
        "System Health",
        "Reports",
        "Pending Approvals",
        "Compliance",
    ]
)

with tab_compliance:
    st.subheader("Compliance Command Center")
    st.caption(
        "Continuous posture monitoring: automated controls evaluated against "
        "this repository, mapped to NIST CSF 2.0, SOC 2, and ISO 27001. " + FRAMEWORK_DISCLAIMER
    )
    repo_root = Path(__file__).resolve().parent.parent

    if st.button("Run controls & record evidence", key="compliance_run"):
        try:
            attestations = load_attestations(store_path(repo_root))
        except AttestationError as exc:
            # A malformed attestation file is a security event: surface it and
            # run without attestations rather than trusting it partially.
            st.error(f"Attestation store FAILED validation (ignored): {exc}")
            attestations = {}
        report = run_controls(repo_root, attestations=attestations)
        record_run(report, root=repo_root)
        st.session_state["compliance_report"] = report

    stored_report = st.session_state.get("compliance_report")
    if stored_report is None:
        st.info("Run the controls to evaluate the current posture.")
    else:
        col_score, col_pass, col_fail, col_manual = st.columns(4)
        col_score.metric("Posture score", f"{stored_report.score}%")
        col_pass.metric("Passing", f"{stored_report.passing}/{len(stored_report.automated)}")
        col_fail.metric("Failing", len(stored_report.failing))
        awaiting = sum(1 for r in stored_report.manual if r.status is ControlStatus.MANUAL)
        col_manual.metric("Awaiting attestation", awaiting)

        history = score_history(repo_root)
        if len(history) > 1:
            st.subheader("Posture trend")
            st.line_chart(
                {"score": [p.score for p in history]},
                x_label="recorded runs (chronological)",
                y_label="score %",
            )

        st.subheader("Framework coverage")
        for fw_rollup in stored_report.framework_rollups():
            st.write(f"**{fw_rollup.framework.value}** — {fw_rollup.passing}/{fw_rollup.total}")
            st.progress(fw_rollup.percent / 100)

        st.subheader("Controls by category")
        st.table(category_summary(stored_report))

        st.subheader("All controls")
        st.table(control_rows(stored_report))
        with st.expander("Framework references per control"):
            for result in stored_report.results:
                refs = framework_refs_line(stored_report, result.control.id)
                st.write(f"`{result.control.id}` {refs}")

        st.subheader("Evidence trail")
        chain = verify_chain(repo_root)
        if chain.entries == 0:
            st.info("No evidence chain yet — it starts with the first recorded run.")
        elif chain.intact:
            st.success(
                f"Evidence chain verified — {chain.entries} entries, signature: {chain.signature}."
            )
        else:
            # A broken chain is a security event, not a display glitch.
            st.error(f"Evidence chain FAILED verification: {chain.failure}")
        recent = load_recent(repo_root, limit=50)
        if recent:
            st.table(evidence_rows(recent))

        with st.expander("Record an attestation (manual controls)"):
            st.caption(
                "Attestations are written to the committed "
                "`compliance/attestations.json` — review and commit the change "
                "yourself; recording here never publishes anything."
            )
            manual_controls = [r.control for r in stored_report.manual]
            if not manual_controls:
                st.info("No manual controls in the registry.")
            else:
                att_control = st.selectbox(
                    "Control",
                    manual_controls,
                    format_func=lambda c: f"{c.id} — {c.title}",
                    key="att_control",
                )
                att_by = st.text_input("Attested by (name/role)", key="att_by")
                att_note = st.text_input(
                    "What was verified (per the control's hint)", key="att_note"
                )
                att_days = st.number_input(
                    "Valid for (days)", min_value=1, max_value=365, value=90, key="att_days"
                )
                if st.button("Record attestation", key="att_record"):
                    if not att_by.strip() or not att_note.strip():
                        st.warning("Name and verification note are both required.")
                    else:
                        from datetime import UTC, datetime, timedelta

                        today = datetime.now(tz=UTC).date()
                        try:
                            record(
                                store_path(repo_root),
                                control_id=att_control.id,
                                attested_by=att_by.strip(),
                                date=today.isoformat(),
                                expires=(today + timedelta(days=int(att_days))).isoformat(),
                                note=att_note.strip(),
                            )
                        except AttestationError as exc:
                            st.error(f"Attestation rejected: {exc}")
                        else:
                            st.success(
                                "Recorded. Re-run controls to see the ATTESTED "
                                "status, then commit compliance/attestations.json."
                            )

        if st.button("Export auditor bundle", key="compliance_export"):
            bundle_path = export_bundle(
                stored_report,
                root=repo_root,
                dest=repo_root
                / "reports"
                / "compliance"
                / f"compliance-{stored_report.generated_at[:10]}.json",
            )
            st.success(f"Bundle written to `{bundle_path.relative_to(repo_root)}`")

with tab_approvals:
    st.subheader("Agent Trust Broker — Pending Approvals")
    st.caption(
        "Escalations awaiting a human decision, read from the broker's "
        "hash-chained audit file (read-only; resolve via the broker's own tooling)."
    )
    chain_path = os.environ.get("ATB_AUDIT_CHAIN", "")
    if not chain_path:
        st.info("Set ATB_AUDIT_CHAIN in the environment to the broker's audit JSONL file.")
    else:
        try:
            view = load_chain_view(Path(chain_path))
        except FileNotFoundError:
            st.info(f"No audit chain found at `{chain_path}` — the broker has not run yet.")
        except AuditChainError as exc:
            # A broken chain is a security event, not a display glitch (THR-0003).
            st.error(f"Audit chain FAILED verification — treat as a security event: {exc}")
        else:
            col_pend, col_rec, col_res, col_used = st.columns(4)
            col_pend.metric("Pending", len(view.pending))
            col_rec.metric("Chain records", view.records)
            col_res.metric("Resolved", view.resolved)
            col_used.metric("Approvals consumed", view.consumed)
            if view.pending:
                st.table(
                    [
                        {
                            "Ref": p.ref,
                            "Agent": p.subject,
                            "Action": p.action,
                            "Resource": p.resource,
                            "Reason": p.reason,
                        }
                        for p in view.pending
                    ]
                )
            else:
                st.success("No escalations awaiting approval — chain verified.")

with tab_soc:
    log_text = st.text_area(
        "Paste a security log entry",
        value="Failed password for root from 10.0.0.5 port 22 ssh2",
        height=150,
        key="soc_log_input",
    )

    if st.button("Run SOC Workflow"):
        result = agent.process_log(log_text)
        soc = result["soc"]

        # At-a-glance severity before the raw JSON.
        col_sev, col_score, col_event = st.columns(3)
        col_sev.metric("Severity", str(soc.get("severity", "unknown")).upper())
        col_score.metric("Severity score", f"{soc.get('severity_score', 'N/A')} / 100")
        col_event.metric("Event type", soc.get("event_type", "unknown"))

        st.subheader("SOC Analysis")
        st.json(soc)

        st.subheader("MITRE ATT&CK Mapping")
        st.json(result["mitre"])

        st.subheader("Threat Intelligence")
        st.json(result["threat_intel"])

        # Surface the knowledge-base grounding the orchestrator now returns.
        kb_references = result.get("knowledge_base", [])
        st.subheader("Knowledge Base References")
        if kb_references:
            for ref in kb_references:
                st.markdown(
                    f"- **{ref['source']}** (relevance {ref['score']:.2f}) — {ref['snippet']}"
                )
        else:
            st.caption("No knowledge-base references matched this event.")

        st.success("Incident workflow completed.")

        markdown_report = Path("reports/markdown/orchestrated_incident.md")
        if markdown_report.exists():
            st.subheader("Markdown Report")
            st.code(markdown_report.read_text(encoding="utf-8"))

        try:
            subprocess.run([sys.executable, "scripts/convert_report_to_pdf.py"], check=True)
            pdf_report = Path("reports/pdf/sample_incident_report.pdf")
            if pdf_report.exists():
                st.subheader("PDF Report")
                st.download_button(
                    "Download PDF Incident Report",
                    data=pdf_report.read_bytes(),
                    file_name="sample_incident_report.pdf",
                    mime="application/pdf",
                )
        except Exception as exc:
            st.warning(f"PDF generation skipped: {exc}")

# Bundled, deterministic test scenarios (fixed allow-list — the selectbox value
# is never treated as a free-form path, so no traversal is possible).
SAMPLE_SCENARIOS = {
    "SSH brute force (5 events)": "ssh_brute_force.log",
    "Auth batch — failures then success (3 events)": "auth_batch.log",
    "ARP spoofing / adversary-in-the-middle (4 events)": "arp_spoofing.log",
    "Persistence chain — account created → privileged → history cleared (4 events)": (
        "persistence_chain.log"
    ),
    "Recon → port scan → firewall blocks → login attempt (5 events)": "recon_scan.log",
}

with tab_batch:
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=["log", "txt"],
    )

    sample_choice = st.selectbox(
        "…or load a bundled sample scenario (no upload needed)",
        ["None", *SAMPLE_SCENARIOS],
        help=(
            "Deterministic fixtures from sample-logs/ so every batch feature — "
            "sequence correlation, verified citations, the incident report — "
            "is testable in one click."
        ),
    )

    raw_text = None
    if uploaded_file is not None:
        raw_text = uploaded_file.read().decode("utf-8", errors="ignore")
    elif sample_choice != "None":
        sample_path = Path("sample-logs") / SAMPLE_SCENARIOS[sample_choice]
        if sample_path.exists():
            raw_text = sample_path.read_text(encoding="utf-8")
        else:
            st.warning(f"Sample file not found: {sample_path}")

    if raw_text is not None:
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

        # Bound the work a single upload can trigger (defense in depth on top
        # of the server-level maxUploadSize cap in .streamlit/config.toml).
        MAX_BATCH_LINES = 2000
        if len(lines) > MAX_BATCH_LINES:
            st.warning(
                f"Batch truncated to the first {MAX_BATCH_LINES} of "
                f"{len(lines)} lines — split larger logs into multiple runs."
            )
            lines = lines[:MAX_BATCH_LINES]

        st.write(f"Loaded {len(lines)} log entries.")

        # analyze_sequence validates fail-closed (an empty batch raises);
        # surface that as a friendly message instead of a traceback.
        if not lines:
            st.warning("The uploaded file contains no non-empty log lines.")
        elif st.button("Run Batch SOC Workflow"):
            # One correlated pipeline run over the ordered batch (sequence
            # correlation + report anchored on the most severe event), instead
            # of N independent single-line analyses that can't see patterns.
            result = agent.process_sequence(lines)
            sequence = result["sequence"]

            col_sev, col_score, col_events = st.columns(3)
            col_sev.metric("Sequence severity", str(sequence["severity"]).upper())
            col_score.metric("Severity score", f"{sequence['severity_score']} / 100")
            col_events.metric("Events analyzed", sequence["event_count"])
            st.caption(sequence["summary"])

            # Honest-degradation strip: surface analysis caveats the result
            # already records, so evasion-by-formatting is visible, not buried.
            caveats = []
            uncorrelated = sequence.get("uncorrelated_event_count", 0)
            if uncorrelated:
                caveats.append(
                    f"{uncorrelated} event(s) had no extractable source and were "
                    "excluded from source-based correlation."
                )
            for assumption in sequence.get("assumptions", []):
                if "failed to parse" in assumption:
                    caveats.append(assumption)
            if caveats:
                st.warning("**Analysis caveats** — " + " ".join(caveats))

            st.subheader("Entity Risk (RBA)")
            st.caption(
                "Per-entity risk: each event's severity is weighted by type and "
                "accumulated per source. A finding is raised only when an entity "
                "crosses the threshold — every finding is explainable."
            )
            source_labels = result.get("source_labels", [])
            if source_labels:
                _BADGE = {
                    "malicious": "🔴",
                    "suspicious": "🟠",
                    "benign-scanner": "🟢",
                    "unknown": "⚪",
                }
                st.markdown(
                    "**Source labels:** "
                    + " · ".join(
                        f"{_BADGE.get(sl['label'], '⚪')} `{sl['source']}` "
                        f"{sl['label']} ({sl['rule']})"
                        for sl in source_labels
                    )
                )
            risk_findings = result.get("risk_findings", [])
            if risk_findings:
                for rf in risk_findings:
                    st.markdown(
                        f"- **`{rf['entity']}`** — risk **{rf['total_score']}** "
                        f"(threshold {rf['threshold']}), {rf['contribution_count']} "
                        f"event(s), dominant: _{rf['dominant_event_type']}_"
                    )
                    with st.expander(f"Risk story for {rf['entity']}"):
                        st.dataframe(rf["contributions"], use_container_width=True)
            else:
                st.caption("No entity crossed the risk threshold in this batch.")

            st.subheader("Correlated Findings")
            findings = sequence["findings"]
            if findings:
                for finding in findings:
                    event_numbers = ", ".join(str(i + 1) for i in finding["event_indices"])
                    st.markdown(
                        f"- **{finding['pattern']}** from `{finding['source']}` — "
                        f"severity **{str(finding['severity']).upper()}** "
                        f"(events {event_numbers}): {finding['description']}"
                    )
            else:
                st.caption("No multi-event patterns detected in this batch.")

            st.subheader("Per-Event Breakdown")
            per_event = [
                {
                    "event": entry["index"] + 1,
                    "log": lines[entry["index"]],
                    "event_type": entry["event_type"],
                    "ocsf_class": ocsf_normalize(entry["event_type"])["class_name"],
                    "severity": entry["severity"],
                    "severity_score": entry["severity_score"],
                    "source": entry["source"] or "—",
                    "indicators": ", ".join(entry["indicators"]),
                }
                for entry in sequence["events"]
            ]
            st.dataframe(per_event, use_container_width=True)

            st.subheader("Matching Detections")
            sequence_detections = result.get("sequence_detections", [])
            if sequence_detections:
                for detection in sequence_detections:
                    st.markdown(
                        f"- **{detection['title']}** [{detection['level']}] — "
                        f"`{detection['file']}` ({detection['technique']}, "
                        f"covers {detection['pattern']})"
                    )
            else:
                st.caption("No Sigma correlation rule covers these patterns yet.")

            st.subheader("Recommended Actions")
            for action in sequence["recommended_actions"]:
                st.markdown(f"- {action}")

            st.subheader("Threat Intelligence (sequence-wide)")
            st.json(result["threat_intel"])

            citations = result.get("citations", [])
            st.subheader("Cited Passages (verified)")
            if citations:
                for citation in citations:
                    st.markdown(
                        f"- **{citation['source']}** "
                        f"[chars {citation['char_start']}-{citation['char_end']}, "
                        f"relevance {citation['score']:.2f}]: "
                        f'"{citation["quote"]}"'
                    )
            else:
                st.caption("No knowledge-base passages passed citation verification.")

            st.download_button(
                "Download Batch Results (JSON)",
                data=json.dumps(result, indent=2, default=str),
                file_name="batch_soc_results.json",
                mime="application/json",
            )

            sequence_report = Path("reports/markdown/orchestrated_sequence_incident.md")
            if sequence_report.exists():
                with st.expander("Sequence Incident Report (Markdown)"):
                    st.markdown(sequence_report.read_text(encoding="utf-8"))

with tab_coverage:
    st.subheader("ATT&CK Detection Coverage")
    st.caption(
        "The techniques the Sigma corpus detects, generated deterministically "
        "from detections/sigma/ (drift-gated in CI). Load the exported layer "
        "into the MITRE ATT&CK Navigator for the full heatmap."
    )
    layer = _load_navigator_layer()
    if layer is None:
        st.info(
            "Coverage layer not found — run "
            "`python scripts/build_attack_navigator.py` to generate it."
        )
    else:
        techniques = layer.get("techniques", [])
        col_t, col_r = st.columns(2)
        col_t.metric("Techniques covered", len(techniques))
        col_r.metric("Sigma rules", _sigma_rule_count())
        st.markdown("**Covered techniques** (score = rules covering each):")
        st.dataframe(
            [
                {
                    "technique": t["techniqueID"],
                    "rules": t["score"],
                    "detected_by": t["comment"].removeprefix("Detected by: "),
                }
                for t in techniques
            ],
            use_container_width=True,
        )
        st.download_button(
            "Download ATT&CK Navigator layer (JSON)",
            data=json.dumps(layer, indent=2, sort_keys=True),
            file_name="attack-navigator-layer.json",
            mime="application/json",
            help="Import at mitre-attack.github.io/attack-navigator",
        )

with tab_kb:
    category = st.selectbox(
        "Select knowledge base category",
        ["all", "cybersecurity", "mitre", "nist", "owasp", "cis", "security-plus"],
    )

    query = st.text_input(
        "Search the cybersecurity knowledge base",
        value="What are the NIST CSF functions?",
    )

    if st.button("Search Knowledge Base"):
        # Fails soft: semantic search against local Qdrant when available,
        # otherwise the offline lexical corpus — labelled so degraded results
        # are never passed off as the primary backend.
        points, backend = search_kb_resilient(query=query, category=category)
        st.caption(f"Backend: {backend}")

        if not points:
            st.info("No knowledge-base results matched this query.")

        for index, point in enumerate(points, start=1):
            st.subheader(f"Result {index}")
            st.write("Score:", point.score)
            st.write("Source:", point.payload.get("source"))
            st.write("Category:", point.payload.get("category"))
            st.write("Chunk:", point.payload.get("chunk_index"))
            st.markdown(point.payload.get("text", ""))

with tab_health:
    st.subheader("System Health")
    st.write("**Git Version:**", get_git_tag())
    st.write("**Python:**", get_python_info())
    st.write("**Qdrant Collections:**", get_qdrant_collections())
    st.write("**Ollama Models:**")
    st.code(get_ollama_models())

with tab_reports:
    st.subheader("Generated Reports")
    reports_dir = Path("reports/markdown")
    if reports_dir.exists():
        report_files = sorted(reports_dir.glob("*.md"))
        if report_files:
            for report_file in report_files:
                with st.expander(report_file.name):
                    st.markdown(report_file.read_text(encoding="utf-8"))
        else:
            st.info("No reports generated yet. Run a SOC workflow to create one.")
    else:
        st.info("Reports directory not found.")
