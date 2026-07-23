from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import streamlit as st
from agents.orchestrator_agent import OrchestratorAgent

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

tab_soc, tab_batch, tab_kb, tab_health, tab_reports, tab_approvals = st.tabs(
    [
        "SOC Workflow",
        "Batch Processing",
        "Knowledge Base Search",
        "System Health",
        "Reports",
        "Pending Approvals",
    ]
)

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
