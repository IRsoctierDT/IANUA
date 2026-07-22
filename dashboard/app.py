from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import streamlit as st
from agents.orchestrator_agent import OrchestratorAgent

from dashboard.kb_search import search_kb
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

tab_soc, tab_batch, tab_kb, tab_health, tab_reports = st.tabs(
    [
        "SOC Workflow",
        "Batch Processing",
        "Knowledge Base Search",
        "System Health",
        "Reports",
    ]
)

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

with tab_batch:
    uploaded_file = st.file_uploader(
        "Upload a log file",
        type=["log", "txt"],
    )

    if uploaded_file is not None:
        raw_text = uploaded_file.read().decode("utf-8", errors="ignore")
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

        st.write(f"Loaded {len(lines)} log entries.")

        if st.button("Run Batch SOC Workflow"):
            results = []

            for index, line in enumerate(lines, start=1):
                res = agent.process_log(line)
                results.append(
                    {
                        "event": index,
                        "log": line,
                        "event_type": res["soc"]["event_type"],
                        "severity": res["soc"]["severity"],
                        "severity_score": res["soc"].get("severity_score"),
                        "mitre_technique": res["mitre"]["technique_id"],
                        "mitre_name": res["mitre"]["technique"],
                        "indicators": ", ".join(res["soc"]["indicators"]),
                    }
                )

            st.subheader("Batch Results")
            st.dataframe(results, use_container_width=True)

            st.download_button(
                "Download Batch Results (JSON)",
                data=json.dumps(results, indent=2),
                file_name="batch_soc_results.json",
                mime="application/json",
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
        points = search_kb(query=query, category=category)

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
