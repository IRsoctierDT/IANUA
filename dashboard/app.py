from pathlib import Path
import subprocess

import streamlit as st

from agents.orchestrator_agent import OrchestratorAgent
from kb_search import search_kb
from ollama_service import ensure_ollama_running
from system_health import (
    get_git_tag,
    get_ollama_models,
    get_python_info,
    get_qdrant_collections,
)


st.set_page_config(
    page_title="AI Operator Cyber Command Center",
    layout="wide",
)

st.title("AI Operator Cyber Command Center")
st.caption("Local AI-assisted SOC workflow")

st.sidebar.header("System Status")
st.sidebar.write("Model: qwen3:4b")
st.sidebar.write("Vector DB: Qdrant")
st.sidebar.write("Mode: Local")
st.sidebar.subheader("Health Panel")
st.sidebar.write("Git Version:", get_git_tag())
st.sidebar.write("Python:", get_python_info())
st.sidebar.write("Qdrant Collections:", get_qdrant_collections())
ollama_status = ensure_ollama_running()
st.sidebar.write("Ollama:", ollama_status)
with st.sidebar.expander("Ollama Models"):
    st.text(get_ollama_models())

mode = st.radio(
    "Choose analysis mode",
    [
        "Single Log Entry",
        "Batch Log File",
        "Knowledge Base Search",
    ],
)

agent = OrchestratorAgent()

if mode == "Single Log Entry":
    log_text = st.text_area(
        "Paste a security log entry",
        value="Failed password for root from 10.0.0.5 port 22 ssh2",
        height=150,
    )

    if st.button("Run SOC Workflow"):
        result = agent.process_log(log_text)

        st.subheader("SOC Analysis")
        st.json(result["soc"])

        st.subheader("MITRE ATT&CK Mapping")
        st.json(result["mitre"])

        st.subheader("Threat Intelligence")
        st.json(result["threat_intel"])

        st.success("Incident workflow completed.")

        markdown_report = Path("reports/markdown/orchestrated_incident.md")

        if markdown_report.exists():
            st.subheader("Markdown Report")
            st.code(markdown_report.read_text(encoding="utf-8"))

        try:
            subprocess.run(["python", "scripts/convert_report_to_pdf.py"], check=True)
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

if mode == "Batch Log File":
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
                result = agent.process_log(line)
                results.append(
                    {
                        "event": index,
                        "log": line,
                        "event_type": result["soc"]["event_type"],
                        "severity": result["soc"]["severity"],
                        "mitre_technique": result["mitre"]["technique_id"],
                        "mitre_name": result["mitre"]["technique"],
                        "indicators": ", ".join(result["soc"]["indicators"]),
                    }
                )

            st.subheader("Batch Results")
            st.dataframe(results, use_container_width=True)

            output = "\n".join(str(item) for item in results)

            st.download_button(
                "Download Batch Results",
                data=output,
                file_name="batch_soc_results.txt",
                mime="text/plain",
            )

if mode == "Knowledge Base Search":
    from kb_search import search_kb

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