from pathlib import Path
import subprocess

import streamlit as st

from agents.orchestrator_agent import OrchestratorAgent

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

log_text = st.text_area(
    "Paste a security log entry",
    value="Failed password for root from 10.0.0.5 port 22 ssh2",
    height=150,
)

if st.button("Run SOC Workflow"):
    agent = OrchestratorAgent()
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
        subprocess.run(
            ["python", "scripts/convert_report_to_pdf.py"],
            check=True,
        )
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
