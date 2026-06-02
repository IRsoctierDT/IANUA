import streamlit as st

from agents.orchestrator_agent import OrchestratorAgent

st.set_page_config(
    page_title="AI Operator Cyber Command Center",
    layout="wide",
)

st.title("AI Operator Cyber Command Center")
st.caption("Local AI-assisted SOC workflow")

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
