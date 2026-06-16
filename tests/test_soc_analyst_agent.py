import pytest
from agents.soc_analyst_agent import SocAnalystAgent


def test_analyze_log_auth_failure_extracts_ip():
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    )

    assert result["event_type"] == "authentication failure"
    assert result["severity"] == "medium"
    assert "192.168.1.50" in result["indicators"]


def test_analyze_log_root_failure_high_severity():
    agent = SocAnalystAgent()
    result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")

    assert result["severity"] == "high"


def test_analyze_log_rejects_empty_input():
    agent = SocAnalystAgent()

    with pytest.raises(ValueError):
        agent.analyze_log("   ")


def test_analyze_log_rejects_non_string_input():
    agent = SocAnalystAgent()

    with pytest.raises(ValueError):
        agent.analyze_log(None)  # type: ignore[arg-type]
