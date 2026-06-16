import pytest
from agents.soc_analyst_agent import SocAnalystAgent


# ------------------------------------------------------------------ v0.1 compat
def test_analyze_log_auth_failure_extracts_ip() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    )
    assert result["event_type"] == "authentication failure"
    assert result["severity"] == "medium"
    assert "192.168.1.50" in result["indicators"]


def test_analyze_log_root_failure_high_severity() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert result["severity"] == "high"


def test_analyze_log_rejects_empty_input() -> None:
    agent = SocAnalystAgent()
    with pytest.raises(ValueError):
        agent.analyze_log("   ")


def test_analyze_log_rejects_non_string_input() -> None:
    agent = SocAnalystAgent()
    with pytest.raises(ValueError):
        agent.analyze_log(None)  # type: ignore[arg-type]


# ------------------------------------------------------------------ v0.2: JSON string input
@pytest.mark.unit
def test_json_string_input_parsed() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        '{"timestamp":"2025-06-15T14:00:00Z","host":"web-01",'
        '"user":"root","src_ip":"10.0.0.5","message":"Failed password for root"}'
    )
    assert result["event_type"] == "authentication failure"
    assert "10.0.0.5" in result["indicators"]


@pytest.mark.unit
def test_json_string_honours_explicit_severity() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        '{"severity":"critical","message":"Failed password for root from 1.2.3.4"}'
    )
    assert result["severity"] == "critical"


# ------------------------------------------------------------------ v0.2: dict input
@pytest.mark.unit
def test_dict_input_extracts_src_ip() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        {
            "timestamp": "2025-06-15T14:00:00Z",
            "host": "web-01",
            "user": "admin",
            "src_ip": "192.168.1.99",
            "message": "Failed password for invalid user admin from 192.168.1.99",
        }
    )
    assert result["indicators"] == ["192.168.1.99"]


@pytest.mark.unit
def test_dict_input_populates_evidence_table() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log(
        {
            "timestamp": "2025-06-15T14:00:00Z",
            "host": "web-01",
            "user": "root",
            "src_ip": "10.0.0.5",
            "message": "Failed password for root",
        }
    )
    fields = {e["field"] for e in result["evidence"]}
    assert "timestamp" in fields
    assert "host" in fields
    assert "src_ip" in fields


@pytest.mark.unit
def test_empty_dict_raises() -> None:
    agent = SocAnalystAgent()
    with pytest.raises((ValueError, KeyError)):
        agent.analyze_log({})


# ------------------------------------------------------------------ v0.2: severity score
@pytest.mark.unit
def test_severity_score_present_and_in_range() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert "severity_score" in result
    assert 0 <= result["severity_score"] <= 100


@pytest.mark.unit
def test_root_login_score_above_medium_baseline() -> None:
    agent = SocAnalystAgent()
    root_result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    user_result = agent.analyze_log(
        "Failed password for invalid user bob from 10.0.0.5 port 22 ssh2"
    )
    assert root_result["severity_score"] > user_result["severity_score"]


@pytest.mark.unit
def test_critical_severity_scores_90_or_above() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log('{"severity":"critical","message":"Failed password for root"}')
    assert result["severity_score"] >= 90


@pytest.mark.unit
def test_unknown_event_scores_zero() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("routine system startup completed")
    assert result["severity_score"] == 0


# ------------------------------------------------------------------ v0.2: evidence table
@pytest.mark.unit
def test_plain_text_root_produces_evidence() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    fields = {e["field"] for e in result["evidence"]}
    assert "privileged_account" in fields


@pytest.mark.unit
def test_evidence_entries_have_required_keys() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    for entry in result["evidence"]:
        assert "field" in entry
        assert "value" in entry
        assert "significance" in entry


# ------------------------------------------------------------------ v0.2: new event types
@pytest.mark.unit
def test_successful_login_classified() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Accepted password for deploy from 10.0.0.2 port 22 ssh2")
    assert result["event_type"] == "successful login"


@pytest.mark.unit
def test_network_anomaly_classified() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Connection refused to 10.0.0.1 port 443")
    assert result["event_type"] == "network anomaly"


@pytest.mark.unit
def test_root_successful_login_is_high_severity() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_log("Accepted password for root from 10.0.0.5 port 22 ssh2")
    assert result["severity"] == "high"
