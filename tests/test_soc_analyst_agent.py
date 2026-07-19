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


# ------------------------------------------------------------------ v1.9: sequence correlation
_FAIL_BOB = "Failed password for invalid user bob from 203.0.113.7 port 22 ssh2"
_FAIL_ROOT = "Failed password for root from 203.0.113.7 port 22 ssh2"
_OK_BOB = "Accepted password for bob from 203.0.113.7 port 22 ssh2"


@pytest.mark.unit
def test_sequence_detects_brute_force() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_FAIL_BOB, _FAIL_BOB, _FAIL_BOB])
    patterns = {f["pattern"] for f in result["findings"]}
    assert "brute_force" in patterns
    assert result["severity"] == "high"
    assert result["event_count"] == 3


@pytest.mark.unit
def test_sequence_brute_force_privileged_is_critical() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_FAIL_ROOT, _FAIL_ROOT, _FAIL_ROOT])
    brute = next(f for f in result["findings"] if f["pattern"] == "brute_force")
    assert brute["severity"] == "critical"
    assert result["severity"] == "critical"
    assert result["severity_score"] == 100


@pytest.mark.unit
def test_sequence_failure_then_success_is_credential_compromise() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_FAIL_BOB, _FAIL_BOB, _OK_BOB])
    compromise = next(f for f in result["findings"] if f["pattern"] == "auth_failure_then_success")
    assert compromise["severity"] == "critical"
    assert compromise["source"] == "203.0.113.7"
    assert compromise["event_indices"] == [0, 1, 2]
    assert any("credential rotation" in a for a in result["recommended_actions"])


@pytest.mark.unit
def test_sequence_success_before_failures_not_compromise() -> None:
    # A success that precedes the first failure is not a failure->success chain.
    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_OK_BOB, _FAIL_BOB, _FAIL_BOB])
    patterns = {f["pattern"] for f in result["findings"]}
    assert "auth_failure_then_success" not in patterns


@pytest.mark.unit
def test_sequence_below_threshold_no_findings() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_FAIL_BOB, _FAIL_BOB])
    assert result["findings"] == []
    # Falls back to the worst single event (auth failure, non-privileged).
    assert result["severity"] == "medium"


@pytest.mark.unit
def test_sequence_different_sources_not_correlated() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence(
        [
            "Failed password for invalid user bob from 198.51.100.1 port 22 ssh2",
            "Failed password for invalid user bob from 198.51.100.2 port 22 ssh2",
            "Failed password for invalid user bob from 198.51.100.3 port 22 ssh2",
        ]
    )
    assert all(f["pattern"] != "brute_force" for f in result["findings"])


@pytest.mark.unit
def test_sequence_accepts_mixed_str_and_dict_events() -> None:
    agent = SocAnalystAgent()
    result = agent.analyze_sequence(
        [
            _FAIL_BOB,
            {"src_ip": "203.0.113.7", "message": "Failed password for invalid user bob"},
            _FAIL_BOB,
        ]
    )
    assert any(f["pattern"] == "brute_force" for f in result["findings"])


@pytest.mark.unit
def test_sequence_rejects_empty_list() -> None:
    agent = SocAnalystAgent()
    with pytest.raises(ValueError):
        agent.analyze_sequence([])


@pytest.mark.unit
def test_sequence_rejects_non_list() -> None:
    agent = SocAnalystAgent()
    with pytest.raises(ValueError):
        agent.analyze_sequence("not a list")  # type: ignore[arg-type]


@pytest.mark.unit
def test_sequence_rejects_empty_event_inside_list() -> None:
    agent = SocAnalystAgent()
    with pytest.raises(ValueError):
        agent.analyze_sequence([_FAIL_BOB, "   "])


@pytest.mark.unit
def test_sequence_is_deterministic() -> None:
    agent = SocAnalystAgent()
    events: list[str | dict[str, object]] = [_FAIL_ROOT, _FAIL_ROOT, _FAIL_ROOT, _OK_BOB]
    assert agent.analyze_sequence(events) == agent.analyze_sequence(events)


@pytest.mark.unit
def test_sequence_reports_versioned_agent_name() -> None:
    from agents import __version__

    agent = SocAnalystAgent()
    result = agent.analyze_sequence([_FAIL_BOB])
    assert result["agent"] == f"SOC Analyst Agent v{__version__}"
