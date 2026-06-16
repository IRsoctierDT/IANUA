import pytest
from agents.threat_intel_agent import ThreatIntelAgent


def test_private_ip_classification():
    agent = ThreatIntelAgent()
    result = agent.analyze_indicator("192.168.1.50")

    assert result["indicator_type"] == "private_ip"
    assert result["risk_level"] == "context-dependent"
    assert result["confidence"] == "high"


def test_public_ip_classification():
    agent = ThreatIntelAgent()
    result = agent.analyze_indicator("8.8.8.8")

    assert result["indicator_type"] == "public_ip"
    assert result["risk_level"] == "unknown"


def test_domain_classification():
    agent = ThreatIntelAgent()
    result = agent.analyze_indicator("example.com")

    assert result["indicator_type"] == "domain"


def test_empty_indicator_rejected():
    agent = ThreatIntelAgent()

    with pytest.raises(ValueError):
        agent.analyze_indicator("")
