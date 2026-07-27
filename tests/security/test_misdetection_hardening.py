"""Misdetection-path hardening contracts for the SOC Analyst Agent.

These pin the behaviors that keep detection degradation *visible* instead of
silent — the paths an attacker could otherwise exploit through input
formatting alone:

* JSON-looking input that fails to parse is analyzed as plain text, and the
  downgrade is reported (evidence row + assumption), never silent.
* Sequence correlation covers IPv6 sources — IPv4-only matching would let an
  IPv6 attacker evade correlation by construction.
* Events with no extractable source are counted and reported, so
  correlation-evasion-by-formatting shows up in the result.
* Privileged-account detection matches whole words only — "rootkit" or
  "chroot" in a message must not count as the root account.
"""

from __future__ import annotations

from agents.soc_analyst_agent import SocAnalystAgent


def _agent() -> SocAnalystAgent:
    return SocAnalystAgent()


class TestMalformedJsonVisibility:
    def test_malformed_json_is_flagged_in_evidence_and_assumptions(self) -> None:
        # Truncated JSON: startswith "{" but unparseable.
        result = _agent().analyze_log('{"message": "Failed password for root from 10.0.0.5')
        evidence_fields = {e["field"]: e["value"] for e in result["evidence"]}
        assert evidence_fields.get("parse_status") == "malformed_json"
        assert any("failed to parse" in a for a in result["assumptions"])

    def test_valid_json_is_not_flagged(self) -> None:
        result = _agent().analyze_log('{"message": "Failed password for root from 10.0.0.5"}')
        evidence_fields = {e["field"] for e in result["evidence"]}
        assert "parse_status" not in evidence_fields
        assert not any("failed to parse" in a for a in result["assumptions"])

    def test_plain_text_is_not_flagged(self) -> None:
        result = _agent().analyze_log("Failed password for root from 10.0.0.5")
        evidence_fields = {e["field"] for e in result["evidence"]}
        assert "parse_status" not in evidence_fields

    def test_sequence_reports_malformed_event_count(self) -> None:
        events = [
            '{"message": "Failed password for admin from 10.0.0.5',  # malformed
            "Failed password for admin from 10.0.0.5",
        ]
        result = _agent().analyze_sequence(events)
        assert any("resembled JSON but failed to parse" in a for a in result["assumptions"])


class TestIpv6Correlation:
    def test_brute_force_correlates_from_ipv6_source(self) -> None:
        events = ["Failed password for root from 2001:db8::1 port 22"] * 3
        result = _agent().analyze_sequence(events)
        patterns = {f["pattern"]: f["source"] for f in result["findings"]}
        assert patterns.get("brute_force") == "2001:db8::1"

    def test_bracketed_ipv6_source_is_unwrapped(self) -> None:
        result = _agent().analyze_sequence(["Failed password for root from [2001:db8::2]"] * 3)
        sources = {f["source"] for f in result["findings"]}
        assert "2001:db8::2" in sources

    def test_hostname_after_from_is_not_a_source(self) -> None:
        # A non-address token must not become a correlation key.
        result = _agent().analyze_sequence(["Failed password for root from badhost.example"] * 3)
        assert result["findings"] == []
        assert result["uncorrelated_event_count"] == 3


class TestUncorrelatedVisibility:
    def test_sourceless_events_are_counted_and_reported(self) -> None:
        events = [
            "Failed password for root from 10.0.0.5",
            "Suricata alert: possible scan detected",  # no source token
        ]
        result = _agent().analyze_sequence(events)
        assert result["uncorrelated_event_count"] == 1
        assert any("no extractable source" in a for a in result["assumptions"])

    def test_fully_attributed_sequence_reports_zero(self) -> None:
        result = _agent().analyze_sequence(["Failed password for root from 10.0.0.5"] * 3)
        assert result["uncorrelated_event_count"] == 0
        assert not any("no extractable source" in a for a in result["assumptions"])


class TestPrivilegeWordBoundary:
    def test_rootkit_is_not_the_root_account(self) -> None:
        assert not SocAnalystAgent._is_privileged("Suricata alert: rootkit signature match", {})

    def test_chroot_is_not_the_root_account(self) -> None:
        assert not SocAnalystAgent._is_privileged("service entered chroot jail", {})

    def test_root_word_in_text_is_privileged(self) -> None:
        assert SocAnalystAgent._is_privileged("Failed password for root from 10.0.0.5", {})

    def test_structured_user_field_is_authoritative(self) -> None:
        assert SocAnalystAgent._is_privileged("login event", {"user": "Root"})
        assert not SocAnalystAgent._is_privileged("login event", {"user": "alice"})
