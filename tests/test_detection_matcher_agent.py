from pathlib import Path

import pytest
from agents.detection_matcher_agent import DetectionMatcherAgent


def _make_corpus(root: Path) -> Path:
    """A controlled Sigma corpus so assertions don't couple to the real rules."""
    root.mkdir(parents=True)
    (root / "brute.yml").write_text(
        "title: Brute Force\nid: 11111111-1111-4111-8111-111111111111\n"
        "level: high\ntags: [attack.credential-access, attack.t1110]\n"
        "logsource: {product: linux}\ndetection: {selection: {a: b}, condition: selection}\n",
        encoding="utf-8",
    )
    (root / "valid.yml").write_text(
        "title: Valid Accounts\nid: 22222222-2222-4222-8222-222222222222\n"
        "level: medium\ntags: [attack.initial-access, attack.t1078]\n"
        "logsource: {product: linux}\ndetection: {selection: {a: b}, condition: selection}\n",
        encoding="utf-8",
    )
    (root / "subtech.yml").write_text(
        "title: Account Created\nid: 33333333-3333-4333-8333-333333333333\n"
        "level: low\ntags: [attack.persistence, attack.t1136.001]\n"
        "logsource: {product: linux}\ndetection: {selection: {a: b}, condition: selection}\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def agent(tmp_path: Path) -> DetectionMatcherAgent:
    return DetectionMatcherAgent(_make_corpus(tmp_path / "sigma"))


@pytest.mark.unit
def test_match_for_technique_returns_matching_rule(agent: DetectionMatcherAgent) -> None:
    matches = agent.match_for_technique("T1110")
    assert len(matches) == 1
    m = matches[0]
    assert m["title"] == "Brute Force"
    assert m["technique"] == "T1110"
    assert set(m) == {"rule_id", "title", "level", "technique", "file"}


@pytest.mark.unit
def test_case_insensitive_and_subtechnique(agent: DetectionMatcherAgent) -> None:
    assert agent.match_for_technique("t1078")[0]["title"] == "Valid Accounts"
    assert agent.match_for_technique("T1136.001")[0]["title"] == "Account Created"


@pytest.mark.unit
def test_no_match_returns_empty(agent: DetectionMatcherAgent) -> None:
    assert agent.match_for_technique("T9999") == []


@pytest.mark.unit
def test_unknown_or_blank_technique_returns_empty(agent: DetectionMatcherAgent) -> None:
    assert agent.match_for_technique("UNKNOWN") == []
    assert agent.match_for_technique("") == []


@pytest.mark.unit
def test_match_for_event_uses_technique_id(agent: DetectionMatcherAgent) -> None:
    assert agent.match_for_event({"technique_id": "T1110"})[0]["title"] == "Brute Force"
    assert agent.match_for_event({"technique_id": "UNKNOWN"}) == []
    assert agent.match_for_event({}) == []


@pytest.mark.unit
def test_matches_ranked_by_severity(tmp_path: Path) -> None:
    root = tmp_path / "sigma"
    root.mkdir(parents=True)
    (root / "a.yml").write_text(
        "title: Low One\nid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n"
        "level: low\ntags: [attack.t1110]\nlogsource: {a: b}\n"
        "detection: {selection: {a: b}, condition: selection}\n",
        encoding="utf-8",
    )
    (root / "b.yml").write_text(
        "title: Critical One\nid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\n"
        "level: critical\ntags: [attack.t1110]\nlogsource: {a: b}\n"
        "detection: {selection: {a: b}, condition: selection}\n",
        encoding="utf-8",
    )
    titles = [m["title"] for m in DetectionMatcherAgent(root).match_for_technique("T1110")]
    assert titles == ["Critical One", "Low One"]


@pytest.mark.unit
def test_missing_corpus_fails_soft(tmp_path: Path) -> None:
    assert DetectionMatcherAgent(tmp_path / "nope").match_for_technique("T1110") == []
