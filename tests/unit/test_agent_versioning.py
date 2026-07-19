"""Drift gate: every agent's display name must carry the current platform version.

The platform version has one source of truth (``pyproject.toml``); agents derive
their display names from it via ``agents.versioned_agent_name``. These tests fail
closed if an agent ever hard-codes a version again (the incident this prevents:
the SOC Analyst Agent announced ``v0.2`` while the platform was at ``v1.9.0``).
"""

import tomllib
from pathlib import Path
from typing import Any

import agents
import pytest
from agents import __version__, versioned_agent_name
from agents.business_proposal_agent import BusinessProposalAgent
from agents.executive_assistant_agent import ExecutiveAssistantAgent
from agents.knowledge_curator_agent import KnowledgeCuratorAgent
from agents.legal_compliance_agent import LegalComplianceAgent
from agents.portfolio_documentation_agent import PortfolioDocumentationAgent
from agents.soc_analyst_agent import SocAnalystAgent
from agents.vulnerability_assessment_agent import VulnerabilityAssessmentAgent

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every agent that reports a display name, with its expected base name.
_NAMED_AGENTS = [
    (SocAnalystAgent, "SOC Analyst Agent"),
    (BusinessProposalAgent, "Business Proposal Agent"),
    (ExecutiveAssistantAgent, "Executive Assistant Agent"),
    (KnowledgeCuratorAgent, "Knowledge Curator Agent"),
    (LegalComplianceAgent, "Legal/Compliance Research Agent"),
    (PortfolioDocumentationAgent, "Portfolio Documentation Agent"),
    (VulnerabilityAssessmentAgent, "Vulnerability Assessment Agent"),
]


@pytest.mark.unit
def test_version_matches_pyproject() -> None:
    # pyproject.toml is the release source of truth; the resolved version must
    # match it exactly in a source checkout.
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert __version__ == data["project"]["version"]


@pytest.mark.unit
def test_versioned_agent_name_format() -> None:
    assert versioned_agent_name("X Agent") == f"X Agent v{__version__}"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("agent_cls", "base"), _NAMED_AGENTS, ids=lambda p: getattr(p, "__name__", p)
)
def test_agent_default_name_carries_current_version(agent_cls: type[Any], base: str) -> None:
    # The drift gate: a hard-coded stale version in any default name fails here.
    assert agent_cls().name == f"{base} v{__version__}"


@pytest.mark.unit
def test_agent_name_override_respected() -> None:
    assert SocAnalystAgent(name="Custom").name == "Custom"


@pytest.mark.unit
def test_result_reports_versioned_agent_name() -> None:
    result = SocAnalystAgent().analyze_log("Failed password for root from 10.0.0.5")
    assert result["agent"] == f"SOC Analyst Agent v{__version__}"


@pytest.mark.unit
def test_no_hardcoded_versions_in_agent_sources() -> None:
    # Belt-and-suspenders: no agent module may embed a literal "vN.N" version
    # in a default-name string. (Docstrings explaining the mechanism are fine —
    # this scans only string literals assigned as name defaults.)
    import re

    pattern = re.compile(r'name: str = "[^"]*v\d+\.\d+')
    offenders = [
        path.name
        for path in (REPO_ROOT / "agents").glob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


@pytest.mark.unit
def test_version_fallback_is_conspicuous_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    # If neither pyproject nor installed metadata is available, resolution must
    # return the sentinel — visibly wrong, never a crash (secure defaults).
    from importlib import metadata as importlib_metadata

    monkeypatch.setattr(agents, "_PYPROJECT", Path("/nonexistent/pyproject.toml"))

    def _raise(_name: str) -> str:
        raise importlib_metadata.PackageNotFoundError

    monkeypatch.setattr(agents.metadata, "version", _raise)
    assert agents._resolve_version() == "0.0.0"
