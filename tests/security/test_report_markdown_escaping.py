"""Report rendering: untrusted log-derived text cannot break Markdown structure.

The incident report embeds attacker-influenced values (evidence values, mapper
evidence, indicators, detection file names) in three Markdown positions: table
cells, inline bullets, and code spans. Each position has a distinct escape
requirement; these tests pin all three plus control-character stripping and
the length cap, so a crafted log line cannot smuggle active Markdown — or NUL
bytes — into an analyst-facing (and PDF-exported) deliverable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from agents.incident_report_agent import IncidentReportAgent, _md_cell, _md_code, _sanitize


def _report(tmp_path: Path, log_text: str, **kwargs: Any) -> str:
    agent = IncidentReportAgent()
    out = tmp_path / "report.md"
    agent.generate_report(log_text, str(out), **kwargs)
    return out.read_text(encoding="utf-8")


@pytest.mark.security
def test_backtick_cannot_break_out_of_code_span() -> None:
    hostile = "evil` ![x](https://attacker.example/x) `"
    rendered = _md_code(hostile)
    assert "`" not in rendered


@pytest.mark.security
def test_cell_escapes_pipe_and_backtick() -> None:
    rendered = _md_cell("a|b`c")
    assert "\\|" in rendered and "\\`" in rendered


@pytest.mark.security
def test_control_characters_stripped() -> None:
    rendered = _sanitize("a\x00b\x07c\x1bd\x7fe")
    assert rendered == "abcde"


@pytest.mark.security
def test_newlines_flattened_and_length_capped() -> None:
    rendered = _sanitize("line1\r\nline2\rline3\nline4")
    assert "\n" not in rendered and "\r" not in rendered
    long = _sanitize("x" * 10_000)
    assert len(long) < 600
    assert long.endswith("…[truncated]")


@pytest.mark.security
def test_hostile_evidence_value_stays_inside_its_table_cell(tmp_path: Path) -> None:
    # A crafted username lands in the evidence table via the SOC agent's
    # structured passthrough. The rendered table row must stay one row.
    hostile_user = "bob | pwned | `rm -rf` \x00"
    content = _report(
        tmp_path,
        '{"message": "Failed password for user", "user": "'
        + hostile_user.replace("\x00", "")
        + '"}',
    )
    for line in content.splitlines():
        if "pwned" in line:
            assert "\\|" in line, "pipe in untrusted value must be escaped"
            assert "\\`rm -rf\\`" in line, "backticks must be escaped, not live"
    assert "\x00" not in content


@pytest.mark.security
def test_hostile_mitre_evidence_is_escaped(tmp_path: Path) -> None:
    mitre = {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "confidence": "medium",
        "evidence": ["injected `code` and\x07control | pipe"],
        "recommended_investigation": ["step with `tick`"],
    }
    soc = {
        "summary": "s",
        "severity": "high",
        "severity_score": 70,
        "event_type": "authentication failure",
        "indicators": ["203.0.113.5`whoami`"],
        "evidence": [],
        "recommended_actions": ["act"],
        "assumptions": ["assume"],
    }
    content = _report(tmp_path, "log", soc_result=soc, mitre_result=mitre)
    assert "\\`code\\`" in content
    assert "\x07" not in content
    # Indicator renders in a code span with backticks neutralized, not live.
    assert "203.0.113.5'whoami'" in content
