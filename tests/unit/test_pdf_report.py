"""Unit tests for PDF incident-report export (agents/tools/pdf_report.py).

reportlab ships in the ``dev`` extra, so these run in CI; if it is somehow
absent the whole module is skipped rather than failing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("reportlab")

from agents.incident_report_agent import IncidentReportAgent
from agents.tools.pdf_report import render_markdown_to_pdf

_SAMPLE_MD = """# Incident Report

## Summary
Detected probable **authentication failure** activity from `10.0.0.5`.

## Severity
high

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | Brute Force (T1110) |

## Notes
- Repeated failed logins observed.
- Angle brackets <script> & ampersands are escaped, not rendered.
"""


def _assert_valid_pdf(path: Path) -> None:
    assert path.exists()
    data = path.read_bytes()
    assert data.startswith(b"%PDF-")  # magic header
    assert data.rstrip().endswith(b"%%EOF")  # complete document
    assert len(data) > 1000  # non-trivial content


def test_render_markdown_to_pdf_writes_valid_pdf(tmp_path: Path) -> None:
    out = render_markdown_to_pdf(_SAMPLE_MD, tmp_path / "report.pdf")
    _assert_valid_pdf(out)


def test_render_creates_parent_directories(tmp_path: Path) -> None:
    out = render_markdown_to_pdf("# Title\n\nBody.", tmp_path / "nested" / "deep" / "r.pdf")
    _assert_valid_pdf(out)


def test_hostile_markup_does_not_break_rendering(tmp_path: Path) -> None:
    # Content with XML/markup metacharacters must render (escaped), not raise.
    md = "# T\n\n<b>not bold</b> & <tag> `code` **bold** | pipes |"
    out = render_markdown_to_pdf(md, tmp_path / "x.pdf")
    _assert_valid_pdf(out)


def test_generate_report_emits_both_markdown_and_pdf(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    md_path = tmp_path / "incident.md"
    pdf_path = tmp_path / "incident.pdf"
    result = agent.generate_report(
        "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
        str(md_path),
        pdf_path=str(pdf_path),
    )
    assert result == md_path
    assert md_path.read_text(encoding="utf-8").startswith("# Incident Report")
    _assert_valid_pdf(pdf_path)


def test_generate_report_without_pdf_path_writes_no_pdf(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    md_path = tmp_path / "incident.md"
    agent.generate_report("some log line", str(md_path))
    assert md_path.exists()
    assert not list(tmp_path.glob("*.pdf"))
