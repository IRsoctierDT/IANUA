# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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


class _HostileFreeTextGenerator:
    """A model whose output a crafted log line steered into active Markdown."""

    def generate(self, prompt: str, *, system: str | None = None) -> str:
        return (
            "Root brute-force success.\n# INJECTED HEADING\n"
            "![beacon](https://attacker.example/px)\n| a | b |\n`live`\x00\x07" + "Z" * 5_000
        )


@pytest.mark.security
def test_free_text_narrative_is_escaped_like_any_untrusted_value(tmp_path: Path) -> None:
    """Model output is untrusted: it must get the same treatment as log text.

    Before the fix the free-text generator path was the one place the report
    wrote text verbatim — a heading, an image beacon, a NUL byte and 5,000
    characters all survived (measured). The structured path already escaped.
    """
    content = _report(
        tmp_path,
        "Failed password for root from 203.0.113.5 port 22 ssh2",
        generator=_HostileFreeTextGenerator(),
    )
    narrative = content.split("## Analyst Narrative (AI-generated)")[1].split("## Severity")[0]
    assert "brute-force success" in narrative  # the legitimate sentence survives
    assert "\n# INJECTED HEADING" not in narrative, "newline + heading must be flattened"
    assert "\x00" not in content and "\x07" not in content
    assert "| a | b |" not in narrative and "\\| a \\| b \\|" in narrative
    assert "`live`" not in narrative and "\\`live\\`" in narrative
    assert "…\\[truncated]" in narrative and len(narrative) < 700


@pytest.mark.security
def test_generator_error_text_is_escaped(tmp_path: Path) -> None:
    from agents.tools.validation import ValidationError

    class _NoisyFailure:
        def generate(self, prompt: str, *, system: str | None = None) -> str:
            raise ValidationError("bad output\n# not a heading | `tick`\x00")

    content = _report(tmp_path, "Failed password for root", generator=_NoisyFailure())
    assert "AI narrative unavailable" in content
    assert "\n# not a heading" not in content and "\x00" not in content
    assert "\\`tick\\`" in content


class _Says:
    def __init__(self, out: str) -> None:
        self.out = out

    def generate(self, prompt: str, *, system: str | None = None) -> str:
        return self.out


@pytest.mark.security
@pytest.mark.parametrize(
    ("out", "line"),
    [
        ("# Severity: LOW", "\\# Severity: LOW"),
        ("\x00 > quote", "\\> quote"),
        ("--- ", "\\---"),
        ("1. ordered", "1\\. ordered"),
        ("<div>x</div>", "\\<div>x\\</div>"),
        ("ok\u2028## Severity\u2029low\x85- fake", "ok ## Severity low - fake"),
    ],
)
def test_free_text_narrative_cannot_open_a_block(tmp_path: Path, out: str, line: str) -> None:
    """Measured before: a leading ``#`` rendered an ``<h1>`` and a PDF Title, and
    U+2028/U+2029/NEL survived ``_sanitize`` into the PDF renderer's
    ``splitlines()``, forging a ``## Severity`` heading there."""
    content = _report(tmp_path, "Failed password for root", generator=_Says(out))
    section = content.split("## Analyst Narrative (AI-generated)\n")[1].split("\n\n## Severity")[0]
    assert section.splitlines() == [line]


@pytest.mark.security
def test_links_images_html_and_backslashes_are_not_live() -> None:
    """Measured before: CommonMark rendered an ``<img>`` beacon, an ``<a>`` link
    and an autolink from this text, and ``\\`x`` re-armed an escaped backtick."""
    hostile = "![b](https://attacker.example/px) [l](u) <https://attacker.example> <img> \\`x`"
    assert _md_cell(hostile) == (
        "!\\[b](https://attacker.example/px) \\[l](u) \\<https://attacker.example> "
        "\\<img> \\\\\\`x\\`"
    )
