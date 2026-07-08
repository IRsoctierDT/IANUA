"""Render an incident-report Markdown document to PDF (pure-Python, reportlab).

Purpose: a portable, client-ready PDF of the deterministic incident report, with
no HTML/CSS engine or system libraries (unlike WeasyPrint) — reportlab is
pure-Python and CI-friendly.

Security notes (AGENTS.md §5):
- Input is the *already-generated* report Markdown (trusted, produced by
  :class:`agents.incident_report_agent.IncidentReportAgent`). Text is XML-escaped
  before it reaches reportlab's paragraph markup, so report content cannot inject
  markup.
- Output is confined to the caller-supplied path; the caller owns placement.
- ``reportlab`` is an **optional** dependency (``pip install -e '.[pdf]'``);
  importing this module's renderer without it raises a clear, actionable error
  rather than failing obscurely.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_DIGEST_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}")


def _escape(text: str) -> str:
    """XML-escape, then re-apply a tiny, safe subset of inline Markdown."""
    safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
    return re.sub(r"`([^`]+?)`", r'<font face="Courier">\1</font>', safe)


def _split_row(line: str) -> list[str]:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def render_markdown_to_pdf(markdown: str, output_path: str | Path) -> Path:
    """Render ``markdown`` to a PDF at ``output_path`` and return the path.

    Supports the subset the incident report uses: ``#``/``##``/``###`` headings,
    ``|`` tables, ``-`` bullets, fenced code blocks, and paragraphs (with
    ``**bold**`` and ``` `code` ```). Raises :class:`RuntimeError` if the optional
    ``reportlab`` dependency is not installed.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised via a stubbed import in tests
        raise RuntimeError(
            "PDF export requires the optional 'reportlab' dependency; "
            "install it with:  pip install -e '.[pdf]'"
        ) from exc

    styles = getSampleStyleSheet()
    heading = {1: styles["Title"], 2: styles["Heading2"], 3: styles["Heading3"]}
    flow: list[Any] = []

    lines = markdown.splitlines()
    i = 0
    in_code = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            in_code = not in_code
            i += 1
            continue
        if in_code:
            flow.append(Paragraph(_escape(line) or "&nbsp;", styles["Code"]))
            i += 1
            continue
        if not stripped:
            flow.append(Spacer(1, 6))
            i += 1
            continue

        # Table: consecutive lines starting with '|'.
        if stripped.startswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                if not _DIGEST_TABLE_SEP.match(lines[i]):  # skip the |---|---| rule
                    rows.append([_escape(c) for c in _split_row(lines[i])])
                i += 1
            if rows:
                cells = [[Paragraph(c, styles["BodyText"]) for c in row] for row in rows]
                table = Table(cells, hAlign="LEFT")
                table.setStyle(
                    TableStyle(
                        [
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                flow.append(table)
                flow.append(Spacer(1, 6))
            continue

        match = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if match:
            level = len(match.group(1))
            flow.append(Paragraph(_escape(match.group(2)), heading[level]))
        elif stripped.startswith(("- ", "* ")):
            flow.append(Paragraph(f"• {_escape(stripped[2:])}", styles["BodyText"]))
        else:
            flow.append(Paragraph(_escape(stripped), styles["BodyText"]))
        i += 1

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(target),
        pagesize=letter,
        title="Incident Report",
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    doc.build(flow or [Paragraph("(empty report)", styles["BodyText"])])
    return target
