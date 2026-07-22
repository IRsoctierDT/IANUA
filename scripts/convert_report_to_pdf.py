#!/usr/bin/env python3
"""Convert the Markdown incident report to PDF — hardened rendering path.

Incident reports interpolate **untrusted input** (raw log lines, indicators,
attacker-controlled strings) into Markdown. Two hardening controls protect the
Markdown → HTML → PDF pipeline:

1. **Raw-markup neutralization** — ``python-markdown`` passes raw HTML through
   by default, so a log line like ``<img src=...>`` or ``<style>`` would reach
   the HTML renderer as live markup. ``&`` and ``<`` are escaped *before*
   Markdown rendering: Markdown syntax (headings, tables, fences, backticks)
   is unaffected, while embedded HTML is rendered as visible text.
2. **No external fetches (SSRF guard)** — WeasyPrint's default URL fetcher
   retrieves external resources (``img src``, CSS ``url()``), which would let
   report *content* trigger network requests during rendering. A deny-all
   fetcher refuses every URL, so PDF generation is fully offline.

Heavy renderer imports (``markdown``, ``weasyprint``) are deferred so the
sanitization logic stays importable/testable on minimal installs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SOURCE = Path("reports/markdown/sample_incident_report.md")
TARGET = Path("reports/pdf/sample_incident_report.pdf")

_HTML_TEMPLATE = """
<html>
<head>
<meta charset="utf-8">
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    line-height: 1.6;
}}
h1 {{
    color: #1f2937;
}}
h2 {{
    color: #374151;
}}
code {{
    background-color: #f3f4f6;
    padding: 2px 4px;
}}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def sanitize_markdown(text: str) -> str:
    """Neutralize raw HTML in Markdown source from untrusted inputs.

    Escapes ``&`` then ``<`` so embedded markup becomes inert text while every
    Markdown construct the reports use (headings, lists, tables, fenced code,
    inline code, blockquotes) renders unchanged.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;")


def deny_url_fetcher(url: str, *args: Any, **kwargs: Any) -> Any:
    """WeasyPrint URL fetcher that refuses every resource (SSRF guard)."""
    raise ValueError(f"external resource fetch blocked by report policy: {url}")


def render_html(markdown_text: str) -> str:
    """Render sanitized Markdown into the styled, self-contained HTML shell."""
    import markdown

    body = markdown.markdown(sanitize_markdown(markdown_text), extensions=["tables", "fenced_code"])
    return _HTML_TEMPLATE.format(body=body)


def convert(source: Path = SOURCE, target: Path = TARGET) -> Path:
    """Convert ``source`` Markdown to a PDF at ``target`` (offline, sanitized)."""
    from weasyprint import HTML

    if not source.exists():
        raise FileNotFoundError(f"Source report not found: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)

    html_document = render_html(source.read_text(encoding="utf-8"))
    HTML(string=html_document, base_url=None, url_fetcher=deny_url_fetcher).write_pdf(str(target))
    return target


def main() -> int:
    """CLI entry point. Returns a process exit code."""
    target = convert()
    print(f"Generated PDF: {target}")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
