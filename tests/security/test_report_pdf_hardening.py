"""Security tests for the hardened Markdown → PDF report pipeline.

Incident reports interpolate untrusted log content; these tests pin the two
rendering controls: raw HTML is neutralized before Markdown rendering, and the
WeasyPrint URL fetcher refuses every external resource (SSRF guard). The pure
sanitization logic needs no renderer; HTML-rendering assertions skip cleanly
when the optional ``markdown`` package is absent.
"""

from __future__ import annotations

import pytest
from scripts.convert_report_to_pdf import (
    deny_url_fetcher,
    render_html,
    sanitize_markdown,
)


@pytest.mark.security
def test_sanitize_neutralizes_raw_html() -> None:
    hostile = 'Failed login <img src="http://attacker.example/x.png"> from 10.0.0.5'
    out = sanitize_markdown(hostile)
    assert "<img" not in out
    assert "&lt;img" in out


@pytest.mark.security
def test_sanitize_escapes_ampersand_first_no_double_escape() -> None:
    assert sanitize_markdown("&lt;b&gt;") == "&amp;lt;b&amp;gt;"
    assert sanitize_markdown("<b>") == "&lt;b>"


@pytest.mark.security
def test_sanitize_preserves_markdown_constructs() -> None:
    report = "# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n```text\ncode\n```\n- item\n> quote"
    assert sanitize_markdown(report) == report  # nothing markdown needs is touched


@pytest.mark.security
def test_deny_url_fetcher_refuses_everything() -> None:
    for url in (
        "http://169.254.169.254/latest/meta-data/",
        "https://attacker.example/exfil.css",
        "file:///etc/passwd",
        "data:text/css,body{}",
    ):
        with pytest.raises(ValueError, match="blocked by report policy"):
            deny_url_fetcher(url)


@pytest.mark.security
def test_render_html_keeps_injected_markup_inert() -> None:
    pytest.importorskip("markdown")
    hostile = '## Raw Log\n\n<script>alert(1)</script> and <img src="http://attacker.example/x">\n'
    html = render_html(hostile)
    assert "<script>" not in html
    assert '<img src="http://attacker.example/x"' not in html
    assert "&lt;script&gt;" in html


@pytest.mark.security
def test_render_html_still_renders_report_structure() -> None:
    pytest.importorskip("markdown")
    html = render_html("# Incident\n\n- `10.0.0.5`\n\n| k | v |\n|---|---|\n| a | b |")
    assert "<h1>Incident</h1>" in html
    assert "<code>10.0.0.5</code>" in html
    assert "<table>" in html
