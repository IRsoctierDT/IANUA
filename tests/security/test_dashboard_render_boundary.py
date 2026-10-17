# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests: the dashboard's Markdown render boundary.

Measured on the base commit, a structured record's ``src_ip`` of
``x` ![b](https://evil.example/c.png) `y`` reached the batch tab's ``source``,
``entity``, ``description`` and ``summary`` verbatim, and the report it passed
whole to ``st.markdown``. Pinned by AST (``app.py`` needs Streamlit): untrusted
values reach a Markdown widget only neutralized, file contents never. The rules
run against planted snippets first, so a rule that stopped matching fails.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from dashboard.markdown_safety import MAX_INLINE_LEN, code_span, inert

_DASHBOARD = Path(__file__).resolve().parents[2] / "dashboard"
_SINKS = {"markdown", "caption", "expander", "write", "info", "warning", "error", "success"}
_UNTRUSTED = {"source", "entity", "description", "summary", "snippet", "log", "message", "user"}
_HOSTILE = "x` ![b](https://evil.example/c.png) `y [l](https://evil.example/l) $m$ :red[t]"
_UNESCAPE = re.compile(r"\\(.)")


def _sinks(tree: ast.AST) -> list[ast.Call]:
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and getattr(n.func.value, "id", None) == "st"
        and n.func.attr in _SINKS
    ]


def _raw_untrusted(call: ast.Call) -> list[str]:
    """Untrusted-key subscripts in the call's arguments not under a neutralizer."""
    found: list[str] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in {"inert", "code_span"}:
            return
        if isinstance(node, ast.Subscript):
            key = getattr(node.slice, "value", None)
            if key in _UNTRUSTED:
                found.append(f"{node.lineno}:{key}")
        for child in ast.iter_child_nodes(node):
            visit(child)

    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        visit(arg)
    return found


def _file_reads(call: ast.Call) -> list[str]:
    return [
        f"{n.lineno}:{n.func.attr}"
        for arg in [*call.args, *(kw.value for kw in call.keywords)]
        for n in ast.walk(arg)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in {"read_text", "read_bytes", "read"}
    ]


@pytest.mark.security
def test_neutralizers_leave_no_live_markdown() -> None:
    out = inert(_HOSTILE)
    singles = [t for t in re.findall(r"\\.|[^\\]", out) if len(t) == 1]
    assert not [c for c in singles if c in "!`[]()$:*_<>|#"], out
    assert _UNESCAPE.sub(r"\1", out) == _HOSTILE, "nothing dropped: the analyst reads the log"
    spanned = code_span(_HOSTILE)
    assert "`" not in spanned and "![b](https://evil.example/c.png)" in spanned


@pytest.mark.security
@pytest.mark.parametrize("neutralize", [inert, code_span])
def test_flattened_and_capped(neutralize: Callable[[object], str]) -> None:
    out = neutralize("a\n# heading\r\n\x00\x07b\ttail")
    assert not set(out) & set("\n\r\x00\x07") and out.startswith("a ")
    capped = neutralize("a" * (MAX_INLINE_LEN * 4))
    assert _UNESCAPE.sub(r"\1", capped) == "a" * MAX_INLINE_LEN + " …[truncated]"
    assert neutralize(10.5) == ("10\\.5" if neutralize is inert else "10.5")


@pytest.mark.security
def test_rules_catch_planted_routes() -> None:
    planted = (
        "st.markdown(f\"`{sl['source']}` {inert(rf['entity'])}\")\n"
        'st.caption(seq["summary"])\n'
        "st.expander(f\"Risk story for {code_span(rf['entity'])}\")\n"
        'st.markdown(report.read_text(encoding="utf-8"))\n'
        'st.code(report.read_text(encoding="utf-8"))\n'
    )
    calls = _sinks(ast.parse(planted))
    assert len(calls) == 4, "st.code is not a Markdown sink"
    assert [_raw_untrusted(c) for c in calls] == [["1:source"], ["2:summary"], [], []]
    assert [_file_reads(c) for c in calls] == [[], [], [], ["4:read_text"]]


@pytest.mark.security
def test_app_renders_untrusted_text_neutralized_never_files_and_never_raw_html() -> None:
    calls = _sinks(ast.parse((_DASHBOARD / "app.py").read_text(encoding="utf-8")))
    assert len(calls) >= 20, "app.py renders through st.markdown and friends; none found?"
    assert [h for c in calls for h in _raw_untrusted(c)] == [], "log-derived value rendered raw"
    assert [h for c in calls for h in _file_reads(c)] == [], "a file rendered as Markdown"
    sources = {p.name: p.read_text(encoding="utf-8") for p in _DASHBOARD.glob("*.py")}
    assert not [n for n, s in sources.items() if "unsafe_allow_html=True" in s.replace(" ", "")]
