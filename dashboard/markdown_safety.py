# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Neutralize untrusted text before a Markdown-interpreting Streamlit widget.

``st.markdown``, ``st.caption`` and widget labels interpret Markdown, and
log-derived values reach them: a structured record's ``src_ip`` becomes the
batch tab's ``source``/``entity``, and its ``host``/``user``/``message`` land in
the report's evidence table. Measured on the base commit, a ``src_ip`` of
``x` ![b](https://evil.example/c.png) `y`` arrived in all of them verbatim —
the backtick closes the code span the dashboard wrapped it in, and the image
makes the analyst's browser fetch an attacker's URL, the beacon class
``scripts/convert_report_to_pdf.py`` already refuses with a deny-all fetcher.

Security consideration: this is the render boundary. Streamlit sanitizes raw
HTML already; this backslash-escapes every ASCII punctuation character (which
CommonMark renders literally), flattens whitespace, strips controls, caps length.
"""

from __future__ import annotations

import re
import string

#: Same cap as ``agents/incident_report_agent.py::_MAX_INLINE_LEN``.
MAX_INLINE_LEN = 500

_PUNCTUATION_RE = re.compile(f"([{re.escape(string.punctuation)}])")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _flatten(text: object) -> str:
    flat = " ".join(_CONTROL_CHARS_RE.sub("", str(text)).split())
    if len(flat) > MAX_INLINE_LEN:
        flat = flat[:MAX_INLINE_LEN] + " …[truncated]"
    return flat


def inert(text: object) -> str:
    """Return ``text`` for a plain Markdown position with no live syntax left.

    ``![b](url)`` renders as those nine characters: nothing is fetched, linked,
    emphasised or styled. Inside a code span use :func:`code_span` instead.
    """
    return _PUNCTUATION_RE.sub(r"\\\1", _flatten(text))


def code_span(text: object) -> str:
    """Return ``text`` for *inside* a single-backtick code span.

    Backslash escapes do not work there, so the backtick — the one character
    that can end the span — becomes an apostrophe, the visible substitution
    ``agents/incident_report_agent.py::_md_code`` makes. The rest is literal.
    """
    return _flatten(text).replace("`", "'")
