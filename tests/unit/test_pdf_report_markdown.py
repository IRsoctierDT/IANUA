# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the pure-Python Markdown parsing in agents/tools/pdf_report.py.

These need no reportlab (the renderer imports it lazily), so they run even
where tests/unit/test_pdf_report.py is skipped for lack of it.
"""

from __future__ import annotations

import pytest

from agents.tools.pdf_report import _DIGEST_TABLE_SEP


@pytest.mark.unit
@pytest.mark.parametrize("row", ["|---|---|", "| :-- | --: |", "|--|--|", "  | --- | --- |  "])
def test_separator_rows_are_recognized(row: str) -> None:
    assert _DIGEST_TABLE_SEP.match(row)


@pytest.mark.unit
@pytest.mark.parametrize(
    "row",
    ["| --flag | value |", "| --no-verify | ran |", "| - | x |", "| Tactic | Credential Access |"],
)
def test_content_rows_are_not_dropped_as_separators(row: str) -> None:
    """Measured before the fix: both `--`-leading rows matched and were skipped."""
    assert not _DIGEST_TABLE_SEP.match(row)
