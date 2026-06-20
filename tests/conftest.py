"""Shared test fixtures.

Keep the suite deterministic and network-free: the orchestrator enables the LLM
narrative by default (``LLM_NARRATIVE=auto``), so disable it for tests unless a
test opts in explicitly. Tests that exercise the LLM path inject a fake generator.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_llm_narrative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_NARRATIVE", "off")
