# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The dashboard's Ollama probe spawns the daemon at most once per process.

Measured on the base commit with the probe stubbed to "installed, not
answering": three calls — three Streamlit reruns — spawned three
``ollama serve`` processes and blocked for 30 simulated seconds.
"""

from __future__ import annotations

from typing import Any

import pytest

from dashboard import ollama_service as svc


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> tuple[list[dict[str, Any]], list[float]]:
    spawned: list[dict[str, Any]] = []
    clock = [0.0]

    def popen(argv: list[str], **kwargs: Any) -> None:
        spawned.append({"argv": argv, **kwargs})

    monkeypatch.setattr(svc, "_start_attempted", False)
    monkeypatch.setattr(svc.shutil, "which", lambda name: "/usr/local/bin/ollama")
    monkeypatch.setattr(svc, "is_ollama_running", lambda: False)
    monkeypatch.setattr(svc.subprocess, "Popen", popen)
    monkeypatch.setattr(svc.time, "time", lambda: clock[0])
    monkeypatch.setattr(svc.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    return spawned, clock


def test_three_reruns_spawn_once(harness: tuple[list[dict[str, Any]], list[float]]) -> None:
    spawned, clock = harness
    first = svc.ensure_ollama_running()
    later = [svc.ensure_ollama_running() for _ in range(2)]
    assert first == "Ollama start attempted but not responding"
    assert later == ["Ollama start attempted earlier but not responding (not retried)"] * 2
    assert len(spawned) == 1, "one daemon per process, not one per rerun"
    assert clock[0] == pytest.approx(10.0), "later reruns do not block on the start timeout"
    assert spawned[0]["argv"] == ["ollama", "serve"]
    assert spawned[0]["start_new_session"] is True


def test_no_spawn_when_running_or_absent(
    harness: tuple[list[dict[str, Any]], list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    spawned, _ = harness
    monkeypatch.setattr(svc, "is_ollama_running", lambda: True)
    assert svc.ensure_ollama_running() == "Ollama running"
    monkeypatch.setattr(svc.shutil, "which", lambda name: None)
    assert svc.ensure_ollama_running() == "Ollama not installed"
    assert spawned == [] and svc._start_attempted is False
