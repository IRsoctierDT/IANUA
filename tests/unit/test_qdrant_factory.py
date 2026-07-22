"""Tests for the env-driven Qdrant client factory (``rag.qdrant``).

The real ``qdrant-client`` package is an optional extra and is not required
here: a stub module is injected into ``sys.modules`` so the factory's
selection logic (embedded-by-default, server by opt-in, actionable error on a
minimal install) is pinned without heavy dependencies or any network/service.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest
from rag.qdrant import make_client


class _StubClient:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _install_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = types.ModuleType("qdrant_client")
    stub.QdrantClient = _StubClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "qdrant_client", stub)


def test_default_is_embedded_with_no_listening_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_stub(monkeypatch)
    monkeypatch.delenv("QDRANT_URL", raising=False)
    monkeypatch.setenv("QDRANT_PATH", str(tmp_path / "embedded"))

    client = make_client()

    assert isinstance(client, _StubClient)
    assert client.kwargs == {"path": str(tmp_path / "embedded")}
    assert (tmp_path / "embedded").is_dir()  # created eagerly for the store


def test_url_opts_in_to_server_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_stub(monkeypatch)
    monkeypatch.setenv("QDRANT_URL", "http://127.0.0.1:6333")

    client = make_client()

    assert isinstance(client, _StubClient)
    assert client.kwargs["url"] == "http://127.0.0.1:6333"
    assert client.kwargs["check_compatibility"] is False


def test_missing_dependency_raises_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QDRANT_URL", raising=False)
    monkeypatch.setitem(sys.modules, "qdrant_client", None)  # simulate absent package

    with pytest.raises(RuntimeError, match=r"\.\[dashboard\]"):
        make_client()
