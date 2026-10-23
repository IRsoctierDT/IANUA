# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

import rag.qdrant
from rag.qdrant import QdrantPathError, embedded_path, make_client


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


def test_empty_path_variable_falls_back_to_anchored_default_not_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``QDRANT_PATH=`` (set but empty) must not plant the store in the CWD.

    The real anchor, unpatched: an earlier version of this test monkeypatched
    the default to an absolute path, which hid that ``"./data/qdrant"`` was
    itself CWD-relative. Resolution only -- nothing is created in the checkout.
    """
    monkeypatch.chdir(tmp_path)
    checkout = Path(rag.qdrant.__file__).resolve().parent.parent
    assert (checkout / "pyproject.toml").is_file()

    resolved = embedded_path("")

    assert resolved == checkout / "data" / "qdrant" == rag.qdrant.DEFAULT_EMBEDDED_PATH
    assert not resolved.is_relative_to(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_factory_creates_the_anchored_store_and_refuses_before_creating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_stub(monkeypatch)
    monkeypatch.delenv("QDRANT_URL", raising=False)
    checkout = (tmp_path / "checkout").resolve()
    (checkout / "data").mkdir(parents=True)
    monkeypatch.setattr("rag.qdrant._REPO_ROOT", checkout)
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")

    monkeypatch.setenv("QDRANT_PATH", "")
    client = make_client()
    assert isinstance(client, _StubClient)
    assert client.kwargs == {"path": str(checkout / "data" / "qdrant")}
    assert (checkout / "data" / "qdrant").is_dir()

    monkeypatch.setenv("QDRANT_PATH", " ")
    with pytest.raises(QdrantPathError):
        make_client()
    assert not (checkout / " ").exists()
    assert list((tmp_path / "cwd").iterdir()) == []


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
