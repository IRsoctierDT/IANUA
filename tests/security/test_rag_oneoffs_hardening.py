# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Hardening tests for the one-off KB ingest scripts under ``scripts/``.

They run at import and need the ``dashboard`` extra, so they are checked
*statically* (AST: discovery goes through ``rag.ingest.discover_documents``,
never a bare ``glob``/``rglob``; measured, ``rglob`` + ``read_text`` followed a
file symlink out of the corpus) and *dynamically* (``sys.modules`` stubs, the
seam ``test_qdrant_factory.py`` uses; run from a foreign working directory;
upserted points must carry repo-relative ``source`` values and the payload
keys the dashboard reads).
"""

from __future__ import annotations

import ast
import functools
import runpy
import sys
import types
from pathlib import Path
from typing import Any, ClassVar
from uuid import NAMESPACE_URL, uuid5

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = _REPO_ROOT / "scripts"
_INGEST_SCRIPTS = ("ingest_cyber_kb.py", "ingest_cyber_kb_chunked.py")
_ASK_SCRIPTS = ("ask_cyber_kb_ollama.py", "ask_cyber_kb_chunked_ollama.py")
#: Every script in the block: no host literal anywhere, Qdrant only via the factory.
_BLOCK_SCRIPTS = (
    *_INGEST_SCRIPTS,
    *_ASK_SCRIPTS,
    "ask_cyber_kb.py",
    "search_cyber_kb.py",
    "search_cyber_kb_chunked.py",
    "create_cyber_collection.py",
    "test_embeddings_qdrant.py",
    "rag_cli.py",
)
#: Any of these inside a string literal is a hard-coded host/port (AGENTS.md section 4).
_HOST_LITERAL_FRAGMENTS = ("11434", "localhost", "127.0.0.1", "http://", "https://")
#: Discovery primitives that would bypass ``discover_documents``'s controls.
_DISCOVERY_BYPASSES = frozenset({"glob", "rglob", "iterdir", "walk", "scandir", "listdir"})


# ------------------------------------------------------------------ static
def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


@pytest.mark.security
@pytest.mark.parametrize("script", _INGEST_SCRIPTS)
def test_ingest_scripts_discover_only_through_rag_ingest(script: str) -> None:
    tree = ast.parse((_SCRIPTS / script).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "rag.ingest"
        for alias in node.names
    }
    assert "discover_documents" in imported, f"{script} must import rag.ingest.discover_documents"
    called = {call.func.id for call in _calls(tree) if isinstance(call.func, ast.Name)}
    assert "discover_documents" in called, f"{script} must call discover_documents"
    bypasses = sorted(
        call.func.attr
        for call in _calls(tree)
        if isinstance(call.func, ast.Attribute) and call.func.attr in _DISCOVERY_BYPASSES
    )
    assert not bypasses, f"{script} discovers documents outside rag.ingest via {bypasses}"


# ----------------------------------------------------------------- dynamic
class _Encoded:
    def __init__(self, text: str) -> None:
        self._vector = [float(len(text) % 7), 1.0]

    def tolist(self) -> list[float]:
        return self._vector

    def __len__(self) -> int:
        return len(self._vector)


class _StubModel:
    def __init__(self, name: str) -> None:
        self.name = name

    def encode(self, text: str) -> _Encoded:
        return _Encoded(text)


class _StubPoint:
    def __init__(self, id: Any, vector: Any, payload: dict[str, Any]) -> None:
        self.id = id
        self.vector = vector
        self.payload = payload


class _StubClient:
    instances: ClassVar[list[_StubClient]] = []
    canned_points: ClassVar[list[Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.created: list[str] = []
        self.upserts: list[tuple[str, list[_StubPoint]]] = []
        _StubClient.instances.append(self)

    def get_collections(self) -> Any:
        return types.SimpleNamespace(
            collections=[types.SimpleNamespace(name=n) for n in self.created]
        )

    def create_collection(self, collection_name: str, vectors_config: Any) -> None:
        self.created.append(collection_name)

    def upsert(self, collection_name: str, points: list[_StubPoint]) -> None:
        self.upserts.append((collection_name, list(points)))

    def query_points(self, **kwargs: Any) -> Any:
        return types.SimpleNamespace(points=list(self.canned_points))


def _install_stubs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    qdrant = types.ModuleType("qdrant_client")
    qdrant.QdrantClient = _StubClient  # type: ignore[attr-defined]
    models = types.ModuleType("qdrant_client.models")
    models.PointStruct = _StubPoint  # type: ignore[attr-defined]
    models.VectorParams = lambda **kwargs: kwargs  # type: ignore[attr-defined]
    models.Distance = types.SimpleNamespace(COSINE="Cosine")  # type: ignore[attr-defined]
    transformers = types.ModuleType("sentence_transformers")
    transformers.SentenceTransformer = _StubModel  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "qdrant_client", qdrant)
    monkeypatch.setitem(sys.modules, "qdrant_client.models", models)
    monkeypatch.setitem(sys.modules, "sentence_transformers", transformers)
    monkeypatch.delenv("QDRANT_URL", raising=False)
    monkeypatch.setenv("QDRANT_PATH", str(tmp_path / "qdrant"))
    # The corpus root must not depend on the working directory.
    monkeypatch.chdir(tmp_path)
    _StubClient.instances.clear()
    _StubClient.canned_points = [
        types.SimpleNamespace(
            score=0.9,
            payload={
                "source": "knowledge-base/x.md",
                "chunk_index": 0,
                "text": "RETRIEVED-PASSAGE",
            },
        )
    ]


def _run(script: str) -> list[_StubPoint]:
    runpy.run_path(str(_SCRIPTS / script), run_name="__main__")
    (client,) = _StubClient.instances
    return [point for _, batch in client.upserts for point in batch]


@pytest.mark.security
@pytest.mark.parametrize("script", _INGEST_SCRIPTS)
def test_ingest_scripts_store_repo_relative_sources_from_any_cwd(
    script: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_stubs(monkeypatch, tmp_path)
    points = _run(script)
    assert points, f"{script} ingested nothing from the shipped knowledge-base"
    for point in points:
        source = point.payload["source"]
        assert not Path(source).is_absolute(), source
        assert source.startswith("knowledge-base/"), source
        assert (_REPO_ROOT / source).is_file(), source
        assert isinstance(point.payload["text"], str) and point.payload["text"]


@pytest.mark.security
def test_chunked_ingest_keeps_the_payload_shape_the_dashboard_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_stubs(monkeypatch, tmp_path)
    points = _run("ingest_cyber_kb_chunked.py")
    assert points
    for point in points:
        assert set(point.payload) == {"source", "category", "chunk_index", "text"}
        assert point.payload["category"] == Path(point.payload["source"]).parent.name
        assert isinstance(point.payload["chunk_index"], int)


@pytest.mark.security
@pytest.mark.parametrize("script", _INGEST_SCRIPTS)
def test_ingest_point_ids_derive_from_identity_not_position(
    script: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-running an ingest must upsert each document in place (AGENTS.md section 3).

    Measured before the fix, ``ingest_cyber_kb.py`` numbered points by
    enumeration order, so adding one document renumbered every existing id and
    the next upsert overwrote unrelated points. Both one-offs now derive the id
    from the repo-relative ``source`` (plus chunk index for the chunked one).
    """
    _install_stubs(monkeypatch, tmp_path)
    points = _run(script)
    assert points
    ids = [point.id for point in points]
    assert len(set(ids)) == len(ids), "point ids must be unique"
    for point in points:
        key = point.payload["source"]
        if "chunk_index" in point.payload:
            key = f"{key}:{point.payload['chunk_index']}"
        assert point.id == str(uuid5(NAMESPACE_URL, key)), (point.id, key)


# -------------------------------------------------------------- ask scripts
@pytest.mark.security
@pytest.mark.parametrize("script", _ASK_SCRIPTS)
def test_ask_scripts_carry_no_host_literal_and_no_requests(script: str) -> None:
    """Generation goes through the allow-listed adapter; no literal host, no `requests`."""
    tree = ast.parse((_SCRIPTS / script).read_text(encoding="utf-8"))
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names
    }
    assert "requests" not in modules, f"{script} imports the undeclared `requests`"
    assert "agents.tools.llm" in modules, f"{script} must generate through OllamaGenerator"
    offenders = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and any(fragment in n.value for fragment in _HOST_LITERAL_FRAGMENTS)
    ]
    assert not offenders, f"{script} hard-codes a host/port: {offenders}"


def _fake_generation(monkeypatch: pytest.MonkeyPatch, calls: list[Any]) -> None:
    import agents.tools.llm as llm

    def transport(url: str, body: dict[str, object], timeout: float) -> dict[str, object]:
        calls.append((url, body, timeout))
        return {"response": "STUB-ANSWER"}

    monkeypatch.setattr(
        llm, "OllamaGenerator", functools.partial(llm.OllamaGenerator, transport=transport)
    )


@pytest.mark.security
@pytest.mark.parametrize("script", _ASK_SCRIPTS)
def test_ask_scripts_generate_via_env_host_with_the_data_flow_intact(
    script: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "QUESTION-TEXT")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    calls: list[Any] = []
    _fake_generation(monkeypatch, calls)
    runpy.run_path(str(_SCRIPTS / script), run_name="__main__")
    ((url, body, timeout),) = calls
    assert url == "http://127.0.0.1:11434/api/generate"
    assert body["model"] == "qwen3:4b" and body["stream"] is False and timeout > 0
    assert "QUESTION-TEXT" in str(body["prompt"]) and "RETRIEVED-PASSAGE" in str(body["prompt"])
    assert "STUB-ANSWER" in capsys.readouterr().out


@pytest.mark.security
@pytest.mark.parametrize("script", _ASK_SCRIPTS)
def test_ask_scripts_refuse_a_non_loopback_host_before_asking_or_sending(
    script: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_stubs(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "builtins.input", lambda _prompt="": pytest.fail("input() reached before host validation")
    )
    monkeypatch.setenv("OLLAMA_HOST", "http://kb.example.invalid:11434")
    calls: list[Any] = []
    _fake_generation(monkeypatch, calls)
    with pytest.raises(SystemExit) as info:
        runpy.run_path(str(_SCRIPTS / script), run_name="__main__")
    assert "not in egress allow-list" in str(info.value)
    assert calls == [], "no request may leave before the host is validated"


# ------------------------------------------------------------ whole block
@pytest.mark.security
@pytest.mark.parametrize("script", _BLOCK_SCRIPTS)
def test_block_scripts_carry_no_host_literal_and_use_the_qdrant_factory(script: str) -> None:
    """No hard-coded host/port (AGENTS.md section 4); Qdrant only via ``make_client``.

    Measured before the fix, ``test_embeddings_qdrant.py`` built
    ``QdrantClient(url="http://localhost:6333")`` directly -- the one script
    that forced server mode regardless of ``QDRANT_URL``/``QDRANT_PATH``.
    """
    tree = ast.parse((_SCRIPTS / script).read_text(encoding="utf-8"))
    offenders = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and any(fragment in n.value for fragment in _HOST_LITERAL_FRAGMENTS)
    ]
    assert not offenders, f"{script} hard-codes a host/port: {offenders}"
    direct = [
        alias.name
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module == "qdrant_client"
        for alias in n.names
        if alias.name == "QdrantClient"
    ] + [
        n.func.id
        for n in _calls(tree)
        if isinstance(n.func, ast.Name) and n.func.id == "QdrantClient"
    ]
    assert not direct, f"{script} builds a QdrantClient outside rag.qdrant.make_client"


@pytest.mark.security
def test_embeddings_smoke_script_is_embedded_unless_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install_stubs(monkeypatch, tmp_path)
    runpy.run_path(str(_SCRIPTS / "test_embeddings_qdrant.py"), run_name="__main__")
    (client,) = _StubClient.instances
    assert "url" not in client.kwargs, client.kwargs
    assert client.kwargs["path"] == str(tmp_path / "qdrant")
    assert "Embedding dimensions: 2" in capsys.readouterr().out
