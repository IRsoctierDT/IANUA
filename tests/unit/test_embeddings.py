"""Unit + security tests for OllamaEmbedder (no real network in CI)."""

import pytest
from agents.tools.validation import ValidationError
from rag.embeddings import OllamaEmbedder


def fake_transport(url, body, timeout):
    # Deterministic, offline stand-in for the Ollama /api/embeddings response.
    return {"embedding": [0.1, 0.2, 0.3]}


@pytest.mark.unit
def test_embeds_via_injected_transport() -> None:
    emb = OllamaEmbedder(transport=fake_transport)
    out = emb.embed(["hello", "world"])
    assert out == [[0.1, 0.2, 0.3], [0.1, 0.2, 0.3]]


@pytest.mark.security
def test_rejects_non_allowlisted_host() -> None:
    with pytest.raises(ValidationError):
        OllamaEmbedder(host="http://evil.example.com:11434", transport=fake_transport)


@pytest.mark.security
def test_rejects_bad_scheme() -> None:
    with pytest.raises(ValidationError):
        OllamaEmbedder(host="ftp://127.0.0.1", transport=fake_transport)


@pytest.mark.security
def test_fails_closed_on_empty_vector() -> None:
    emb = OllamaEmbedder(transport=lambda u, b, t: {"embedding": []})
    with pytest.raises(ValidationError):
        emb.embed(["x"])


@pytest.mark.security
def test_rejects_nonpositive_timeout() -> None:
    with pytest.raises(ValidationError):
        OllamaEmbedder(timeout=0, transport=fake_transport)
