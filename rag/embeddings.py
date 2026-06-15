"""Embedding backends for the RAG pipeline.

`OllamaEmbedder` calls a LOCAL Ollama server for embeddings. Per AGENTS.md §5
(default-deny egress) it is constrained to an explicit host allow-list, uses a
bounded timeout, and fails closed on any error -- it never silently returns a
partial or zero vector.

Only the Python standard library is used (urllib), so the package has no extra
runtime dependency. Tests inject a fake transport; no network is touched in CI.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlparse

from agents.tools.validation import ValidationError

# Transport seam: (url, json_body, timeout) -> decoded JSON response.
Transport = Callable[[str, dict[str, object], float], dict[str, object]]

# Default-deny: only loopback hosts are allowed unless explicitly extended.
DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def _urllib_transport(url: str, body: dict[str, object], timeout: float) -> dict[str, object]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - host allow-listed below
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValidationError(f"embedding request failed: {exc}") from exc


@dataclass
class OllamaEmbedder:
    """Embedding backend backed by a local Ollama instance.

    Args:
        host: Base URL of the Ollama server (must resolve to an allowed host).
        model: Embedding model name (e.g. ``nomic-embed-text``).
        timeout: Per-request timeout in seconds (bounded; fail closed).
        allowed_hosts: Host allow-list enforced before any request.
        transport: Injectable HTTP seam (defaults to stdlib urllib).
    """

    host: str = "http://127.0.0.1:11434"
    model: str = "nomic-embed-text"
    timeout: float = 30.0
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    transport: Transport = field(default=_urllib_transport)

    def __post_init__(self) -> None:
        parsed = urlparse(self.host)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValidationError(f"invalid Ollama host: {self.host!r}")
        if parsed.hostname not in self.allowed_hosts:
            raise ValidationError(
                f"host {parsed.hostname!r} not in egress allow-list {sorted(self.allowed_hosts)}"
            )
        if self.timeout <= 0:
            raise ValidationError("timeout must be positive")

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Return one embedding vector per input text (order preserved)."""
        url = f"{self.host.rstrip('/')}/api/embeddings"
        vectors: list[list[float]] = []
        for text in texts:
            if not isinstance(text, str):
                raise ValidationError("each input must be a string")
            payload = self.transport(url, {"model": self.model, "prompt": text}, self.timeout)
            vector = payload.get("embedding")
            if not isinstance(vector, list) or not vector:
                raise ValidationError("embedder returned no 'embedding' vector")
            vectors.append([float(x) for x in vector])
        return vectors
