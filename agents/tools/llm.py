"""Local LLM generation client (Ollama) — the sanctioned model capability surface.

`OllamaGenerator` calls a LOCAL Ollama server for text generation. It mirrors the
security posture of `rag.embeddings.OllamaEmbedder` (AGENTS.md §5): constrained to an
explicit host allow-list (loopback by default), bounded timeout, and **fail closed**
on any error — it never returns a partial or fabricated response.

Only the Python standard library is used (urllib), so the package keeps a
dependency-free core. Tests inject a fake transport; no network is touched in CI.

The default model is read from ``LLM_MODEL`` (default ``qwen3.5:9b`` — Apache-2.0,
~6.6GB Q4, 256K context) and the host from ``OLLAMA_HOST``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

from agents.tools.validation import ValidationError

# Transport seam: (url, json_body, timeout) -> decoded JSON response.
Transport = Callable[[str, dict[str, object], float], dict[str, object]]

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_MODEL = "qwen3.5:9b"
DEFAULT_HOST = "http://127.0.0.1:11434"
LLAMACPP_DEFAULT_HOST = "http://127.0.0.1:8080"

# GBNF grammar (llama.cpp) constraining the analyst narrative to a strict JSON object
# with exactly these three string fields, in order. Guarantees parseable output.
NARRATIVE_GRAMMAR = r"""
root ::= "{" ws "\"summary\"" ws ":" ws string ws "," ws "\"assessment\"" ws ":" ws string ws "," ws "\"recommended_next_step\"" ws ":" ws string ws "}"
string ::= "\"" ( [^"\\] | "\\" . )* "\""
ws ::= [ \t\n]*
"""


class Generator(Protocol):
    """Anything that turns a prompt into text (lets agents/tests inject a fake)."""

    def generate(self, prompt: str, *, system: str | None = None) -> str: ...


def _validate_local_host(host: str, allowed_hosts: frozenset[str], timeout: float) -> None:
    """Enforce the egress allow-list and bounds shared by every generator (§5)."""
    parsed = urlparse(host)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValidationError(f"invalid LLM host: {host!r}")
    if parsed.hostname not in allowed_hosts:
        raise ValidationError(
            f"host {parsed.hostname!r} not in egress allow-list {sorted(allowed_hosts)}"
        )
    if timeout <= 0:
        raise ValidationError("timeout must be positive")


def _urllib_transport(url: str, body: dict[str, object], timeout: float) -> dict[str, object]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})  # noqa: S310 - host allow-listed by OllamaGenerator.__post_init__
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 - scheme restricted to http/https and host allow-listed in __post_init__
            return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ValidationError(f"generation request failed: {exc}") from exc


@dataclass
class OllamaGenerator:
    """Text-generation backend backed by a local Ollama instance.

    Args:
        host: Base URL of the Ollama server (must resolve to an allowed host).
        model: Generation model name (default from ``LLM_MODEL``).
        timeout: Per-request timeout in seconds (bounded; fail closed).
        allowed_hosts: Host allow-list enforced before any request.
        transport: Injectable HTTP seam (defaults to stdlib urllib).
    """

    host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", DEFAULT_HOST))
    model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", DEFAULT_MODEL))
    timeout: float = 120.0
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    transport: Transport = field(default=_urllib_transport)

    def __post_init__(self) -> None:
        _validate_local_host(self.host, self.allowed_hosts, self.timeout)

    def generate(self, prompt: str, *, system: str | None = None) -> str:
        """Return the model's completion for ``prompt`` (non-streaming).

        Fails closed: a transport error, or a response missing a non-empty
        ``response`` field, raises :class:`ValidationError`.
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValidationError("prompt must be a non-empty string")
        url = f"{self.host.rstrip('/')}/api/generate"
        body: dict[str, object] = {"model": self.model, "prompt": prompt, "stream": False}
        if system:
            body["system"] = system
        payload = self.transport(url, body, self.timeout)
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            raise ValidationError("generator returned no 'response' text")
        return text


@dataclass
class LlamaCppGenerator:
    """Text-generation backend backed by a local ``llama-server`` (llama.cpp).

    Targets llama.cpp's OpenAI-compatible ``/v1/chat/completions`` endpoint. Same
    security posture as :class:`OllamaGenerator` (loopback allow-list, bounded
    timeout, fail closed). Use this for tighter resource control or GBNF
    grammar-constrained output; select it via ``LLM_BACKEND=llamacpp``.
    """

    host: str = field(
        default_factory=lambda: os.environ.get("LLAMACPP_HOST", LLAMACPP_DEFAULT_HOST)
    )
    model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", DEFAULT_MODEL))
    timeout: float = 120.0
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    transport: Transport = field(default=_urllib_transport)

    def __post_init__(self) -> None:
        _validate_local_host(self.host, self.allowed_hosts, self.timeout)

    def generate(
        self, prompt: str, *, system: str | None = None, grammar: str | None = None
    ) -> str:
        """Return the model's completion via the OpenAI-compatible chat endpoint.

        When ``grammar`` (a GBNF string) is supplied, it is sent to ``llama-server``
        so the output is constrained to that grammar — e.g. guaranteed-valid JSON.
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValidationError("prompt must be a non-empty string")
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        url = f"{self.host.rstrip('/')}/v1/chat/completions"
        body: dict[str, object] = {"model": self.model, "messages": messages, "stream": False}
        if grammar:
            body["grammar"] = grammar  # llama-server GBNF extension
        payload = self.transport(url, body, self.timeout)
        try:
            choices = payload["choices"]
            text = choices[0]["message"]["content"]  # type: ignore[index]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValidationError("generator returned no chat completion") from exc
        if not isinstance(text, str) or not text.strip():
            raise ValidationError("generator returned empty completion")
        return text

    def generate_json(
        self, prompt: str, *, system: str | None = None, grammar: str = NARRATIVE_GRAMMAR
    ) -> dict[str, Any]:
        """Generate GBNF-constrained output and return it parsed as a JSON object.

        Fails closed: output that is not a JSON object raises :class:`ValidationError`.
        """
        raw = self.generate(prompt, system=system, grammar=grammar)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"grammar-constrained output was not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValidationError("grammar-constrained output was not a JSON object")
        return parsed


def resolve_generator(env: dict[str, str] | None = None) -> Generator | None:
    """Build the configured local generator, or ``None`` to keep output deterministic.

    Controlled by environment (defaults in parentheses):
    - ``LLM_NARRATIVE`` (``auto``): ``off`` returns ``None`` (deterministic);
      ``auto``/``on`` return a generator (which fails soft at call time if the
      server is unreachable).
    - ``LLM_BACKEND`` (``ollama``): ``ollama`` or ``llamacpp``.

    Returns ``None`` (rather than raising) if the configured host is invalid, so a
    misconfiguration degrades to the deterministic report instead of breaking it.
    """
    environ = env if env is not None else dict(os.environ)
    mode = environ.get("LLM_NARRATIVE", "auto").strip().lower()
    if mode == "off":
        return None
    backend = environ.get("LLM_BACKEND", "ollama").strip().lower()
    model = environ.get("LLM_MODEL", DEFAULT_MODEL)
    try:
        if backend == "llamacpp":
            return LlamaCppGenerator(
                host=environ.get("LLAMACPP_HOST", LLAMACPP_DEFAULT_HOST), model=model
            )
        return OllamaGenerator(host=environ.get("OLLAMA_HOST", DEFAULT_HOST), model=model)
    except ValidationError:
        return None
