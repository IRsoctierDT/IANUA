"""Tests for the local LLM generation client (no network — injected transport)."""

from collections.abc import Callable

import pytest
from agents.tools.llm import DEFAULT_MODEL, OllamaGenerator
from agents.tools.validation import ValidationError

Transport = Callable[[str, dict, float], dict]


def _ok_transport(response: str) -> Transport:
    def _t(url: str, body: dict, timeout: float) -> dict:
        return {"response": response}

    return _t


@pytest.mark.unit
def test_generates_text() -> None:
    gen = OllamaGenerator(transport=_ok_transport("hello world"))
    assert gen.generate("summarize this") == "hello world"


@pytest.mark.unit
def test_default_model_is_configured_choice() -> None:
    assert DEFAULT_MODEL == "qwen3.5:9b"
    assert OllamaGenerator(transport=_ok_transport("x")).model == "qwen3.5:9b"


@pytest.mark.unit
def test_sends_model_and_prompt() -> None:
    captured: dict = {}

    def _t(url: str, body: dict, timeout: float) -> dict:
        captured.update(body)
        captured["url"] = url
        return {"response": "ok"}

    OllamaGenerator(model="qwen3.5:9b", transport=_t).generate("the facts", system="be terse")
    assert captured["model"] == "qwen3.5:9b"
    assert captured["prompt"] == "the facts"
    assert captured["system"] == "be terse"
    assert captured["stream"] is False
    assert captured["url"].endswith("/api/generate")


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_prompt_raises(bad: str) -> None:
    with pytest.raises(ValidationError):
        OllamaGenerator(transport=_ok_transport("x")).generate(bad)


@pytest.mark.unit
def test_empty_response_fails_closed() -> None:
    with pytest.raises(ValidationError):
        OllamaGenerator(transport=_ok_transport("")).generate("x")


@pytest.mark.security
def test_non_loopback_host_is_blocked() -> None:
    with pytest.raises(ValidationError):
        OllamaGenerator(host="http://evil.example:11434")


@pytest.mark.security
def test_invalid_host_is_blocked() -> None:
    with pytest.raises(ValidationError):
        OllamaGenerator(host="not-a-url")


@pytest.mark.unit
def test_non_positive_timeout_raises() -> None:
    with pytest.raises(ValidationError):
        OllamaGenerator(timeout=0)
