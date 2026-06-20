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


# --- llama.cpp backend -------------------------------------------------------


@pytest.mark.unit
def test_llamacpp_generates_via_chat_endpoint() -> None:
    from agents.tools.llm import LlamaCppGenerator

    captured: dict = {}

    def _t(url: str, body: dict, timeout: float) -> dict:
        captured["url"] = url
        captured["messages"] = body["messages"]
        return {"choices": [{"message": {"content": "incident summary"}}]}

    out = LlamaCppGenerator(transport=_t).generate("facts", system="be terse")
    assert out == "incident summary"
    assert captured["url"].endswith("/v1/chat/completions")
    assert captured["messages"][0]["role"] == "system"
    assert captured["messages"][-1]["content"] == "facts"


@pytest.mark.unit
def test_llamacpp_malformed_response_fails_closed() -> None:
    from agents.tools.llm import LlamaCppGenerator

    def _t(url: str, body: dict, timeout: float) -> dict:
        return {"unexpected": True}

    with pytest.raises(ValidationError):
        LlamaCppGenerator(transport=_t).generate("x")


@pytest.mark.security
def test_llamacpp_non_loopback_host_blocked() -> None:
    from agents.tools.llm import LlamaCppGenerator

    with pytest.raises(ValidationError):
        LlamaCppGenerator(host="http://evil.example:8080")


# --- resolve_generator -------------------------------------------------------


@pytest.mark.unit
def test_resolve_off_returns_none() -> None:
    from agents.tools.llm import resolve_generator

    assert resolve_generator({"LLM_NARRATIVE": "off"}) is None


@pytest.mark.unit
def test_resolve_default_is_ollama() -> None:
    from agents.tools.llm import OllamaGenerator, resolve_generator

    assert isinstance(resolve_generator({}), OllamaGenerator)


@pytest.mark.unit
def test_resolve_llamacpp_backend() -> None:
    from agents.tools.llm import LlamaCppGenerator, resolve_generator

    assert isinstance(resolve_generator({"LLM_BACKEND": "llamacpp"}), LlamaCppGenerator)


@pytest.mark.unit
def test_resolve_bad_host_degrades_to_none() -> None:
    from agents.tools.llm import resolve_generator

    assert resolve_generator({"OLLAMA_HOST": "http://evil.example:11434"}) is None


# --- GBNF grammar-constrained JSON (llama.cpp) -------------------------------


@pytest.mark.unit
def test_grammar_is_sent_in_body() -> None:
    from agents.tools.llm import NARRATIVE_GRAMMAR, LlamaCppGenerator

    captured: dict = {}

    def _t(url: str, body: dict, timeout: float) -> dict:
        captured.update(body)
        return {"choices": [{"message": {"content": "ok"}}]}

    LlamaCppGenerator(transport=_t).generate("facts", grammar=NARRATIVE_GRAMMAR)
    assert "grammar" in captured
    assert "root ::=" in captured["grammar"]


@pytest.mark.unit
def test_generate_json_parses_object() -> None:
    from agents.tools.llm import LlamaCppGenerator

    payload = '{"summary": "s", "assessment": "a", "recommended_next_step": "n"}'

    def _t(url: str, body: dict, timeout: float) -> dict:
        return {"choices": [{"message": {"content": payload}}]}

    data = LlamaCppGenerator(transport=_t).generate_json("facts")
    assert data == {"summary": "s", "assessment": "a", "recommended_next_step": "n"}


@pytest.mark.unit
def test_generate_json_invalid_json_fails_closed() -> None:
    from agents.tools.llm import LlamaCppGenerator

    def _t(url: str, body: dict, timeout: float) -> dict:
        return {"choices": [{"message": {"content": "not json"}}]}

    with pytest.raises(ValidationError):
        LlamaCppGenerator(transport=_t).generate_json("facts")


@pytest.mark.unit
def test_generate_json_non_object_fails_closed() -> None:
    from agents.tools.llm import LlamaCppGenerator

    def _t(url: str, body: dict, timeout: float) -> dict:
        return {"choices": [{"message": {"content": "[1, 2, 3]"}}]}

    with pytest.raises(ValidationError):
        LlamaCppGenerator(transport=_t).generate_json("facts")
