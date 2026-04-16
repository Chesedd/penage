from __future__ import annotations

import pytest

from penage.core.errors import LLMResponseError, PenageError
from penage.llm.base import LLMMessage, LLMResponse
from penage.llm.openai import OpenAIClient


def test_openai_provider_name_is_class_attr():
    assert OpenAIClient.provider_name == "openai"


def test_openai_missing_api_key_raises_llm_response_error(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LLMResponseError):
        OpenAIClient(model="gpt-4o")


def test_openai_missing_api_key_is_penage_error(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(PenageError):
        OpenAIClient(model="gpt-4o")


def test_openai_uses_env_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-from-env")
    client = OpenAIClient(model="gpt-4o")
    assert client.api_key == "test-key-from-env"


def test_openai_explicit_api_key_overrides_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    client = OpenAIClient(model="gpt-4o", api_key="explicit-key")
    assert client.api_key == "explicit-key"


def test_openai_token_usage_returns_all_four_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    client = OpenAIClient(model="gpt-4o")

    resp = LLMResponse(
        text="",
        raw={
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 80,
                "prompt_tokens_details": {"cached_tokens": 50},
                "completion_tokens_details": {"reasoning_tokens": 15},
            }
        },
    )
    usage = client.token_usage(resp)
    assert usage == {
        "input_tokens": 200,
        "output_tokens": 80,
        "cached_tokens": 50,
        "reasoning_tokens": 15,
    }
    assert all(isinstance(v, int) for v in usage.values())


def test_openai_token_usage_defaults_to_zero_for_missing_fields(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    client = OpenAIClient(model="gpt-4o")

    resp = LLMResponse(text="", raw={})
    usage = client.token_usage(resp)
    assert usage == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "reasoning_tokens": 0,
    }


def test_openai_coerce_turns_preserves_roles(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    client = OpenAIClient(model="gpt-4o")

    turns = client._coerce_turns(
        [
            LLMMessage(role="system", content="sys"),
            LLMMessage(role="user", content="hi"),
            LLMMessage(role="assistant", content="hello"),
            LLMMessage(role="weird", content="fallback"),
        ]
    )
    assert turns == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "fallback"},
    ]


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeUsage:
    def __init__(self) -> None:
        self.prompt_tokens = 20
        self.completion_tokens = 10
        self.total_tokens = 30


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.id = "cmpl_abc"
        self.model = "gpt-4o"
        self.choices = [_FakeChoice(content)]
        self.usage = _FakeUsage()


class _FakeCompletions:
    def __init__(self, text: str) -> None:
        self._text = text
        self.captured_kwargs: dict = {}

    async def create(self, **kwargs):
        self.captured_kwargs = kwargs
        return _FakeResponse(self._text)


class _FakeChat:
    def __init__(self, text: str) -> None:
        self.completions = _FakeCompletions(text)


class _FakeAsyncOpenAI:
    def __init__(self, text: str = '{"actions":[]}') -> None:
        self.chat = _FakeChat(text)


@pytest.mark.asyncio
async def test_openai_generate_returns_response_with_text_and_usage(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    fake = _FakeAsyncOpenAI(text='{"actions":[]}')
    client = OpenAIClient(model="gpt-4o", client=fake)

    resp = await client.generate(
        [LLMMessage(role="user", content="Return only JSON with actions")],
    )

    assert isinstance(resp, LLMResponse)
    assert resp.text == '{"actions":[]}'
    usage = client.token_usage(resp)
    assert usage["input_tokens"] == 20
    assert usage["output_tokens"] == 10


@pytest.mark.asyncio
async def test_openai_generate_sets_json_response_format_when_requested(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    fake = _FakeAsyncOpenAI(text='{"ok":true}')
    client = OpenAIClient(model="gpt-4o", client=fake)

    await client.generate(
        [LLMMessage(role="user", content="Return only JSON please")],
        temperature=0.1,
        max_tokens=500,
    )

    kwargs = fake.chat.completions.captured_kwargs
    assert kwargs["model"] == "gpt-4o"
    assert kwargs["temperature"] == 0.1
    assert kwargs["max_tokens"] == 500
    assert kwargs["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_openai_generate_omits_json_response_format_without_hint(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    fake = _FakeAsyncOpenAI(text="hello")
    client = OpenAIClient(model="gpt-4o", client=fake)

    await client.generate([LLMMessage(role="user", content="just say hi")])

    kwargs = fake.chat.completions.captured_kwargs
    assert "response_format" not in kwargs


@pytest.mark.asyncio
async def test_openai_generate_wraps_sdk_errors_as_stop_plan(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")

    class _BoomCompletions:
        async def create(self, **kwargs):
            raise RuntimeError("api down")

    class _BoomChat:
        completions = _BoomCompletions()

    class _BoomClient:
        chat = _BoomChat()

    client = OpenAIClient(model="gpt-4o", client=_BoomClient(), max_retries=0)
    resp = await client.generate([LLMMessage(role="user", content="hi")])

    assert isinstance(resp, LLMResponse)
    assert "llm_error" in resp.text
    assert resp.raw.get("error") == "api down"
