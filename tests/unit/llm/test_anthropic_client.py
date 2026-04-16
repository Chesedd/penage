from __future__ import annotations

import pytest

from penage.core.errors import LLMResponseError, PenageError
from penage.llm.anthropic import AnthropicClient
from penage.llm.base import LLMMessage, LLMResponse


def test_anthropic_provider_name_is_class_attr():
    assert AnthropicClient.provider_name == "anthropic"


def test_anthropic_missing_api_key_raises_llm_response_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMResponseError):
        AnthropicClient(model="claude-sonnet-4-20250514")


def test_anthropic_missing_api_key_is_penage_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(PenageError):
        AnthropicClient(model="claude-sonnet-4-20250514")


def test_anthropic_uses_env_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-from-env")
    client = AnthropicClient(model="claude-sonnet-4-20250514")
    assert client.api_key == "test-key-from-env"


def test_anthropic_explicit_api_key_overrides_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    client = AnthropicClient(model="claude-sonnet-4-20250514", api_key="explicit-key")
    assert client.api_key == "explicit-key"


def test_anthropic_token_usage_returns_all_four_keys(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    client = AnthropicClient(model="claude-sonnet-4-20250514")

    resp = LLMResponse(
        text="",
        raw={
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 30,
                "cache_creation_input_tokens": 10,
            }
        },
    )
    usage = client.token_usage(resp)
    assert usage == {
        "input_tokens": 100,
        "output_tokens": 50,
        "cached_tokens": 40,
        "reasoning_tokens": 0,
    }
    assert all(isinstance(v, int) for v in usage.values())


def test_anthropic_token_usage_defaults_to_zero_for_missing_fields(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    client = AnthropicClient(model="claude-sonnet-4-20250514")

    resp = LLMResponse(text="", raw={})
    usage = client.token_usage(resp)
    assert usage == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "reasoning_tokens": 0,
    }


def test_anthropic_splits_system_from_turns(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    client = AnthropicClient(model="claude-sonnet-4-20250514")

    messages = [
        LLMMessage(role="system", content="You are helpful."),
        LLMMessage(role="user", content="Hello"),
        LLMMessage(role="assistant", content="Hi"),
        LLMMessage(role="user", content="How are you?"),
    ]
    system, turns = client._split_system_and_turns(messages)
    assert system == "You are helpful."
    assert turns == [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi"},
        {"role": "user", "content": "How are you?"},
    ]


class _FakeBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeUsage:
    def __init__(self) -> None:
        self.input_tokens = 12
        self.output_tokens = 7
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.id = "msg_123"
        self.model = "claude-sonnet-4-20250514"
        self.content = [_FakeBlock(text)]
        self.usage = _FakeUsage()


class _FakeMessages:
    def __init__(self, text: str) -> None:
        self._text = text
        self.captured_kwargs: dict = {}

    async def create(self, **kwargs):
        self.captured_kwargs = kwargs
        return _FakeResponse(self._text)


class _FakeAsyncAnthropic:
    def __init__(self, text: str = '{"actions":[]}') -> None:
        self.messages = _FakeMessages(text)


@pytest.mark.asyncio
async def test_anthropic_generate_returns_response_with_text_and_usage(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    fake = _FakeAsyncAnthropic(text='{"actions":[]}')
    client = AnthropicClient(model="claude-sonnet-4-20250514", client=fake)

    resp = await client.generate(
        [LLMMessage(role="user", content="Return only JSON with actions")],
    )

    assert isinstance(resp, LLMResponse)
    assert resp.text == '{"actions":[]}'
    usage = client.token_usage(resp)
    assert usage["input_tokens"] == 12
    assert usage["output_tokens"] == 7


@pytest.mark.asyncio
async def test_anthropic_generate_passes_system_and_messages(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    fake = _FakeAsyncAnthropic(text='{"ok":true}')
    client = AnthropicClient(model="claude-sonnet-4-20250514", client=fake)

    await client.generate(
        [
            LLMMessage(role="system", content="sys"),
            LLMMessage(role="user", content="hi"),
        ],
        temperature=0.5,
        max_tokens=1000,
    )

    kwargs = fake.messages.captured_kwargs
    assert kwargs["model"] == "claude-sonnet-4-20250514"
    assert kwargs["max_tokens"] == 1000
    assert kwargs["temperature"] == 0.5
    assert kwargs["system"] == "sys"
    assert kwargs["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.asyncio
async def test_anthropic_generate_wraps_sdk_errors_as_stop_plan(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")

    class _BoomMessages:
        async def create(self, **kwargs):
            raise RuntimeError("api down")

    class _BoomClient:
        messages = _BoomMessages()

    client = AnthropicClient(model="claude-sonnet-4-20250514", client=_BoomClient(), max_retries=0)
    resp = await client.generate([LLMMessage(role="user", content="hi")])

    assert isinstance(resp, LLMResponse)
    assert "llm_error" in resp.text
    assert resp.raw.get("error") == "api down"
