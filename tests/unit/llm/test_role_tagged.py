from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

import pytest

from penage.core.usage import (
    UsageTracker,
    bind_usage_tracker,
    current_usage_tracker,
)
from penage.llm.base import LLMMessage, LLMResponse
from penage.llm.fake import FakeLLMClient
from penage.llm.role_tagged import RoleTaggedLLMClient


@dataclass(slots=True)
class CountingFakeLLM:
    """Like FakeLLMClient, but returns configurable token_usage."""

    provider_name: ClassVar[str] = "counting-fake"

    input_tokens: int = 12
    output_tokens: int = 34
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    calls: int = 0

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text="ok")

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "reasoning_tokens": self.reasoning_tokens,
        }


@pytest.mark.asyncio
async def test_generate_without_bind_records_nothing():
    inner = FakeLLMClient(fixed_text="hello")
    proxy = RoleTaggedLLMClient(inner=inner, role="sandbox")
    tracker = UsageTracker()

    # tracker exists but is not bound to ContextVar
    assert current_usage_tracker() is None

    resp = await proxy.generate([LLMMessage(role="user", content="hi")])
    assert resp.text == "hello"
    assert tracker.to_dict()["by_role"] == {}
    assert tracker.to_dict()["by_specialist"] == {}


@pytest.mark.asyncio
async def test_generate_records_by_role_without_specialist():
    inner = CountingFakeLLM(input_tokens=10, output_tokens=5)
    proxy = RoleTaggedLLMClient(inner=inner, role="sandbox")
    tracker = UsageTracker()

    with bind_usage_tracker(tracker):
        await proxy.generate([LLMMessage(role="user", content="hi")])

    d = tracker.to_dict()
    assert d["by_role"]["sandbox"]["llm_calls"] == 1
    assert d["by_role"]["sandbox"]["input_tokens"] == 10
    assert d["by_role"]["sandbox"]["output_tokens"] == 5
    assert d["by_specialist"] == {}


@pytest.mark.asyncio
async def test_generate_records_by_role_and_specialist_once():
    inner = CountingFakeLLM(input_tokens=10, output_tokens=5)
    proxy = RoleTaggedLLMClient(inner=inner, role="sandbox", specialist_name="xss")
    tracker = UsageTracker()

    with bind_usage_tracker(tracker):
        await proxy.generate([LLMMessage(role="user", content="hi")])

    d = tracker.to_dict()
    assert d["by_role"]["sandbox"]["llm_calls"] == 1
    assert d["by_specialist"]["xss"]["llm_calls"] == 1
    # totals not duplicated — sum stays equal to by_role["sandbox"].input_tokens
    assert d["totals"]["input_tokens"] == d["by_role"]["sandbox"]["input_tokens"] == 10
    assert d["totals"]["output_tokens"] == d["by_role"]["sandbox"]["output_tokens"] == 5
    assert d["totals"]["llm_calls"] == 1


@pytest.mark.asyncio
async def test_nested_bind_writes_to_innermost_and_restores():
    inner = CountingFakeLLM(input_tokens=3, output_tokens=1)
    proxy = RoleTaggedLLMClient(inner=inner, role="sandbox")
    t1 = UsageTracker()
    t2 = UsageTracker()

    with bind_usage_tracker(t1):
        with bind_usage_tracker(t2):
            await proxy.generate([LLMMessage(role="user", content="a")])
        # inner ContextVar is reset → outer tracker must receive the next call
        await proxy.generate([LLMMessage(role="user", content="b")])

    assert t2.to_dict()["by_role"]["sandbox"]["llm_calls"] == 1
    assert t1.to_dict()["by_role"]["sandbox"]["llm_calls"] == 1
    # each tracker saw exactly one call — no leakage
    assert t2.to_dict()["totals"]["input_tokens"] == 3
    assert t1.to_dict()["totals"]["input_tokens"] == 3


@pytest.mark.asyncio
async def test_provider_name_and_token_usage_delegate_to_inner():
    inner = CountingFakeLLM(input_tokens=7, output_tokens=8, cached_tokens=2, reasoning_tokens=1)
    proxy = RoleTaggedLLMClient(inner=inner, role="sandbox")

    assert proxy.provider_name == "counting-fake"

    resp = await proxy.generate([LLMMessage(role="user", content="x")])
    usage = proxy.token_usage(resp)
    assert usage == {
        "input_tokens": 7,
        "output_tokens": 8,
        "cached_tokens": 2,
        "reasoning_tokens": 1,
    }
