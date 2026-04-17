from __future__ import annotations

import pytest

from penage.agents import AgentRole, SandboxAgent
from penage.core.usage import UsageTracker, bind_usage_tracker
from penage.llm.base import LLMMessage
from penage.llm.fake import FakeLLMClient
from penage.llm.role_tagged import RoleTaggedLLMClient


def test_sandbox_agent_build_exposes_role_prompt_and_proxy() -> None:
    inner = FakeLLMClient(fixed_text="{}")
    agent = SandboxAgent.build(inner_llm=inner, specialist_name="xss")

    assert agent.role is AgentRole.SANDBOX
    assert agent.specialist_name == "xss"
    assert agent.system_prompt

    proxy = agent.llm_client
    assert isinstance(proxy, RoleTaggedLLMClient)
    assert proxy.role == "sandbox"
    assert proxy.specialist_name == "xss"
    assert proxy.inner is inner


def test_sandbox_agent_system_prompt_non_empty() -> None:
    agent = SandboxAgent.build(inner_llm=FakeLLMClient(), specialist_name="sqli")
    assert agent.system_prompt.strip()


@pytest.mark.asyncio
async def test_sandbox_agent_proxy_records_by_role_and_specialist() -> None:
    inner = FakeLLMClient(fixed_text="ok")
    agent = SandboxAgent.build(inner_llm=inner, specialist_name="xss")
    tracker = UsageTracker()

    with bind_usage_tracker(tracker):
        await agent.llm_client.generate([LLMMessage(role="user", content="hi")])

    d = tracker.to_dict()
    assert d["by_role"]["sandbox"]["llm_calls"] == 1
    assert d["by_specialist"]["xss"]["llm_calls"] == 1
