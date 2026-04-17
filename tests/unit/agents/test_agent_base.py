from __future__ import annotations

import pytest

from penage.agents import Agent, AgentRole
from penage.core.usage import UsageTracker
from penage.llm.fake import FakeLLMClient


@pytest.mark.parametrize(
    "role",
    [AgentRole.COORDINATOR, AgentRole.SANDBOX, AgentRole.VALIDATION],
)
def test_agent_holds_passed_fields(role: AgentRole) -> None:
    agent = Agent(
        role=role,
        system_prompt="x",
        llm_client=FakeLLMClient(),
        usage_tracker=UsageTracker(),
    )

    assert agent.role is role
    assert agent.system_prompt == "x"
    assert isinstance(agent.llm_client, FakeLLMClient)
    assert isinstance(agent.usage_tracker, UsageTracker)
    assert agent.tool_set is None
    assert agent.context_window == 0


def test_agent_role_string_equality() -> None:
    assert AgentRole.COORDINATOR == "coordinator"
    assert AgentRole.SANDBOX == "sandbox"
    assert AgentRole.VALIDATION == "validation"
