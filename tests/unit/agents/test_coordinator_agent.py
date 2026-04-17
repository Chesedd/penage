from __future__ import annotations

import pytest

from penage.agents import AgentRole
from penage.agents.coordinator import CoordinatorAgent
from penage.core.state import State
from penage.core.usage import UsageTracker
from penage.llm.fake import FakeLLMClient


def test_coordinator_agent_build_exposes_role_and_prompt() -> None:
    llm = FakeLLMClient(fixed_text="{}")
    coord = CoordinatorAgent.build(llm=llm)

    assert coord.role is AgentRole.COORDINATOR
    assert coord.system_prompt
    assert "JSON" in coord.system_prompt
    assert "planner" in coord.system_prompt
    assert coord.planner.system_prompt == coord.system_prompt
    assert coord.llm_client is llm


@pytest.mark.asyncio
async def test_coordinator_choose_actions_records_usage_under_coordinator_role() -> None:
    llm = FakeLLMClient(fixed_text='{"actions": []}')
    coord = CoordinatorAgent.build(llm=llm)
    tracker = UsageTracker()

    decision = await coord.choose_actions(
        step=1,
        user_prompt="probe the target",
        state=State(),
        tracker=tracker,
    )

    assert decision.actions == []

    by_role = tracker.to_dict()["by_role"]
    assert "coordinator" in by_role
    assert by_role["coordinator"]["llm_calls"] >= 1
    assert "planner" not in by_role
