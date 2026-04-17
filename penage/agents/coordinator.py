from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from penage.agents.base import Agent, AgentRole
from penage.core.guard import ExecutionGuard
from penage.core.planner import Planner, PlannerDecision, ResearchMemorySyncer
from penage.core.state import State
from penage.core.url_guard import UrlGuard
from penage.core.usage import UsageTracker
from penage.llm.base import LLMClient
from penage.prompts.loader import load_prompt


@dataclass(slots=True)
class CoordinatorAgent(Agent):
    """MAPTA-style Coordinator role: owns the planning loop.

    Wraps the existing ``Planner`` and its long system prompt. Records
    LLM usage under the ``"coordinator"`` role on the tracker passed
    per-call (the tracker lives inside an episode, while this agent is
    built once by the orchestrator/runtime factory).
    """

    planner: Planner = field(kw_only=True)

    @classmethod
    def build(
        cls,
        *,
        llm: LLMClient,
        guard: Optional[ExecutionGuard] = None,
        url_guard: Optional[UrlGuard] = None,
        research_memory_syncer: Optional[ResearchMemorySyncer] = None,
    ) -> "CoordinatorAgent":
        prompt = load_prompt("coordinator")
        planner = Planner(
            llm=llm,
            system_prompt=prompt,
            guard=guard,
            url_guard=url_guard,
            research_memory_syncer=research_memory_syncer,
        )
        return cls(
            role=AgentRole.COORDINATOR,
            system_prompt=prompt,
            llm_client=llm,
            planner=planner,
        )

    async def choose_actions(
        self,
        *,
        step: int,
        user_prompt: str,
        state: State,
        tracker: UsageTracker,
    ) -> PlannerDecision:
        decision = await self.planner.choose_actions(
            step=step, user_prompt=user_prompt, state=state,
        )
        for resp in decision.llm_responses:
            token_usage = self.llm_client.token_usage(resp)
            tracker.record_llm_call(
                "coordinator", self.llm_client.provider_name, token_usage,
            )
        return decision
