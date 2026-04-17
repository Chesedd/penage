from __future__ import annotations

from dataclasses import dataclass, field

from penage.agents.base import Agent, AgentRole
from penage.llm.base import LLMClient
from penage.llm.role_tagged import RoleTaggedLLMClient
from penage.prompts.loader import load_prompt


@dataclass(slots=True)
class SandboxAgent(Agent):
    """MAPTA-style Sandbox role: one agent per specialist.

    Wraps the shared inner LLM client in a :class:`RoleTaggedLLMClient`
    so every call flowing through this agent's ``llm_client`` is recorded
    under ``role="sandbox"`` and the specialist's own bucket in
    :class:`UsageTracker.by_specialist`.

    The narrow-executor system prompt is a TODO placeholder (see
    ``penage/prompts/sandbox.md``) and is loaded here so the field is
    populated; per-specialist specialists still use their own
    hard-coded prompts until the shared sandbox protocol lands in 3.5.
    """

    specialist_name: str = field(kw_only=True)

    @classmethod
    def build(
        cls,
        *,
        inner_llm: LLMClient,
        specialist_name: str,
    ) -> "SandboxAgent":
        prompt = load_prompt("sandbox")
        proxy = RoleTaggedLLMClient(
            inner=inner_llm,
            role="sandbox",
            specialist_name=specialist_name,
        )
        return cls(
            role=AgentRole.SANDBOX,
            system_prompt=prompt,
            llm_client=proxy,
            specialist_name=specialist_name,
        )
