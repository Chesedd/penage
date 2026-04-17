from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

import pytest

from penage.agents import AgentRole, ValidationAgent
from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.usage import UsageTracker
from penage.llm.base import LLMClient, LLMMessage, LLMResponse
from penage.llm.fake import FakeLLMClient
from penage.validation.candidate import CandidateFinding
from penage.validation.verdict import ValidationVerdict


def _make_candidate() -> CandidateFinding:
    return CandidateFinding(
        kind="xss",
        action=Action(
            type=ActionType.HTTP,
            params={"method": "GET", "url": "http://target/x?q=<script>alert(1)</script>"},
        ),
        obs=Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": "http://target/x",
                "text_excerpt": "<html>...<script>alert(1)</script>...</html>",
            },
        ),
        state_snapshot={
            "base_url": "http://target",
            "last_http_status": 200,
        },
        evidence_so_far={"http_validator": "candidate"},
    )


@dataclass(slots=True)
class RaisingLLMClient:
    provider_name: ClassVar[str] = "raising"

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        raise RuntimeError("boom")

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        return {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "reasoning_tokens": 0}


def test_validation_agent_build_exposes_role_and_prompt() -> None:
    llm = FakeLLMClient(fixed_text="{}")
    agent = ValidationAgent.build(llm=llm)

    assert agent.role is AgentRole.VALIDATION
    assert agent.system_prompt
    assert "strict validation agent" in agent.system_prompt.lower()
    assert agent.llm_client is llm


@pytest.mark.asyncio
async def test_validation_agent_passes_on_pass_verdict() -> None:
    llm = FakeLLMClient(
        fixed_text='{"verdict": "pass", "reason": "alert fired", "evidence": {"tag": "script"}}',
    )
    agent = ValidationAgent.build(llm=llm)
    tracker = UsageTracker()

    verdict = await agent.validate(_make_candidate(), tracker=tracker)

    assert verdict.passed is True
    assert verdict.reason == "alert fired"
    assert verdict.evidence["tag"] == "script"

    by_role = tracker.to_dict()["by_role"]
    assert by_role["validation"]["llm_calls"] == 1
    assert "validator" not in by_role


@pytest.mark.asyncio
async def test_validation_agent_fails_on_fail_verdict() -> None:
    llm = FakeLLMClient(fixed_text='{"verdict": "fail", "reason": "no reflection"}')
    agent = ValidationAgent.build(llm=llm)
    tracker = UsageTracker()

    verdict = await agent.validate(_make_candidate(), tracker=tracker)

    assert verdict.passed is False
    assert verdict.reason == "no reflection"


@pytest.mark.asyncio
async def test_validation_agent_fail_closed_on_unparseable_response() -> None:
    llm = FakeLLMClient(fixed_text="not a json at all")
    agent = ValidationAgent.build(llm=llm)
    tracker = UsageTracker()

    verdict = await agent.validate(_make_candidate(), tracker=tracker)

    assert verdict.passed is False
    assert "parse_error" in verdict.reason


@pytest.mark.asyncio
async def test_validation_agent_fail_closed_on_llm_exception() -> None:
    llm: LLMClient = RaisingLLMClient()
    agent = ValidationAgent.build(llm=llm)
    tracker = UsageTracker()

    verdict = await agent.validate(_make_candidate(), tracker=tracker)

    assert verdict.passed is False
    assert "llm_exception" in verdict.reason
    by_role = tracker.to_dict()["by_role"]
    assert "validation" not in by_role


@pytest.mark.asyncio
async def test_validation_agent_fail_closed_on_unknown_verdict() -> None:
    llm = FakeLLMClient(fixed_text='{"verdict": "maybe", "reason": "dunno"}')
    agent = ValidationAgent.build(llm=llm)
    tracker = UsageTracker()

    verdict = await agent.validate(_make_candidate(), tracker=tracker)

    assert verdict.passed is False
    assert "parse_error" in verdict.reason
