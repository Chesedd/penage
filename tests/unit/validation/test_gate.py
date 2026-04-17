from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest

from penage.agents.validation import ValidationAgent
from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.usage import UsageTracker
from penage.llm.fake import FakeLLMClient
from penage.validation.base import ValidationResult
from penage.validation.gate import ValidationGate


@dataclass(slots=True)
class StubHttpValidator:
    """Deterministic stand-in for ``HttpEvidenceValidator``."""

    result: Optional[ValidationResult] = None
    calls: int = 0

    def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
    ) -> Optional[ValidationResult]:
        self.calls += 1
        return self.result


def _make_action() -> Action:
    return Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://target/x?q=canary"},
    )


def _make_obs() -> Observation:
    return Observation(
        ok=True,
        data={
            "status_code": 200,
            "url": "http://target/x?q=canary",
            "headers": {"content-type": "text/html"},
            "text_excerpt": "<html>canary</html>",
        },
    )


def _make_state() -> State:
    state = State()
    state.base_url = "http://target"
    state.last_http_url = "http://target/x?q=canary"
    state.last_http_status = 200
    state.last_http_excerpt = "<html>canary</html>"
    state.notes = ["n1", "n2", "n3"]
    return state


@pytest.mark.asyncio
async def test_gate_returns_none_when_http_validator_returns_none() -> None:
    stub = StubHttpValidator(result=None)
    agent_llm = FakeLLMClient(fixed_text='{"verdict": "pass", "reason": "x"}')
    agent = ValidationAgent.build(llm=agent_llm)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=agent,
        validation_mode="agent",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is None
    assert stub.calls == 1
    assert agent_llm.calls == 0
    assert "validation" not in tracker.to_dict()["by_role"]


@pytest.mark.asyncio
async def test_gate_fast_passes_validated_results_without_calling_agent() -> None:
    http_result = ValidationResult(
        level="validated",
        kind="flag_capture",
        summary="flag seen",
        evidence={"flag": "FLAG{demo}"},
    )
    stub = StubHttpValidator(result=http_result)
    agent_llm = FakeLLMClient(fixed_text='{"verdict": "fail", "reason": "should not run"}')
    agent = ValidationAgent.build(llm=agent_llm)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=agent,
        validation_mode="agent",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is http_result
    assert result is not None
    assert result.level == "validated"
    assert result.evidence["flag"] == "FLAG{demo}"
    assert agent_llm.calls == 0
    assert "validation" not in tracker.to_dict()["by_role"]


@pytest.mark.asyncio
async def test_gate_http_mode_returns_candidate_untouched() -> None:
    http_result = ValidationResult(
        level="candidate",
        kind="xss",
        summary="reflection observed",
        evidence={"reflection": "<script>"},
    )
    stub = StubHttpValidator(result=http_result)
    agent_llm = FakeLLMClient(fixed_text='{"verdict": "pass", "reason": "should not run"}')
    agent = ValidationAgent.build(llm=agent_llm)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=agent,
        validation_mode="http",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is http_result
    assert agent_llm.calls == 0
    assert "validation" not in tracker.to_dict()["by_role"]


@pytest.mark.asyncio
async def test_gate_upgrades_candidate_on_agent_pass() -> None:
    http_result = ValidationResult(
        level="candidate",
        kind="xss",
        summary="reflection observed",
        evidence={"reflection": "<script>"},
    )
    stub = StubHttpValidator(result=http_result)
    agent_llm = FakeLLMClient(
        fixed_text='{"verdict": "pass", "reason": "alert fired", "evidence": {"e": "x"}}',
    )
    agent = ValidationAgent.build(llm=agent_llm)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=agent,
        validation_mode="agent",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is not None
    assert result.level == "validated"
    assert result.kind == "xss"
    assert "agent_confirmed" in result.summary
    assert "alert fired" in result.summary
    assert result.evidence["agent"] == {"e": "x"}
    assert result.evidence["agent_reason"] == "alert fired"
    assert result.evidence["reflection"] == "<script>"

    by_role = tracker.to_dict()["by_role"]
    assert by_role["validation"]["llm_calls"] == 1


@pytest.mark.asyncio
async def test_gate_keeps_candidate_on_agent_fail() -> None:
    http_result = ValidationResult(
        level="candidate",
        kind="xss",
        summary="reflection observed",
        evidence={"reflection": "<script>"},
    )
    stub = StubHttpValidator(result=http_result)
    agent_llm = FakeLLMClient(
        fixed_text='{"verdict": "fail", "reason": "no reflection"}',
    )
    agent = ValidationAgent.build(llm=agent_llm)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=agent,
        validation_mode="agent",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is not None
    assert result.level == "candidate"
    assert result.kind == "xss"
    assert "agent_rejected" in result.summary
    assert "no reflection" in result.summary
    assert result.evidence["agent_rejection"] == "no reflection"
    assert result.evidence["reflection"] == "<script>"


@pytest.mark.asyncio
async def test_gate_falls_back_to_http_mode_when_agent_missing() -> None:
    http_result = ValidationResult(
        level="candidate",
        kind="xss",
        summary="reflection observed",
        evidence={"reflection": "<script>"},
    )
    stub = StubHttpValidator(result=http_result)
    gate = ValidationGate(
        http_validator=stub,
        validation_agent=None,
        validation_mode="agent",
    )
    tracker = UsageTracker()

    result = await gate.validate(
        action=_make_action(), obs=_make_obs(), state=_make_state(), tracker=tracker,
    )

    assert result is http_result
    assert result is not None
    assert result.level == "candidate"
    assert "validation" not in tracker.to_dict()["by_role"]
