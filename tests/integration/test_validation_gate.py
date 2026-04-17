"""Integration: ValidationGate wired into Orchestrator.run_episode.

Covers the two live paths:
- ``validation_mode="http"`` (default): one HTTP step with a reflected
  payload yields ``level="evidence"`` from ``HttpEvidenceValidator`` and
  no escalation to the validation LLM.
- ``validation_mode="agent"``: the same step is escalated to a
  ``ValidationAgent`` backed by ``FakeLLM``; a ``pass`` verdict
  upgrades the recorded result to ``level="validated"``.
"""

from __future__ import annotations

import pytest

from penage.agents.validation import ValidationAgent
from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.fake import FakeLLMClient
from penage.validation.gate import ValidationGate
from penage.validation.http import HttpEvidenceValidator


COORD_ACTION_JSON = (
    '{"actions":[{"type":"http","params":'
    '{"method":"GET","url":"http://localhost/vuln?x=canary-payload-xyz"}}]}'
)

_REFLECTION_HTML = (
    "<html><body><h1>Search results</h1>"
    "<p>You searched for: <b>canary-payload-xyz</b></p>"
    "<p>Here are some generic results that reflect the query value back "
    "into the page body verbatim without any sanitisation applied.</p>"
    "<ul><li>one</li><li>two</li><li>three</li></ul></body></html>"
)


class _ReflectionTools:
    """Minimal HTTP mock: substantive HTML page that reflects the payload.

    Returns a 200 OK HTML body of >=180 chars with no negative markers
    and no ``FLAG{...}`` pattern. That yields
    ``HttpEvidenceValidator`` level ``"evidence"`` (kind
    ``substantive_http_response``) — the exact shape the gate should
    escalate in agent mode.
    """

    def __init__(self) -> None:
        self.actions: list[Action] = []

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        url = str((action.params or {}).get("url") or "")
        return Observation(
            ok=True,
            elapsed_ms=5,
            data={
                "status_code": 200,
                "url": url,
                "headers": {"content-type": "text/html"},
                "text_excerpt": _REFLECTION_HTML[:200],
                "text_full": _REFLECTION_HTML,
                "text_len": len(_REFLECTION_HTML),
            },
        )


@pytest.mark.asyncio
async def test_validation_gate_http_mode_records_evidence_without_llm_escalation(
    tmp_path,
) -> None:
    coord_llm = FakeLLMClient(fixed_text=COORD_ACTION_JSON)
    tools = _ReflectionTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="gate-http")

    gate = ValidationGate(
        http_validator=HttpEvidenceValidator(),
        validation_agent=None,
        validation_mode="http",
    )

    orch = Orchestrator(
        llm=coord_llm,
        tools=tools,
        tracer=tracer,
        validation_gate=gate,
    )

    state, tracker = await orch.run_episode(
        user_prompt="exercise gate",
        state=State(base_url="http://localhost"),
        max_steps=1,
    )

    assert len(tools.actions) == 1
    assert tools.actions[0].type == ActionType.HTTP
    assert state.last_validation is not None
    assert state.last_validation["level"] == "evidence"
    assert state.validation_evidence_count == 1
    assert state.validation_validated_count == 0
    assert "validation" not in tracker.to_dict()["by_role"]


@pytest.mark.asyncio
async def test_validation_gate_agent_mode_escalates_and_upgrades_to_validated(
    tmp_path,
) -> None:
    coord_llm = FakeLLMClient(fixed_text=COORD_ACTION_JSON)
    agent_llm = FakeLLMClient(
        fixed_text='{"verdict": "pass", "reason": "reflected payload confirmed"}',
    )
    tools = _ReflectionTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="gate-agent")

    gate = ValidationGate(
        http_validator=HttpEvidenceValidator(),
        validation_agent=ValidationAgent.build(llm=agent_llm),
        validation_mode="agent",
    )

    orch = Orchestrator(
        llm=coord_llm,
        tools=tools,
        tracer=tracer,
        validation_gate=gate,
    )

    state, tracker = await orch.run_episode(
        user_prompt="exercise gate",
        state=State(base_url="http://localhost"),
        max_steps=1,
    )

    assert len(tools.actions) == 1
    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"
    assert state.validation_validated_count == 1
    assert "agent_confirmed" in str(state.last_validation["summary"])

    by_role = tracker.to_dict()["by_role"]
    assert "validation" in by_role
    assert by_role["validation"]["llm_calls"] == 1
    assert agent_llm.calls == 1
