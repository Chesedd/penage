from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator, StepOutcome
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.usage import UsageTracker
from penage.llm.fake import FakeLLMClient


class _RecordingTools:
    def __init__(self) -> None:
        self.actions: list[Action] = []

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        return Observation(
            ok=True,
            elapsed_ms=1,
            data={
                "status_code": 200,
                "url": str((action.params or {}).get("url") or ""),
                "headers": {"content-type": "text/html"},
                "text_excerpt": "",
                "text_full": "",
                "text_len": 0,
                "paths": [],
            },
        )


def _make_orchestrator(tmp_path) -> tuple[Orchestrator, _RecordingTools]:
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/"}}]}'
    )
    tools = _RecordingTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="step-extraction")
    return Orchestrator(llm=llm, tools=tools, tracer=tracer), tools


@pytest.mark.asyncio
async def test_run_step_returns_stop_when_http_budget_already_exhausted(tmp_path):
    orch, _tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()
    st = State(base_url="http://localhost")
    st.http_requests_used = 999

    outcome = await orch._run_step(
        st=st,
        step=1,
        user_prompt="",
        tracker=tracker,
        actions_per_step=1,
        max_http_requests=30,
        max_total_text_len=None,
        early_stop=None,
        stop_condition=None,
    )

    assert isinstance(outcome, StepOutcome)
    assert outcome.stop is True
    assert outcome.reason is not None
    assert "budget_exhausted" in outcome.reason
    assert "budget_exhausted:http_requests" in st.notes


@pytest.mark.asyncio
async def test_run_step_returns_stop_when_stop_condition_matches(tmp_path):
    orch, _tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()
    st = State(base_url="http://localhost")

    outcome = await orch._run_step(
        st=st,
        step=1,
        user_prompt="",
        tracker=tracker,
        actions_per_step=1,
        max_http_requests=30,
        max_total_text_len=None,
        early_stop=None,
        stop_condition=lambda _s: "done",
    )

    assert outcome.stop is True
    assert outcome.reason is not None
    assert "done" in outcome.reason


@pytest.mark.asyncio
async def test_run_action_executes_http_and_returns_no_stop(tmp_path):
    orch, tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()
    st = State(base_url="http://localhost")
    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://localhost/probe"},
    )

    outcome = await orch._run_action(
        a=action,
        st=st,
        step=1,
        tracker=tracker,
        max_http_requests=30,
        max_total_text_len=None,
    )

    assert outcome.stop is False
    assert outcome.reason is None
    assert len(tools.actions) == 1
    assert st.tool_calls_total == 1
    assert st.tool_calls_http == 1
    assert tracker.total_tool_calls == 1
