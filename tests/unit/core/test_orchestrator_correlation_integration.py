from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.usage import EarlyStopThresholds, UsageTracker
from penage.llm.fake import FakeLLMClient


class _EchoTools:
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


def _make_orchestrator(tmp_path) -> tuple[Orchestrator, _EchoTools]:
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/"}}]}'
    )
    tools = _EchoTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="corr-int")
    return Orchestrator(llm=llm, tools=tools, tracer=tracer), tools


@pytest.mark.asyncio
async def test_run_step_stops_on_action_repeat_ratio(tmp_path):
    """When the tracker's fingerprint ring is saturated with repeats,
    `_run_step` must return stop=True with an action_repeat_ratio reason."""
    orch, _tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()
    # Saturate the rolling window before the step starts.
    for _ in range(5):
        tracker.record_action_fingerprint("http:{\"url\":\"/same\"}")

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_action_repeat_ratio=0.7,
        action_repeat_window=5,
    )

    st = State(base_url="http://localhost")
    outcome = await orch._run_step(
        st=st,
        step=3,
        user_prompt="",
        tracker=tracker,
        actions_per_step=1,
        max_http_requests=30,
        max_total_text_len=None,
        early_stop=thresholds,
        stop_condition=None,
    )

    assert outcome.stop is True
    assert outcome.reason is not None
    assert "action_repeat_ratio" in outcome.reason
    assert any("action_repeat_ratio" in n for n in st.notes)


@pytest.mark.asyncio
async def test_run_step_stops_on_no_evidence_gap(tmp_path):
    orch, _tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()

    # Seed a prior observe_step that recorded step=1 / evidence=0.
    st = State(base_url="http://localhost")
    tracker.observe_step(st, step=1)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=3,
    )

    # Current step=5 — gap of 5 steps with no evidence; must stop.
    outcome = await orch._run_step(
        st=st,
        step=5,
        user_prompt="",
        tracker=tracker,
        actions_per_step=1,
        max_http_requests=30,
        max_total_text_len=None,
        early_stop=thresholds,
        stop_condition=None,
    )

    assert outcome.stop is True
    assert outcome.reason is not None
    assert "no_evidence_steps" in outcome.reason


@pytest.mark.asyncio
async def test_run_action_pushes_fingerprint_to_tracker(tmp_path):
    orch, tools = _make_orchestrator(tmp_path)
    tracker = UsageTracker()
    st = State(base_url="http://localhost")
    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://localhost/fp-probe"},
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
    # The single action was pushed to the repeat ring.
    assert len(tracker._recent_fingerprints) == 1
    fp = tracker._recent_fingerprints[0]
    assert "http" in fp
    assert "fp-probe" in fp
