from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.fake import FakeLLMClient


class DummyTools:
    def __init__(self) -> None:
        self.actions: list[Action] = []

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        assert action.type == ActionType.HTTP
        return Observation(
            ok=True,
            elapsed_ms=5,
            data={
                "status_code": 200,
                "url": str((action.params or {}).get("url") or ""),
                "headers": {"content-type": "text/html"},
                "text_excerpt": "FLAG{demo_flag}",
                "text_full": "<html><body>FLAG{demo_flag}</body></html>",
                "text_len": 41,
                "paths": ["/flag"],
                "contains_flag_like": True,
                "flag_snippets": ["FLAG{demo_flag}"],
            },
        )


@pytest.mark.asyncio
async def test_orchestrator_executes_http_plan_and_records_validated_signal(tmp_path):
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/flag"}}]}'
    )
    tools = DummyTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="test")
    orchestrator = Orchestrator(llm=llm, tools=tools, tracer=tracer)

    state = await orchestrator.run_episode(
        user_prompt="get the flag",
        state=State(facts={"base_url": "http://localhost"}),
        max_steps=1,
    )

    assert len(tools.actions) == 1
    assert tools.actions[0].params["url"] == "http://localhost/flag"
    assert state.tool_calls_total == 1
    assert state.tool_calls_http == 1
    assert state.validation_evidence_count == 1
    assert state.validation_validated_count == 1
    assert state.last_validation is not None
    assert state.last_validation["kind"] == "flag_capture"
