from __future__ import annotations

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.fake import FakeLLMClient


class _ClosingTools:
    def __init__(self, *, raise_in_run: bool = False) -> None:
        self.actions: list[Action] = []
        self.closed: bool = False
        self._raise_in_run = raise_in_run

    async def run(self, action: Action) -> Observation:
        if self._raise_in_run:
            raise RuntimeError("forced failure inside run")
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

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_run_episode_calls_tools_aclose_on_success(tmp_path):
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/"}}]}'
    )
    tools = _ClosingTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="lifecycle-success")
    orch = Orchestrator(llm=llm, tools=tools, tracer=tracer)

    await orch.run_episode(
        user_prompt="x",
        state=State(base_url="http://localhost"),
        max_steps=1,
    )

    assert tools.closed is True


@pytest.mark.asyncio
async def test_run_episode_calls_tools_aclose_on_exception(tmp_path):
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/"}}]}'
    )
    tools = _ClosingTools(raise_in_run=True)
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="lifecycle-exception")
    orch = Orchestrator(llm=llm, tools=tools, tracer=tracer)

    with pytest.raises(RuntimeError):
        await orch.run_episode(
            user_prompt="x",
            state=State(base_url="http://localhost"),
            max_steps=1,
        )

    assert tools.closed is True
