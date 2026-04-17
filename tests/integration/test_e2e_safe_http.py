"""End-to-end Stage 3.9 coverage for the legacy safe-http mode.

Safe-http should keep working as before (no validation agent, no daemon
containers). The orchestrator itself does not know about the mode split
— the run mode is expressed purely via :class:`ExecutionGuard`
permissions. This test anchors that invariant from the top.
"""

from __future__ import annotations

import pytest

from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient

from tests.integration.e2e_helpers import build_e2e_orchestrator


def _ok_handler(action):
    return Observation(
        ok=True,
        elapsed_ms=3,
        data={
            "status_code": 200,
            "url": str((action.params or {}).get("url") or ""),
            "headers": {"content-type": "text/html"},
            "text_excerpt": "ok",
            "text_full": "ok",
            "text_len": 2,
        },
    )


@pytest.mark.asyncio
async def test_e2e_safe_http_backcompat(tmp_path) -> None:
    coord_llm = FakeLLMClient(scripted=[
        '{"actions":[{"type":"http","params":'
        '{"method":"GET","url":"http://localhost/index"}}]}',
        '{"actions":[],"stop":true,"stop_reason":"demo"}',
    ])

    orch, tools = build_e2e_orchestrator(
        mode="safe-http",
        validation_mode="http",
        parallel_specialists=True,
        coordinator_llm=coord_llm,
        http_handler=_ok_handler,
        tracer_path=tmp_path / "trace.jsonl",
        episode_id="e2e-safehttp",
    )

    state, tracker = await orch.run_episode(
        user_prompt="test", state=State(base_url="http://localhost"), max_steps=3,
    )

    # Safe-http finishes cleanly and closes the tool runner.
    assert tools.closed is True
    assert len(tools.actions) == 1

    report = tracker.to_dict()
    assert "coordinator" in report["by_role"]

    # Safe-http never escalates to the validation agent.
    by_role = report["by_role"]
    assert (
        "validation" not in by_role
        or by_role["validation"]["llm_calls"] == 0
    )

    # State should be readable without crashing even after an episode.
    assert isinstance(state.validation_results, list)
