"""End-to-end ablation matrix for the Stage 3.x feature flags.

Each ablation prunes one feature and runs a short episode. The purpose
is not to verify that feature's correctness (already covered by
dedicated tests) but to enforce invariant #8: disabling any single 3.x
feature must not break the pipeline end-to-end.
"""

from __future__ import annotations

import pytest

from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient

from tests.integration.e2e_helpers import build_e2e_orchestrator


_REFLECTION_HTML = (
    "<html><body><h1>Hello</h1>"
    "<p>Stable substantive HTML body reflecting data back to the caller "
    "with enough chars to pass the evidence validator heuristics cleanly.</p>"
    "<ul><li>a</li><li>b</li><li>c</li><li>d</li></ul></body></html>"
)


def _evidence_handler(action):
    return Observation(
        ok=True,
        elapsed_ms=4,
        data={
            "status_code": 200,
            "url": str((action.params or {}).get("url") or ""),
            "headers": {"content-type": "text/html"},
            "text_excerpt": _REFLECTION_HTML[:200],
            "text_full": _REFLECTION_HTML,
            "text_len": len(_REFLECTION_HTML),
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"parallel_specialists": False},
        {"validation_mode": "http"},
        {"validation_mode": "agent"},
        {"mode": "safe-http"},
    ],
)
async def test_ablation_each_flag(tmp_path, overrides) -> None:
    coord_llm = FakeLLMClient(scripted=[
        '{"actions":[{"type":"http","params":'
        '{"method":"GET","url":"http://localhost/p"}}]}',
        '{"actions":[],"stop":true,"stop_reason":"ok"}',
    ])
    validation_llm = (
        FakeLLMClient(fixed_text='{"verdict":"pass","reason":"ok"}')
        if overrides.get("validation_mode") == "agent"
        else None
    )

    orch, tools = build_e2e_orchestrator(
        coordinator_llm=coord_llm,
        validation_llm=validation_llm,
        http_handler=_evidence_handler,
        tracer_path=tmp_path / "trace.jsonl",
        episode_id="e2e-ablation",
        **overrides,
    )

    state, tracker = await orch.run_episode(
        user_prompt="test", state=State(base_url="http://localhost"), max_steps=2,
    )

    assert tools.closed is True
    report = tracker.to_dict()
    assert "coordinator" in report["by_role"]
    assert report["by_role"]["coordinator"]["llm_calls"] >= 1
    assert isinstance(state.validation_results, list)

    if overrides.get("validation_mode") == "agent":
        # At least one evidence-level observation was produced above,
        # so the validation role must have been invoked at least once.
        assert report["by_role"].get("validation", {}).get("llm_calls", 0) >= 1
