"""End-to-end Stage 3.9 coverage for the sandboxed MAPTA mode.

These tests exercise ``Orchestrator.run_episode`` with a FakeLLM-backed
coordinator and (optionally) a FakeLLM-backed validation agent. They
assert that the episode completes, that ``by_role`` captures the
coordinator (and the validation role when ``validation_mode="agent"``),
and that ``orch.sandbox_agents`` carries the expected per-specialist
role-tagged proxies.
"""

from __future__ import annotations

import pytest

from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient

from tests.integration.e2e_helpers import build_e2e_orchestrator


_REFLECTION_HTML = (
    "<html><body><h1>Search results</h1>"
    "<p>You searched for: <b>canary-payload-xyz</b></p>"
    "<p>Here are some generic results that reflect the query value back "
    "into the page body verbatim without any sanitisation applied.</p>"
    "<ul><li>one</li><li>two</li><li>three</li></ul></body></html>"
)


def _plain_http_handler(action):
    return Observation(
        ok=True,
        elapsed_ms=5,
        data={
            "status_code": 200,
            "url": str((action.params or {}).get("url") or ""),
            "headers": {"content-type": "text/html"},
            "text_excerpt": "<html><body>ok</body></html>",
            "text_full": "<html><body>ok</body></html>",
            "text_len": 30,
        },
    )


def _reflection_handler(action):
    return Observation(
        ok=True,
        elapsed_ms=5,
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
async def test_e2e_sandboxed_full_stack(tmp_path) -> None:
    coord_llm = FakeLLMClient(scripted=[
        '{"actions":[{"type":"http","params":'
        '{"method":"GET","url":"http://localhost/vuln?x=%3Cscript%3Ealert(1)%3C/script%3E"}}]}',
        '{"actions":[],"stop":true,"stop_reason":"demo"}',
    ])

    orch, tools = build_e2e_orchestrator(
        mode="sandboxed",
        validation_mode="http",
        coordinator_llm=coord_llm,
        http_handler=_plain_http_handler,
        tracer_path=tmp_path / "trace.jsonl",
        episode_id="e2e-sandboxed",
    )

    state, tracker = await orch.run_episode(
        user_prompt="test", state=State(base_url="http://localhost"), max_steps=3,
    )

    # Episode-level assertions
    assert tools.closed is True
    assert isinstance(orch.sandbox_agents, dict)
    assert len(orch.sandbox_agents) >= 6

    report = tracker.to_dict()
    assert "coordinator" in report["by_role"]
    assert report["by_role"]["coordinator"]["llm_calls"] >= 1

    # State-level assertion — just makes sure the pipeline did not crash.
    assert state.validation_evidence_count >= 0
    assert len(tools.actions) == 1


@pytest.mark.asyncio
async def test_e2e_sandboxed_validation_agent_upgrades_to_validated(tmp_path) -> None:
    coord_llm = FakeLLMClient(scripted=[
        '{"actions":[{"type":"http","params":'
        '{"method":"GET","url":"http://localhost/vuln?x=canary-payload-xyz"}}]}',
        '{"actions":[],"stop":true,"stop_reason":"demo"}',
    ])
    validation_llm = FakeLLMClient(
        fixed_text='{"verdict":"pass","reason":"confirmed"}',
    )

    orch, tools = build_e2e_orchestrator(
        mode="sandboxed",
        validation_mode="agent",
        coordinator_llm=coord_llm,
        validation_llm=validation_llm,
        http_handler=_reflection_handler,
        tracer_path=tmp_path / "trace.jsonl",
        episode_id="e2e-sandboxed-agent",
    )

    state, tracker = await orch.run_episode(
        user_prompt="test", state=State(base_url="http://localhost"), max_steps=3,
    )

    assert tools.closed is True
    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"
    assert state.validation_validated_count >= 1

    report = tracker.to_dict()
    assert "validation" in report["by_role"]
    assert report["by_role"]["validation"]["llm_calls"] >= 1
    assert validation_llm.calls >= 1


@pytest.mark.asyncio
async def test_e2e_trace_has_episode_markers(tmp_path) -> None:
    tracer_path = tmp_path / "trace.jsonl"
    coord_llm = FakeLLMClient(fixed_text='{"actions":[],"stop":true,"stop_reason":"noop"}')
    orch, _tools = build_e2e_orchestrator(
        coordinator_llm=coord_llm, tracer_path=tracer_path, episode_id="e2e-trace",
    )
    await orch.run_episode(user_prompt="t", max_steps=1)
    text = tracer_path.read_text(encoding="utf-8")
    assert '"text": "episode_start"' in text
    assert '"text": "episode_end"' in text
