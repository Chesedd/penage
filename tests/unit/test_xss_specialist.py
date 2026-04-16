from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from penage.validation.browser import BrowserEvidence, BrowserVerifier


Responder = Callable[[Action], Observation]


@dataclass
class FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


def _reflected_param_value(action: Action, parameter: str) -> str:
    params = action.params
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _vulnerable_echo(parameter: str, *, echo_event: str | None = None) -> Responder:
    """Echo the parameter value verbatim inside an attribute position."""

    def respond(action: Action) -> Observation:
        injected = _reflected_param_value(action, parameter)
        body = (
            "<html><body><form method=\"POST\" action=\"/search\">"
            f"<input type=\"text\" name=\"{parameter}\" value=\"{injected}\" />"
            "</form></body></html>"
        )
        if echo_event and echo_event in injected:
            body += f"<!-- observed event: {echo_event} -->"
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params.get("url"),
                "headers": {"content-type": "text/html"},
                "text_full": body,
                "text_excerpt": body,
            },
        )

    return respond


class _StubBrowserVerifier(BrowserVerifier):
    """BrowserVerifier that fakes script execution without Playwright."""

    def __init__(self, *, executed: bool = True) -> None:
        super().__init__(screenshot_dir=Path("runs/screenshots"))
        self._executed = executed
        self.calls: list[tuple[str, str, str]] = []

    def verify(self, url: str, payload: str, expectation: str) -> BrowserEvidence:  # type: ignore[override]
        self.calls.append((url, payload, expectation))
        return BrowserEvidence(
            script_executed=self._executed,
            dialog_triggered=self._executed,
            dom_mutations=[],
            console_messages=["[dialog] alert(1)"] if self._executed else [],
            screenshot_path=Path("runs/screenshots/fake.png") if self._executed else None,
            available=True,
        )


def _state_with_form(base_url: str, parameter: str) -> State:
    st = State(base_url=base_url)
    st.last_http_url = base_url
    st.forms_by_url = {
        base_url: [
            {
                "action": base_url,
                "method": "POST",
                "inputs": [{"name": parameter, "type": "text"}],
            }
        ]
    }
    return st


@pytest.mark.asyncio
async def test_xss_specialist_full_five_phase_flow_yields_verified_finding(tmp_path):
    base_url = "http://localhost/search"
    parameter = "q"

    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps([
        '" autofocus onfocus=alert(1) x="',
        '"><img src=x onerror=alert(1)>',
    ]))
    memory = MemoryStore(":memory:")
    browser = _StubBrowserVerifier(executed=True)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        browser_verifier=browser,
        max_http_budget=50,
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=3))

    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.source == "xss"
    assert cand.action.type == ActionType.NOTE
    finding = cand.metadata["evidence"]
    assert finding["verified"] is True
    assert finding["parameter"] == parameter
    assert finding["context"] == "attr_quoted"
    assert "browser" in finding["evidence"]
    assert finding["evidence"]["browser"]["script_executed"] is True

    assert browser.calls, "browser verifier should be invoked"

    # Budget accounting was bumped on the episode state
    assert state.http_requests_used == len(http_tool.calls)
    assert state.tool_calls_http == len(http_tool.calls)

    # Second call after a verified finding is a no-op (short-circuit).
    more = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=3))
    pre_calls = len(http_tool.calls)
    assert more and more[0].metadata["evidence"]["verified"] is True
    assert len(http_tool.calls) == pre_calls


@pytest.mark.asyncio
async def test_xss_specialist_falls_back_to_unverified_without_browser():
    base_url = "http://localhost/search"
    parameter = "q"

    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        browser_verifier=None,
        max_http_budget=40,
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    assert candidates, "fallback should emit an unverified reflection finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xss_unverified_reflection"


@pytest.mark.asyncio
async def test_xss_specialist_skips_targets_already_tried(tmp_path):
    base_url = "http://localhost/search"
    parameter = "q"

    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")
    browser = _StubBrowserVerifier(executed=False)  # never script-executed -> no verify, keeps trying

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        browser_verifier=browser,
        max_http_budget=50,
    )

    state = _state_with_form(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    # Memory records every probed payload. The deterministic attr_quoted
    # library places the onfocus+autofocus variant first.
    assert memory.was_tried(
        episode_id=specialist._episode_id(),
        host="localhost",
        parameter=parameter,
        payload='" onfocus=alert(1) autofocus x="',
    )


@pytest.mark.asyncio
async def test_xss_specialist_respects_http_budget():
    base_url = "http://localhost/search"
    parameter = "q"

    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text="")
    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=None,
        browser_verifier=None,
        max_http_budget=4,  # below min_reserve_http default 8
    )
    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    assert candidates == []
    assert http_tool.calls == []


@pytest.mark.asyncio
async def test_xss_specialist_no_targets_returns_empty():
    http_tool = FakeHttp(responder=_vulnerable_echo("q"))
    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        browser_verifier=None,
    )
    state = State(base_url="http://localhost/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())
    assert candidates == []
    assert http_tool.calls == []


@pytest.mark.asyncio
async def test_xss_specialist_writes_trace_events_for_each_phase(tmp_path):
    from penage.core.tracer import JsonlTracer

    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-xss")

    base_url = "http://localhost/search"
    parameter = "q"
    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    browser = _StubBrowserVerifier(executed=True)
    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_verifier=browser,
        tracer=tracer,
    )

    state = _state_with_form(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phase_events = [e for e in events if e["event"] == "specialist_phase"]
    phases = sorted({e["payload"]["phase"] for e in phase_events})
    assert phases == [1, 2, 3, 4, 5]
