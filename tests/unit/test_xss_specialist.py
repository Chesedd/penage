from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.sandbox.fake_browser import FakeBrowser
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from penage.validation.browser import BrowserEvidenceValidator, MARKERS_JSON_EXPR
from penage.validation.gate import ValidationGate
from penage.validation.http import HttpEvidenceValidator


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


def _build_gate(browser: FakeBrowser) -> ValidationGate:
    return ValidationGate(
        http_validator=HttpEvidenceValidator(),
        browser_validator=BrowserEvidenceValidator(browser),
        validation_mode="http",
    )


def _configure_executing_browser(fake: FakeBrowser, parameter: str) -> None:
    """Wire FakeBrowser so any POST-probe URL (form action) reports execution.

    Because the specialist posts to a fixed action URL with different
    payloads per call, we program both DOM responses (reflection check) and
    marker JSON (execution signal) for that URL. The DOM contains the
    payload literally so the validator's reflection guard passes on every
    call — the programmed DOM below is only a harness shortcut and is not
    meant to model a real browser rendering.
    """

    _ = parameter

    class _AnyPayloadDom(dict):
        def get(self, key, default=None):
            return default

    # We can't pre-compute payload-dependent DOM keys, so pre-seed by
    # overriding FakeBrowser behavior via subclass pattern below is overkill.
    # Tests below instead program FakeBrowser dynamically per action by
    # rebuilding it for each probe. See tests for pattern.
    _ = _AnyPayloadDom


class _ProgrammableBrowser(FakeBrowser):
    """FakeBrowser variant that returns a payload-reflecting DOM for every URL.

    The specialist POSTs to a fixed action URL but each probe carries a
    different payload, so a plain ``dom_responses`` dict keyed by URL is
    insufficient. Instead, we read ``browser_payload`` off the last
    navigation URL via the state hook below — but since that isn't
    available here, we accept any URL and echo the navigator's most-recent
    ``browser_payload`` as the DOM. The validator compares ``payload in
    dom``, which is satisfied when the DOM contains the payload.

    The test passes the current payload via the ``_next_payload`` slot
    before every call (see usage in tests).
    """

    def __init__(self, *, executed: bool) -> None:
        super().__init__()
        self._executed = executed
        self._next_payload: str = ""

    def set_next_payload(self, payload: str) -> None:
        self._next_payload = payload

    async def get_dom(self) -> str:
        payload = self._next_payload or ""
        return f"<html><body>reflected: {payload}</body></html>"

    async def eval_js(self, expr: str) -> Any:
        self.js_calls.append(expr)
        if expr == MARKERS_JSON_EXPR:
            if self._executed:
                return json.dumps([{"type": "alert", "message": "1"}])
            return "[]"
        if self._executed:
            return "__penage_xss_marker__"
        return ""


def _http_with_payload_injection(fake_browser: _ProgrammableBrowser, parameter: str) -> Responder:
    """HTTP responder that mirrors the POST payload into the fake browser.

    Every time the specialist calls http_tool.run(probe), we extract the
    posted payload and tell ``_ProgrammableBrowser`` to use it for the
    next get_dom(). This keeps the reflection assertion in the validator
    satisfied without requiring the test to pre-enumerate payloads.
    """

    echo = _vulnerable_echo(parameter)

    def respond(action: Action) -> Observation:
        injected = _reflected_param_value(action, parameter)
        if injected:
            fake_browser.set_next_payload(injected)
        return echo(action)

    return respond


@pytest.mark.asyncio
async def test_xss_specialist_gate_path_yields_validated_finding():
    base_url = "http://localhost/search"
    parameter = "q"

    browser = _ProgrammableBrowser(executed=True)
    http_tool = FakeHttp(responder=_http_with_payload_injection(browser, parameter))
    llm = FakeLLMClient(fixed_text=json.dumps([
        '" autofocus onfocus=alert(1) x="',
        '"><img src=x onerror=alert(1)>',
    ]))
    memory = MemoryStore(":memory:")

    gate = _build_gate(browser)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=50,
        validation_gate=gate,
        # recorder is intentionally None — the specialist must still assemble
        # a validated finding off the gate's return value even when the
        # recorder hasn't been wired (e.g. in harness tests).
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=3))

    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.source == "xss"
    assert cand.action.type == ActionType.NOTE
    finding = cand.metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "xss_browser_verified"
    assert finding["parameter"] == parameter
    assert finding["evidence"]["validation_level"] == "validated"
    browser_ev = finding["evidence"]["browser"]
    assert browser_ev["payload"] in browser_ev["reflection_dom_fragment"]
    markers = browser_ev["execution_markers"]
    assert markers and markers[0]["type"] == "alert"

    # Probe carried the browser_target flag so the gate's browser branch fired.
    assert any(a.params.get("browser_target") is True for a in http_tool.calls)

    # Budget accounting was bumped on the episode state
    assert state.http_requests_used == len(http_tool.calls)
    assert state.tool_calls_http == len(http_tool.calls)

    # Second call after a verified finding is a no-op (short-circuit).
    more = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=3))
    pre_calls = len(http_tool.calls)
    assert more and more[0].metadata["evidence"]["verified"] is True
    assert len(http_tool.calls) == pre_calls


@pytest.mark.asyncio
async def test_xss_specialist_records_validation_on_state_via_recorder(tmp_path):
    base_url = "http://localhost/search"
    parameter = "q"

    browser = _ProgrammableBrowser(executed=True)
    http_tool = FakeHttp(responder=_http_with_payload_injection(browser, parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")

    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="unit-xss-gate")
    gate = _build_gate(browser)
    recorder = ValidationRecorder(tracer=tracer)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
        validation_gate=gate,
        validation_recorder=recorder,
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    assert candidates
    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"
    assert state.last_validation["kind"] == "xss_browser_execution"
    assert state.validation_validated_count == 1

    events = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines() if line.strip()]
    kinds = {e["event"] for e in events}
    assert "validation" in kinds


@pytest.mark.asyncio
async def test_xss_specialist_evidence_level_when_browser_reflects_without_execution():
    base_url = "http://localhost/search"
    parameter = "q"

    browser = _ProgrammableBrowser(executed=False)
    http_tool = FakeHttp(responder=_http_with_payload_injection(browser, parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")

    gate = _build_gate(browser)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=40,
        validation_gate=gate,
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    assert candidates, "evidence-level finding expected when browser reflects without execution"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xss_unverified_reflection"
    assert finding["evidence"]["validation_level"] == "evidence"
    assert finding["evidence"]["browser"]["execution_markers"] == []


@pytest.mark.asyncio
async def test_xss_specialist_ablation_without_gate_falls_back_to_http_reflection():
    base_url = "http://localhost/search"
    parameter = "q"

    http_tool = FakeHttp(responder=_vulnerable_echo(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=40,
        validation_gate=None,
    )

    state = _state_with_form(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    assert candidates, "fallback should emit an unverified reflection finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xss_unverified_reflection"
    assert finding["evidence"]["browser"] == {"available": False}


@pytest.mark.asyncio
async def test_xss_specialist_skips_targets_already_tried():
    base_url = "http://localhost/search"
    parameter = "q"

    browser = _ProgrammableBrowser(executed=False)
    http_tool = FakeHttp(responder=_http_with_payload_injection(browser, parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    memory = MemoryStore(":memory:")
    gate = _build_gate(browser)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=50,
        validation_gate=gate,
    )

    state = _state_with_form(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

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
        max_http_budget=4,  # below min_reserve_http default 8
        validation_gate=None,
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
        validation_gate=None,
    )
    state = State(base_url="http://localhost/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())
    assert candidates == []
    assert http_tool.calls == []


@pytest.mark.asyncio
async def test_xss_specialist_writes_trace_events_for_each_phase(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-xss")

    base_url = "http://localhost/search"
    parameter = "q"

    browser = _ProgrammableBrowser(executed=True)
    http_tool = FakeHttp(responder=_http_with_payload_injection(browser, parameter))
    llm = FakeLLMClient(fixed_text=json.dumps(['" onfocus=alert(1) x="']))
    gate = _build_gate(browser)
    recorder = ValidationRecorder(tracer=tracer)
    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        validation_gate=gate,
        validation_recorder=recorder,
    )

    state = _state_with_form(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=2))

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phase_events = [e for e in events if e["event"] == "specialist_phase"]
    phases = sorted({e["payload"]["phase"] for e in phase_events})
    assert phases == [1, 2, 3, 4, 5]
