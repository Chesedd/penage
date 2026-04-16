from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.ssti import SstiSpecialist


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


def _param_value(action: Action, parameter: str) -> str:
    params = action.params
    if str(params.get("method") or "GET").upper() == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _ok(text: str, *, url: str, elapsed_ms: int = 100, status: int = 200) -> Observation:
    return Observation(
        ok=True,
        elapsed_ms=elapsed_ms,
        data={
            "status_code": status,
            "url": url,
            "headers": {"content-type": "text/html"},
            "text_full": text,
            "text_excerpt": text[:400],
        },
    )


def _state_with_query_target(base_url: str, parameter: str) -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}?{parameter}=hello"
    return st


def _jinja_like_engine(payload: str) -> str:
    """Evaluate an SSTI probe as a real Jinja2 engine would.

    Supports the specific probe set the specialist sends:
      - ``{{7*7}}`` -> ``49``
      - ``{{7*'7'}}`` -> ``7777777``
      - exploit payloads with a ``penage_jinja_*`` marker render to "<flask.Config …>penage_jinja_cfg"
    Everything else echoes the payload back (no evaluation).
    """
    if payload == "{{7*7}}":
        return "Hello, 49 world!"
    if payload == "{{7*'7'}}":
        return "Hello, 7777777 world!"
    if "penage_jinja_cfg" in payload:
        return "Hello, <class 'flask.config.Config'>penage_jinja_cfg world!"
    if "penage_jinja_rce" in payload:
        return "Hello, [<class 'object'>, <class 'subprocess.Popen'>]penage_jinja_rce world!"
    if "penage_jinja_self" in payload:
        return "Hello, <built-in module builtins>penage_jinja_self world!"
    # Anything else — echo verbatim; simulates a non-evaluating endpoint for
    # payloads this engine does not handle.
    return f"Hello, {payload} world!"


def _twig_like_engine(payload: str) -> str:
    """Twig renders ``{{7*7}}`` -> 49 AND ``{{7*'7'}}`` -> 49 (coerce+multiply)."""
    if payload == "{{7*7}}":
        return "<p>Result: 49</p>"
    if payload == "{{7*'7'}}":
        return "<p>Result: 49</p>"
    if "penage_twig_exec" in payload:
        return "<p>uid=33(www-data) gid=33(www-data) groups=33(www-data)penage_twig_exec</p>"
    if "penage_twig_env" in payload:
        return "<p>uid=33penage_twig_env</p>"
    return f"<p>Result: {payload}</p>"


@pytest.mark.asyncio
async def test_ssti_detects_jinja2_and_verifies_exploit():
    base_url = "http://localhost/render"
    parameter = "name"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        return _ok(_jinja_like_engine(value), url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    llm = FakeLLMClient(fixed_text="")
    memory = MemoryStore(":memory:")

    specialist = SstiSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=40,
    )

    state = _state_with_query_target(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    assert len(candidates) == 1
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["engine"] == "jinja2"
    assert finding["parameter"] == parameter
    # Marker present, payload echo absent -> evidence was drawn from engine output.
    assert finding["marker"].startswith("penage_jinja_")


@pytest.mark.asyncio
async def test_ssti_detects_twig_when_string_mul_coerces_to_49():
    base_url = "http://localhost/render"
    parameter = "q"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        return _ok(_twig_like_engine(value), url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SstiSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        max_http_budget=40,
    )

    state = _state_with_query_target(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    assert candidates, "expected an SSTI finding against the Twig-like mock"
    finding = candidates[0].metadata["evidence"]
    assert finding["engine"] == "twig"


@pytest.mark.asyncio
async def test_ssti_no_false_positive_on_benign_endpoint():
    base_url = "http://localhost/static"
    parameter = "q"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        return _ok(f"<html><body>hello {value}</body></html>", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SstiSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        max_http_budget=30,
    )

    state = _state_with_query_target(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    assert candidates == []


@pytest.mark.asyncio
async def test_ssti_writes_phase_trace_events(tmp_path):
    from penage.core.tracer import JsonlTracer

    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-ssti")

    base_url = "http://localhost/render"
    parameter = "name"

    def respond(action: Action) -> Observation:
        return _ok(_jinja_like_engine(_param_value(action, parameter)), url=action.params.get("url"))

    specialist = SstiSpecialist(
        http_tool=FakeHttp(responder=respond),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        max_http_budget=40,
    )

    state = _state_with_query_target(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phases = sorted({e["payload"]["phase"] for e in events if e["event"] == "specialist_phase"})
    assert phases == [1, 2, 3]


@pytest.mark.asyncio
async def test_ssti_short_circuits_after_verified_finding():
    base_url = "http://localhost/render"
    parameter = "name"

    def respond(action: Action) -> Observation:
        return _ok(_jinja_like_engine(_param_value(action, parameter)), url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SstiSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        max_http_budget=40,
    )
    state = _state_with_query_target(base_url, parameter)
    first = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))
    calls_after_first = len(http_tool.calls)

    second = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))
    assert first and second
    assert first[0].metadata["evidence"]["verified"] is True
    assert len(http_tool.calls) == calls_after_first


@pytest.mark.asyncio
async def test_ssti_respects_http_budget():
    specialist = SstiSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok("hi", url="x")),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        max_http_budget=4,  # below min_reserve_http default 8
    )
    state = _state_with_query_target("http://localhost/x", "name")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
