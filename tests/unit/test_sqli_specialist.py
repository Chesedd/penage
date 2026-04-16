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
from penage.specialists.vulns.sqli import SqliSpecialist


Responder = Callable[[Action], Observation]

MYSQL_ERROR_BODY = (
    "<html><body><h1>Error</h1><p>You have an error in your SQL syntax; "
    "check the manual that corresponds to your MySQL server version "
    "5.7.28 for the right syntax to use near ''' at line 1</p></body></html>"
)


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


def _ok_response(text: str, *, url: str, elapsed_ms: int = 120, status: int = 200) -> Observation:
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
    st.last_http_url = f"{base_url}?{parameter}=1"
    return st


@pytest.mark.asyncio
async def test_sqli_specialist_detects_mysql_error_based_and_extracts_version():
    base_url = "http://localhost/item"
    parameter = "id"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        if value in ("", "baseline", "1"):
            return _ok_response(
                f"<html><body>Item #{value or '?'}</body></html>",
                url=action.params.get("url"),
            )
        return _ok_response(MYSQL_ERROR_BODY, url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    llm = FakeLLMClient(fixed_text="")
    memory = MemoryStore(":memory:")
    specialist = SqliSpecialist(
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
    assert finding["mode"] == "error_based"
    assert finding["backend"] == "mysql"
    assert finding["extracted"] == "5.7.28"
    assert finding["parameter"] == parameter

    assert memory.was_tried(
        episode_id=specialist._episode_id(),
        host="localhost",
        parameter=parameter,
        payload="'",
    )

    assert state.http_requests_used == len(http_tool.calls)


@pytest.mark.asyncio
async def test_sqli_specialist_detects_blind_timing_on_sleep_payload():
    base_url = "http://localhost/search"
    parameter = "q"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        url = action.params.get("url")
        # Fast baseline requests: the specialist uses value="baseline" for them.
        if value in ("baseline", "", "1"):
            return _ok_response("<html><body>ok</body></html>", url=url, elapsed_ms=150)
        # Error probes: echo a benign response (no backend signature, no error).
        if "SLEEP" not in value.upper() and "PG_SLEEP" not in value.upper() and "WAITFOR" not in value.upper() and "RANDOMBLOB" not in value.upper() and "BENCHMARK" not in value.upper():
            return _ok_response("<html><body>no results</body></html>", url=url, elapsed_ms=180)
        # Timing payloads: simulate a long response well above the 5s threshold.
        return _ok_response("<html><body>ok</body></html>", url=url, elapsed_ms=5600)

    http_tool = FakeHttp(responder=respond)
    llm = FakeLLMClient(fixed_text="")
    memory = MemoryStore(":memory:")
    specialist = SqliSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=memory,
        max_http_budget=60,
    )

    state = _state_with_query_target(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    assert candidates, "expected a blind-timing finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["mode"] == "blind_timing"
    assert finding["hits"] >= 2
    assert finding["probes"] == 3
    # Every timing payload we fired should show a delta above threshold.
    assert all(d >= 5.0 for d in finding["deltas_s"])


@pytest.mark.asyncio
async def test_sqli_specialist_no_false_positive_on_benign_endpoint():
    base_url = "http://localhost/page"
    parameter = "q"

    def respond(action: Action) -> Observation:
        return _ok_response(
            "<html><body><p>Welcome — results here</p></body></html>",
            url=action.params.get("url"),
            elapsed_ms=140,
        )

    http_tool = FakeHttp(responder=respond)
    llm = FakeLLMClient(fixed_text="")
    specialist = SqliSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=None,
        max_http_budget=40,
    )

    state = _state_with_query_target(base_url, parameter)
    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=3))

    assert candidates == []


@pytest.mark.asyncio
async def test_sqli_specialist_respects_http_budget():
    specialist = SqliSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok_response("ok", url="x")),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        max_http_budget=5,  # below default min_reserve_http=10
    )
    state = _state_with_query_target("http://localhost/x", "q")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_sqli_specialist_writes_phase_trace_events(tmp_path):
    from penage.core.tracer import JsonlTracer

    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-sqli")

    base_url = "http://localhost/item"
    parameter = "id"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        if value in ("", "baseline", "1"):
            return _ok_response("<html>ok</html>", url=action.params.get("url"))
        return _ok_response(MYSQL_ERROR_BODY, url=action.params.get("url"))

    specialist = SqliSpecialist(
        http_tool=FakeHttp(responder=respond),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        max_http_budget=40,
    )

    state = _state_with_query_target(base_url, parameter)
    await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phase_events = [e for e in events if e["event"] == "specialist_phase"]
    phases = sorted({e["payload"]["phase"] for e in phase_events})
    # Phase 3 (blind) may be skipped when an error-based verified finding appears first.
    assert 1 in phases and 2 in phases


@pytest.mark.asyncio
async def test_sqli_specialist_short_circuits_after_verified_finding():
    base_url = "http://localhost/item"
    parameter = "id"

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        if value in ("", "baseline", "1"):
            return _ok_response("<html>ok</html>", url=action.params.get("url"))
        return _ok_response(MYSQL_ERROR_BODY, url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SqliSpecialist(
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
    # Second call re-emits the finding without any new HTTP traffic.
    assert len(http_tool.calls) == calls_after_first
