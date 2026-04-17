"""Golden-trace regression guards for the XSS specialist.

Stage 4.3: pins byte-level shape of the JSONL trace produced by
``XssSpecialist.propose_async`` for three deterministic scenarios:

* ``xss_reflected_evidence`` — payload reflected in the rendered DOM, browser
  probe reports no execution -> ``level="evidence"``, finding ``unverified``.
* ``xss_noop`` — HTTP responses never echo the canary -> phase 2 yields
  ``not_reflected``, no validation event is emitted.
* ``xss_execution_proof`` — payload reflected *and* the browser probe returns
  an execution marker -> ``level="validated"``, finding ``verified``.

The tests are in-memory only: no real HTTP, no chromium, no Docker. The
canary and marker UUIDs generated internally by ``ReflectionAnalyzer`` and
``FilterInferrer`` do not leak into the trace, so ``time.time()`` (via
``JsonlTracer._now_ms``) is the only ephemeral source -> the harness masks
the ``ts_ms`` fields during normalization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.sandbox.fake_browser import FakeBrowser
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from penage.validation.browser import BrowserEvidenceValidator, DEFAULT_PROBE_EXPR

from tests.support.golden_trace import (
    assert_trace_matches_golden,
    load_trace_events,
)


_BASE_URL = "http://localhost/search"
_PARAMETER = "q"


Responder = Callable[[Action], Observation]


@dataclass
class _FakeHttp:
    """HTTP backend stub driven by a per-test responder.

    Kept local so the fake never writes to the tracer — the JSONL trace
    should contain only events emitted by the specialist / recorder, so
    transport-level noise stays out of the golden snapshot.
    """

    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


class _PayloadReflectingBrowser(FakeBrowser):
    """FakeBrowser variant that reflects the injected parameter into the DOM.

    The probe URL the specialist builds depends on which payload the
    mutator selects, which in turn depends on the filter model. Rather
    than hard-coding the expected URL/DOM, this fake parses the ``q`` query
    parameter out of each navigation and bakes it into a minimal HTML
    document so ``BrowserEvidenceValidator`` sees the payload as reflected.
    """

    def __init__(self, *, parameter: str, js_result: Any) -> None:
        super().__init__()
        self._parameter = parameter
        self._js_result = js_result

    async def get_dom(self) -> str:
        if self._current_url is None:
            return ""
        try:
            q = dict(parse_qsl(urlparse(self._current_url).query, keep_blank_values=True))
        except Exception:
            return ""
        injected = q.get(self._parameter, "")
        return f"<html><body><div>{injected}</div></body></html>"

    async def eval_js(self, expr: str) -> Any:
        self.js_calls.append(expr)
        return self._js_result


def _extract_param(action: Action, name: str) -> str:
    params = action.params or {}
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params.get("url") or "")).query, keep_blank_values=True))
        return q.get(name, "")
    return str((params.get("data") or {}).get(name, ""))


def _reflecting_responder(parameter: str) -> Responder:
    """HTTP responder that echoes ``parameter`` back verbatim inside HTML."""

    def respond(action: Action) -> Observation:
        injected = _extract_param(action, parameter)
        body = (
            "<html><body><form method='POST' action='/search'>"
            f"<input type='text' name='{parameter}' value='{injected}' />"
            f"</form><div>{injected}</div></body></html>"
        )
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


def _noop_responder() -> Responder:
    """HTTP responder that never reflects the injected value."""

    def respond(action: Action) -> Observation:
        body = "<html><body><p>welcome</p></body></html>"
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


def _state_with_form() -> State:
    st = State(base_url=_BASE_URL)
    st.last_http_url = _BASE_URL
    st.forms_by_url = {
        _BASE_URL: [
            {
                "action": _BASE_URL,
                "method": "GET",
                "inputs": [{"name": _PARAMETER, "type": "text"}],
            }
        ]
    }
    return st


def _build_specialist(
    *,
    http_tool: _FakeHttp,
    llm: FakeLLMClient,
    tracer: JsonlTracer,
    browser_validator: BrowserEvidenceValidator | None,
) -> XssSpecialist:
    recorder = (
        ValidationRecorder(tracer=tracer, validator=None)
        if browser_validator is not None
        else None
    )
    return XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_validator=browser_validator,
        validation_recorder=recorder,
        tracer=tracer,
        max_http_budget=40,
    )


async def _run_specialist(specialist: XssSpecialist, state: State) -> list[Any]:
    return await specialist.propose_async(
        state, config=SpecialistConfig(max_candidates=1),
    )


@pytest.mark.asyncio
async def test_xss_reflected_evidence_golden(tmp_path) -> None:
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="golden-xss-reflected-evidence")
    http_tool = _FakeHttp(responder=_reflecting_responder(_PARAMETER))
    llm = FakeLLMClient(fixed_text="[]")

    browser = _PayloadReflectingBrowser(parameter=_PARAMETER, js_result="")
    validator = BrowserEvidenceValidator(browser)

    specialist = _build_specialist(
        http_tool=http_tool, llm=llm, tracer=tracer, browser_validator=validator,
    )

    state = _state_with_form()
    candidates = await _run_specialist(specialist, state)
    await browser.aclose()

    assert candidates, "specialist should emit an unverified finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["evidence"]["validation_level"] == "evidence"

    events = load_trace_events(tmp_path / "trace.jsonl")
    assert_trace_matches_golden(events, "xss_reflected_evidence")


@pytest.mark.asyncio
async def test_xss_noop_golden(tmp_path) -> None:
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="golden-xss-noop")
    http_tool = _FakeHttp(responder=_noop_responder())
    llm = FakeLLMClient(fixed_text="[]")

    specialist = _build_specialist(
        http_tool=http_tool, llm=llm, tracer=tracer, browser_validator=None,
    )

    state = _state_with_form()
    candidates = await _run_specialist(specialist, state)

    assert not candidates, "no reflection -> no finding"
    assert state.last_validation is None

    events = load_trace_events(tmp_path / "trace.jsonl")
    assert_trace_matches_golden(events, "xss_noop")


@pytest.mark.asyncio
async def test_xss_execution_proof_golden(tmp_path) -> None:
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="golden-xss-execution-proof")
    http_tool = _FakeHttp(responder=_reflecting_responder(_PARAMETER))
    llm = FakeLLMClient(fixed_text="[]")

    browser = _PayloadReflectingBrowser(
        parameter=_PARAMETER,
        js_result=json.dumps([{"type": "alert", "message": "xss"}]),
    )
    validator = BrowserEvidenceValidator(browser)

    specialist = _build_specialist(
        http_tool=http_tool, llm=llm, tracer=tracer, browser_validator=validator,
    )

    state = _state_with_form()
    candidates = await _run_specialist(specialist, state)
    await browser.aclose()

    assert candidates, "specialist should emit a verified finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["evidence"]["validation_level"] == "validated"

    # Spot-check the browser saw the default probe expression.
    assert browser.js_calls == [DEFAULT_PROBE_EXPR]

    events = load_trace_events(tmp_path / "trace.jsonl")
    assert_trace_matches_golden(events, "xss_execution_proof")
