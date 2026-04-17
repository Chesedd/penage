"""E2E: XssSpecialist execution-proof flows through the shared BrowserEvidenceValidator.

Exercises the full gate-path after Stage 4.1.b.iii.β: the specialist's
probe action carries ``browser_target=True``; a real
:class:`~penage.sandbox.playwright_browser.PlaywrightBrowser` fronts the
validator; the orchestrator's :class:`~penage.core.validation_recorder.ValidationRecorder`
writes the result to ``state.last_validation`` and to the trace.

Marked :pytest:`integration_slow` because it launches chromium. Run with::

    pytest -q -m integration_slow tests/integration/test_xss_through_gate.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.sandbox.playwright_browser import PlaywrightBrowser
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from penage.validation.browser import BrowserEvidenceValidator


pytestmark = [pytest.mark.integration_slow]


_VULN_DATA_URL_TEMPLATE = (
    "data:text/html,"
    "<html><body>"
    "<form method='GET' action='data:text/html,<h1>noop</h1>'>"
    "<input name='q' value='{injected}' />"
    "</form>"
    "<div id='reflect'>{injected}</div>"
    "</body></html>"
)


Responder = Callable[[Action], Observation]


@dataclass
class _FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


def _extract_param(action: Action, name: str) -> str:
    params = action.params or {}
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params.get("url") or "")).query, keep_blank_values=True))
        return q.get(name, "")
    return str((params.get("data") or {}).get(name, ""))


def _reflecting_html_tool(parameter: str) -> Responder:
    """HTTP mock that reflects ``parameter`` verbatim inside an attribute."""

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


class _InlinePayloadBrowser(PlaywrightBrowser):
    """PlaywrightBrowser variant that rewrites the navigation URL to a
    ``data:`` URI with the XSS payload baked in.

    Required because the specialist aims its probe at ``http://localhost``
    hosts that don't exist in CI. Preserves the real chromium evaluation
    and init-script hooks (``window.__penage_xss_marker__``) so the
    evidence-validator path is genuinely exercised end-to-end.
    """

    def __init__(self, *, parameter: str, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._parameter = parameter

    async def navigate(self, url: str) -> None:
        try:
            parsed = urlparse(url)
            q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            injected = q.get(self._parameter, "")
        except Exception:
            injected = ""
        rewritten = _VULN_DATA_URL_TEMPLATE.format(injected=injected)
        await super().navigate(rewritten)


def _base_url() -> str:
    return "http://localhost/search"


def _state_with_form(parameter: str) -> State:
    st = State(base_url=_base_url())
    st.last_http_url = _base_url()
    st.forms_by_url = {
        _base_url(): [
            {
                "action": _base_url(),
                "method": "GET",
                "inputs": [{"name": parameter, "type": "text"}],
            }
        ]
    }
    return st


def _payload_triggering_alert() -> str:
    # Break out of the value attribute, inject a script tag that writes the
    # marker directly. The PlaywrightBrowser init-script has already replaced
    # window.alert, but writing to the marker array achieves the same
    # detection outcome — this covers the end-to-end validation code path
    # regardless of how the payload coerces execution.
    return "'><script>window.__penage_xss_marker__=[{type:'alert',message:'xss'}]</script>"


@pytest.mark.asyncio
async def test_xss_through_gate_with_browser_verification(tmp_path) -> None:
    parameter = "q"
    http_tool = _FakeHttp(responder=_reflecting_html_tool(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps([_payload_triggering_alert()]))
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="e2e-xss-gate")
    recorder = ValidationRecorder(tracer=tracer, validator=None)

    browser = _InlinePayloadBrowser(parameter=parameter)
    validator = BrowserEvidenceValidator(browser)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_validator=validator,
        validation_recorder=recorder,
        tracer=tracer,
        max_http_budget=40,
    )

    state = _state_with_form(parameter)
    try:
        candidates = await specialist.propose_async(
            state, config=SpecialistConfig(max_candidates=2),
        )
    finally:
        await browser.aclose()

    assert candidates, "specialist should emit at least one candidate"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["evidence"]["validation_level"] == "validated"

    browser_evidence = finding["evidence"]["browser"]
    assert browser_evidence["execution_markers"], (
        "browser evidence should include parsed execution markers"
    )
    assert browser_evidence["execution_markers"][0]["type"] == "alert"

    # Gate-path wrote the validation result into state and trace.
    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"

    events = [
        json.loads(line)
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
        if line.strip()
    ]
    validation_events = [e for e in events if e["event"] == "validation"]
    assert validation_events, "recorder should write validation event to trace"
    assert validation_events[-1]["payload"]["result"]["kind"] == "xss_browser_execution"


@pytest.mark.asyncio
async def test_xss_through_gate_ablation_no_browser_verification(tmp_path) -> None:
    """``--no-browser-verification`` ablation: no PlaywrightBrowser, no validator.

    The specialist still emits a finding for reflected payloads, but the
    finding is ``unverified`` (no execution proof) and no browser-derived
    evidence is attached.
    """
    parameter = "q"
    http_tool = _FakeHttp(responder=_reflecting_html_tool(parameter))
    llm = FakeLLMClient(fixed_text=json.dumps([_payload_triggering_alert()]))
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="e2e-xss-ablation")

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_validator=None,
        validation_recorder=None,
        tracer=tracer,
        max_http_budget=40,
    )

    state = _state_with_form(parameter)
    candidates = await specialist.propose_async(
        state, config=SpecialistConfig(max_candidates=2),
    )

    assert candidates
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xss_unverified_reflection"
    assert "browser" not in finding["evidence"]
    assert state.last_validation is None
