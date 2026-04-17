"""End-to-end XSS validation through the :class:`ValidationGate`.

Starts a tiny aiohttp server that reflects a query parameter into an HTML
attribute context and drives the :class:`XssSpecialist` gate-path with a
real :class:`PlaywrightBrowser`. The goal is to prove that post-migration
(etap 4.1.b.iii.β) the specialist's execution-proof signal really flows
through ``probe action → ValidationGate → BrowserEvidenceValidator →
state.last_validation`` — no inline browser calls remain.

Marked ``integration_slow`` so it's skipped by the default ``pytest -q``
run and executed explicitly via ``pytest -q -m integration_slow``.
"""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from aiohttp import web

from penage.core.actions import Action
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.sandbox.playwright_browser import PlaywrightBrowser
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from penage.tools.http_tool import HttpTool
from penage.validation.browser import BrowserEvidenceValidator
from penage.validation.gate import ValidationGate
from penage.validation.http import HttpEvidenceValidator


pytestmark = [pytest.mark.integration_slow]


async def _reflected_handler(request: web.Request) -> web.Response:
    """Reflect the ``q`` query parameter into an unquoted attribute context.

    The context deliberately breaks out via ``">`` so a payload like
    ``"><img src=x onerror=alert(1)>`` lands inline as executable HTML,
    mirroring the common DVWA-style reflected XSS sink.
    """
    raw = request.rel_url.query.get("q", "")
    body = (
        "<html><body><div>search: "
        f"<input value=\"{raw}\"/>"
        "</div></body></html>"
    )
    return web.Response(text=body, content_type="text/html")


@pytest_asyncio.fixture
async def reflected_xss_server() -> AsyncIterator[str]:
    app = web.Application()
    app.router.add_get("/search", _reflected_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()

    host, port = site._server.sockets[0].getsockname()[:2]  # type: ignore[union-attr]
    base_url = f"http://{host}:{port}"
    try:
        yield base_url
    finally:
        await runner.cleanup()


def _state_for(base_url: str) -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}/search?q=canary"
    return st


@pytest.mark.asyncio
async def test_xss_specialist_gate_path_produces_validated_finding(
    reflected_xss_server: str,
    tmp_path,
):
    base_url = reflected_xss_server

    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="e2e-xss-gate")

    client = httpx.AsyncClient()
    http_tool = HttpTool.create_default(client, allowed_hosts={"127.0.0.1", "localhost"})

    browser = PlaywrightBrowser()
    gate = ValidationGate(
        http_validator=HttpEvidenceValidator(),
        browser_validator=BrowserEvidenceValidator(browser),
        validation_mode="http",
    )
    recorder = ValidationRecorder(tracer=tracer)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=json.dumps([
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
        ])),
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        validation_gate=gate,
        validation_recorder=recorder,
        max_http_budget=40,
    )

    state = _state_for(base_url)
    try:
        candidates = await specialist.propose_async(
            state, config=SpecialistConfig(max_candidates=3)
        )
    finally:
        await http_tool.aclose()
        await browser.aclose()

    assert candidates, "specialist should emit at least one finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "xss_browser_verified"
    assert finding["evidence"]["validation_level"] == "validated"

    browser_evidence = finding["evidence"]["browser"]
    markers = browser_evidence["execution_markers"]
    assert markers, "execution markers must be populated via the JS probe"
    assert markers[0]["type"] in {"alert", "confirm", "prompt"}

    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"
    assert state.last_validation["kind"] == "xss_browser_execution"

    events = [
        json.loads(line)
        for line in trace_path.read_text().splitlines()
        if line.strip()
    ]
    validation_events = [e for e in events if e["event"] == "validation"]
    assert validation_events, "gate must have written at least one validation trace entry"
    assert any(
        e["payload"].get("kind") == "xss_browser_execution"
        for e in validation_events
    )


@pytest.mark.asyncio
async def test_xss_specialist_ablation_without_browser_falls_back_to_evidence(
    reflected_xss_server: str,
    tmp_path,
):
    """``--no-browser-verification`` equivalent: gate has no browser validator.

    The specialist still sees the payload reflected in the HTTP response
    and must emit an ``xss_unverified_reflection`` finding without any
    execution markers.
    """
    base_url = reflected_xss_server

    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="e2e-xss-ablation")

    client = httpx.AsyncClient()
    http_tool = HttpTool.create_default(client, allowed_hosts={"127.0.0.1", "localhost"})

    gate = ValidationGate(
        http_validator=HttpEvidenceValidator(),
        browser_validator=None,
        validation_mode="http",
    )
    recorder = ValidationRecorder(tracer=tracer)

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=json.dumps([
            '"><img src=x onerror=alert(1)>',
        ])),
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        validation_gate=gate,
        validation_recorder=recorder,
        max_http_budget=40,
    )

    state = _state_for(base_url)
    try:
        candidates = await specialist.propose_async(
            state, config=SpecialistConfig(max_candidates=3)
        )
    finally:
        await http_tool.aclose()

    assert candidates, "ablation path must still emit the reflection finding"
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xss_unverified_reflection"

    browser_evidence = finding["evidence"].get("browser") or {}
    assert browser_evidence.get("execution_markers") in (None, [])
