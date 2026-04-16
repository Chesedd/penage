from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.specialists.shared.reflection_analyzer import (
    ReflectionAnalyzer,
    ReflectionContext,
    ReflectionContextType,
)


Responder = Callable[[Action], Observation]


@dataclass
class FakeHttpTool:
    responder: Responder
    calls: list[Action] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.calls = []

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)


def _find_injected(action: Action, parameter: str) -> str:
    from urllib.parse import parse_qsl, urlparse

    params = action.params
    if params.get("method") == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


@pytest.mark.asyncio
async def test_analyzer_classifies_html_body_reflection():
    def respond(action: Action) -> Observation:
        canary = _find_injected(action, "q")
        body = f"<html><body><h1>Results for {canary}</h1></body></html>"
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params["url"],
                "headers": {"content-type": "text/html"},
                "text_full": body,
                "text_excerpt": body[:200],
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    result = await analyzer.analyze("http://localhost/search", "q", tool)

    assert result.parameter == "q"
    assert len(tool.calls) == 8
    assert set(result.channels) == {"GET", "POST"}
    assert any(c.context_type == ReflectionContextType.HTML_BODY for c in result.contexts)


@pytest.mark.asyncio
async def test_analyzer_classifies_attr_quoted_reflection():
    def respond(action: Action) -> Observation:
        canary = _find_injected(action, "name")
        body = f'<input type="text" value="{canary}" />'
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params["url"],
                "headers": {"content-type": "text/html"},
                "text_full": body,
                "text_excerpt": body,
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    result = await analyzer.analyze("http://localhost/form", "name", tool)

    attr_ctxs = [c for c in result.contexts if c.context_type == ReflectionContextType.ATTR_QUOTED]
    assert attr_ctxs, f"expected ATTR_QUOTED, got {result.contexts}"
    assert attr_ctxs[0].quote_char == '"'
    assert attr_ctxs[0].tag_parent == "input"


@pytest.mark.asyncio
async def test_analyzer_classifies_js_string_reflection():
    def respond(action: Action) -> Observation:
        canary = _find_injected(action, "u")
        body = (
            "<html><head><script>var user = \"" + canary + "\";</script></head><body>hi</body></html>"
        )
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params["url"],
                "headers": {"content-type": "text/html"},
                "text_full": body,
                "text_excerpt": body,
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    result = await analyzer.analyze("http://localhost/profile", "u", tool)

    js_ctxs = [c for c in result.contexts if c.context_type == ReflectionContextType.JS_STRING]
    assert js_ctxs, f"expected JS_STRING, got {result.contexts}"
    assert js_ctxs[0].quote_char == '"'
    assert js_ctxs[0].tag_parent == "script"


@pytest.mark.asyncio
async def test_analyzer_reports_not_reflected_when_canary_absent():
    def respond(action: Action) -> Observation:
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params["url"],
                "headers": {"content-type": "text/html"},
                "text_full": "<html><body>static content</body></html>",
                "text_excerpt": "<html><body>static content</body></html>",
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    result = await analyzer.analyze("http://localhost/static", "x", tool)

    assert len(result.contexts) == 1
    assert result.contexts[0].context_type == ReflectionContextType.NOT_REFLECTED
    assert result.channels == []


@pytest.mark.asyncio
async def test_analyzer_detects_json_value_reflection():
    def respond(action: Action) -> Observation:
        canary = _find_injected(action, "name")
        body = '{"ok": true, "name": "' + canary + '"}'
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params["url"],
                "headers": {"content-type": "application/json"},
                "text_full": body,
                "text_excerpt": body,
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    result = await analyzer.analyze("http://localhost/api/lookup", "name", tool)

    assert any(c.context_type == ReflectionContextType.JSON_VALUE for c in result.contexts)


@pytest.mark.asyncio
async def test_analyzer_sends_get_and_post_requests():
    def respond(action: Action) -> Observation:
        return Observation(
            ok=True,
            data={
                "status_code": 200,
                "url": action.params.get("url"),
                "headers": {"content-type": "text/plain"},
                "text_full": "",
                "text_excerpt": "",
            },
        )

    analyzer = ReflectionAnalyzer()
    tool = FakeHttpTool(responder=respond)
    await analyzer.analyze("http://localhost/echo", "q", tool)

    methods = [str(a.params.get("method")) for a in tool.calls]
    assert methods.count("GET") == 4
    assert methods.count("POST") == 4
    for action in tool.calls:
        assert action.type == ActionType.HTTP
