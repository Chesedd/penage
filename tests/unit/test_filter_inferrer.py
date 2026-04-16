from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import FilterModel
from penage.specialists.shared.filter_inferrer import FilterInferrer


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


def _extract_wrapped(action: Action, parameter: str) -> str:
    params = action.params
    if params.get("method") == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _html_echo(action: Action, parameter: str, rewrite=lambda s: s) -> Observation:
    injected = _extract_wrapped(action, parameter)
    body = f"<html><body>{rewrite(injected)}</body></html>"
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


@pytest.mark.asyncio
async def test_infer_marks_everything_allowed_when_echoed_verbatim():
    def respond(action: Action) -> Observation:
        return _html_echo(action, "q")

    inferrer = FilterInferrer()
    tool = FakeHttpTool(responder=respond)
    model = await inferrer.infer("http://localhost/echo", "q", "GET", tool)

    assert isinstance(model, FilterModel)
    assert model.parameter == "q"
    assert model.channel == "GET"
    assert set(model.allowed_tags) == {"<script>", "<img>", "<svg>", "<iframe>", "<body>", "<div>"}
    assert set(model.allowed_events) == {"onerror", "onload", "onmouseover", "onfocus", "onclick"}
    assert model.blocked_tags == []
    assert model.blocked_events == []
    assert model.transformed_chars == {}


@pytest.mark.asyncio
async def test_infer_marks_stripped_script_as_blocked():
    def respond(action: Action) -> Observation:
        def rewrite(s: str) -> str:
            return s.replace("<script>", "").replace("</script>", "")

        return _html_echo(action, "q", rewrite=rewrite)

    inferrer = FilterInferrer()
    tool = FakeHttpTool(responder=respond)
    model = await inferrer.infer("http://localhost/echo", "q", "POST", tool)

    assert "<script>" in model.blocked_tags
    assert "<img>" in model.allowed_tags


@pytest.mark.asyncio
async def test_infer_records_transformed_chars():
    def respond(action: Action) -> Observation:
        def rewrite(s: str) -> str:
            return s.replace("<", "&lt;").replace(">", "&gt;")

        return _html_echo(action, "q", rewrite=rewrite)

    inferrer = FilterInferrer()
    tool = FakeHttpTool(responder=respond)
    model = await inferrer.infer("http://localhost/echo", "q", "GET", tool)

    assert model.transformed_chars.get("<") == "&lt;"
    assert model.transformed_chars.get(">") == "&gt;"
    assert "<script>" in model.blocked_tags


@pytest.mark.asyncio
async def test_infer_rejects_unsupported_channel():
    inferrer = FilterInferrer()
    tool = FakeHttpTool(responder=lambda a: _html_echo(a, "q"))
    with pytest.raises(ValueError):
        await inferrer.infer("http://localhost/echo", "q", "PUT", tool)


@pytest.mark.asyncio
async def test_infer_treats_http_error_as_blocked():
    def respond(action: Action) -> Observation:
        return Observation(ok=False, error="boom")

    inferrer = FilterInferrer()
    tool = FakeHttpTool(responder=respond)
    model = await inferrer.infer("http://localhost/echo", "q", "GET", tool)

    assert set(model.blocked_tags) == {"<script>", "<img>", "<svg>", "<iframe>", "<body>", "<div>"}
    assert set(model.blocked_events) == {"onerror", "onload", "onmouseover", "onfocus", "onclick"}
    assert model.allowed_tags == []
