from __future__ import annotations

import httpx
import pytest

from penage.core.actions import Action, ActionType
from penage.tools.http_tool import HttpTool


@pytest.mark.asyncio
async def test_http_tool_builds_normalized_observation_from_httpx_response():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "http://localhost/flag"
        body = '<html><body><a href="/next">next</a> FLAG{demo_flag}</body></html>'
        return httpx.Response(200, headers={"content-type": "text/html"}, text=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    tool = HttpTool.create_default(client, allowed_hosts={"localhost"})
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/flag"})

    obs = await tool.run(action)
    await tool.aclose()

    assert obs.ok is True
    assert obs.data["status_code"] == 200
    assert obs.data["transport"] == "httpx"
    assert "/next" in obs.data["paths"]
    assert obs.data["contains_flag_like"] is True
    assert "FLAG{demo_flag}" in obs.data["flag_snippets"][0]


@pytest.mark.asyncio
async def test_http_tool_rejects_disallowed_host():
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, text="ok")))
    tool = HttpTool.create_default(client, allowed_hosts={"localhost"})
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://example.com/"})

    obs = await tool.run(action)
    await tool.aclose()

    assert obs.ok is False
    assert "allowlist" in (obs.error or "")