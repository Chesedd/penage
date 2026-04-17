from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest

from penage.core.actions import Action, ActionType
from penage.core.rate_limit import RateLimiter
from penage.tools.http_tool import HttpTool


class SpyRateLimiter:
    """Wraps a real RateLimiter so tests can assert acquire() was called."""

    def __init__(self, inner: RateLimiter) -> None:
        self._inner = inner
        self.acquired_urls: list[str] = []

    @asynccontextmanager
    async def acquire(self, url: str):
        self.acquired_urls.append(url)
        async with self._inner.acquire(url):
            yield


@pytest.mark.asyncio
async def test_http_tool_acquires_rate_limiter_around_request():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    spy = SpyRateLimiter(RateLimiter(None))
    tool = HttpTool.create_default(client, allowed_hosts={"localhost"}, rate_limiter=spy)

    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://localhost/probe"},
    )
    obs = await tool.run(action)
    await tool.aclose()

    assert obs.ok is True
    assert spy.acquired_urls == ["http://localhost/probe"]


@pytest.mark.asyncio
async def test_http_tool_acquire_not_called_for_disallowed_host():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))
    )
    spy = SpyRateLimiter(RateLimiter(None))
    tool = HttpTool.create_default(client, allowed_hosts={"localhost"}, rate_limiter=spy)

    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://example.com/denied"},
    )
    obs = await tool.run(action)
    await tool.aclose()

    assert obs.ok is False
    # allow-list rejection happens before any network I/O; no limiter slot used.
    assert spy.acquired_urls == []
