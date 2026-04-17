from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from penage.core.actions import Action, ActionType
from penage.core.rate_limit import RateLimiter
from penage.sandbox.base import SandboxResult
from penage.tools.curl_http_tool import CurlHttpTool


class OrderingRateLimiterSpy:
    """Wraps a real RateLimiter and records acquire/subprocess ordering.

    Shares a single ``events`` list with :class:`RecordingSandbox` so the test
    can assert that ``acquire`` fires strictly before ``run_shell``.
    """

    def __init__(self, inner: RateLimiter, events: list[tuple[str, str]]) -> None:
        self._inner = inner
        self._events = events

    @asynccontextmanager
    async def acquire(self, url: str):
        self._events.append(("acquire", url))
        async with self._inner.acquire(url):
            yield


class RecordingSandbox:
    def __init__(self, events: list[tuple[str, str]]) -> None:
        self._events = events
        self.commands: list[str] = []

    async def run_shell(self, *, cmd: str, timeout_s: float, cwd=None, env=None) -> SandboxResult:
        self.commands.append(cmd)
        self._events.append(("run_shell", cmd))
        return SandboxResult(
            ok=True,
            exit_code=0,
            stdout="HTTP/1.1 200 OK\r\n\r\nbody",
            stderr="",
            elapsed_ms=1,
            error=None,
        )

    async def run_python(self, *, code: str, timeout_s: float, cwd=None, env=None) -> SandboxResult:
        raise AssertionError("not used")


@pytest.mark.asyncio
async def test_curl_http_tool_uses_rate_limiter():
    events: list[tuple[str, str]] = []
    sandbox = RecordingSandbox(events)
    spy = OrderingRateLimiterSpy(RateLimiter(None), events)
    tool = CurlHttpTool.create_default(sandbox, allowed_hosts={"localhost"}, rate_limiter=spy)

    action = Action(
        type=ActionType.HTTP,
        params={
            "method": "GET",
            "url": "http://localhost/probe",
            "params": {"q": "x"},
        },
    )
    obs = await tool.run(action)

    assert obs.ok is True
    # acquire must happen strictly before the subprocess (curl) call.
    assert [kind for kind, _ in events] == ["acquire", "run_shell"]
    # acquire is called with the *effective* URL — the same one that
    # ends up on the curl command line (query string merged in).
    acquire_url = events[0][1]
    assert acquire_url == "http://localhost/probe?q=x"
    assert acquire_url in events[1][1]


@pytest.mark.asyncio
async def test_curl_http_tool_rate_limiter_not_called_for_disallowed_host():
    events: list[tuple[str, str]] = []
    sandbox = RecordingSandbox(events)
    spy = OrderingRateLimiterSpy(RateLimiter(None), events)
    tool = CurlHttpTool.create_default(sandbox, allowed_hosts={"localhost"}, rate_limiter=spy)

    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://example.com/denied"},
    )
    obs = await tool.run(action)

    assert obs.ok is False
    # allow-list rejection happens before any network I/O; no limiter slot used.
    assert events == []
