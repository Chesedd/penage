from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from penage.core.rate_limit import RateLimiter
from penage.sandbox.playwright_browser import PlaywrightBrowser


class SpyRateLimiter:
    def __init__(self, inner: RateLimiter) -> None:
        self._inner = inner
        self.acquired_urls: list[str] = []

    @asynccontextmanager
    async def acquire(self, url: str):
        self.acquired_urls.append(url)
        async with self._inner.acquire(url):
            yield


class _FakePage:
    def __init__(self) -> None:
        self.navigated: list[str] = []
        self.content_calls: int = 0
        self.eval_calls: list[str] = []

    async def goto(self, url: str, *, wait_until: str, timeout: int) -> None:
        self.navigated.append(url)

    async def content(self) -> str:
        self.content_calls += 1
        return "<html></html>"

    async def evaluate(self, expr: str):
        self.eval_calls.append(expr)
        return None


@pytest.mark.asyncio
async def test_playwright_browser_navigate_uses_rate_limiter():
    spy = SpyRateLimiter(RateLimiter(None))
    browser = PlaywrightBrowser(rate_limiter=spy)

    # Bypass the real Playwright launch — _ensure short-circuits when _page is set.
    fake_page = _FakePage()
    browser._page = fake_page  # type: ignore[attr-defined]

    await browser.navigate("http://localhost:8080/page")

    assert fake_page.navigated == ["http://localhost:8080/page"]
    assert spy.acquired_urls == ["http://localhost:8080/page"]


@pytest.mark.asyncio
async def test_playwright_browser_get_dom_and_eval_js_do_not_acquire_rate_limiter():
    spy = SpyRateLimiter(RateLimiter(None))
    browser = PlaywrightBrowser(rate_limiter=spy)

    fake_page = _FakePage()
    browser._page = fake_page  # type: ignore[attr-defined]

    await browser.get_dom()
    await browser.eval_js("window.x")

    assert fake_page.content_calls == 1
    assert fake_page.eval_calls == ["window.x"]
    # get_dom / eval_js do not initiate target network requests — no acquire.
    assert spy.acquired_urls == []
