from __future__ import annotations

import pytest

from penage.sandbox.browser_base import Browser, BrowserError
from penage.sandbox.playwright_browser import PlaywrightBrowser


pytestmark = [pytest.mark.integration_slow]


def _data_url(html: str) -> str:
    # data: URLs are the cheapest way to exercise navigate/get_dom/eval_js
    # without standing up a local HTTP server. Playwright supports them for
    # page.goto in all three engines.
    return "data:text/html," + html


@pytest.mark.asyncio
async def test_navigate_and_get_dom_returns_rendered_html():
    browser = PlaywrightBrowser()
    try:
        await browser.navigate(_data_url("<h1>hello</h1>"))
        dom = await browser.get_dom()
        assert "<h1>hello</h1>" in dom
    finally:
        await browser.aclose()


@pytest.mark.asyncio
async def test_eval_js_evaluates_expression():
    browser = PlaywrightBrowser()
    try:
        await browser.navigate(_data_url("<h1>ok</h1>"))
        assert await browser.eval_js("1+1") == 2
    finally:
        await browser.aclose()


@pytest.mark.asyncio
async def test_alert_sets_penage_xss_marker():
    browser = PlaywrightBrowser()
    try:
        await browser.navigate(_data_url("<script>alert('xss')</script>hello"))
        # Serialize to string so the same probe the validator uses can see it.
        js = await browser.eval_js(
            "JSON.stringify(window.__penage_xss_marker__ || null)"
        )
        assert js is not None
        assert "alert" in js
        assert "xss" in js
    finally:
        await browser.aclose()


@pytest.mark.asyncio
async def test_marker_absent_without_alert():
    browser = PlaywrightBrowser()
    try:
        await browser.navigate(_data_url("<h1>safe</h1>"))
        js = await browser.eval_js(
            "JSON.stringify(window.__penage_xss_marker__ || null)"
        )
        # Probe returns either the JSON "null" sentinel or "[]" depending on
        # whether the array was ever initialised. Either means "no execution".
        assert js in {"null", "[]"}
    finally:
        await browser.aclose()


@pytest.mark.asyncio
async def test_aclose_is_idempotent():
    browser = PlaywrightBrowser()
    await browser.navigate(_data_url("<h1>ok</h1>"))
    await browser.aclose()
    # Second aclose must not raise.
    await browser.aclose()


@pytest.mark.asyncio
async def test_navigate_after_aclose_raises_browser_error():
    browser = PlaywrightBrowser()
    await browser.aclose()
    with pytest.raises(BrowserError):
        await browser.navigate(_data_url("<h1>nope</h1>"))


def test_satisfies_browser_protocol():
    browser = PlaywrightBrowser()
    assert isinstance(browser, Browser)
