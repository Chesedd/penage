from __future__ import annotations

import pytest

from penage.sandbox.browser_base import Browser, BrowserError
from penage.sandbox.playwright_browser import PlaywrightBrowser


def test_constructor_defaults_keep_browser_cold():
    browser = PlaywrightBrowser()
    # Lazy init: nothing touches Playwright until the first I/O.
    assert browser._page is None
    assert browser._browser is None
    assert browser._closed is False


def test_constructor_accepts_overrides():
    browser = PlaywrightBrowser(
        headless=False,
        navigate_wait_until="networkidle",
        navigate_timeout_ms=500,
    )
    assert browser._headless is False
    assert browser._wait_until == "networkidle"
    assert browser._timeout_ms == 500


def test_satisfies_browser_protocol():
    # Protocol is @runtime_checkable; mismatched signatures would fail this.
    assert isinstance(PlaywrightBrowser(), Browser)


@pytest.mark.asyncio
async def test_aclose_is_idempotent_without_navigate():
    browser = PlaywrightBrowser()
    await browser.aclose()
    assert browser._closed is True
    # Second aclose must be a no-op.
    await browser.aclose()
    assert browser._closed is True


@pytest.mark.asyncio
async def test_methods_raise_after_aclose():
    browser = PlaywrightBrowser()
    await browser.aclose()
    with pytest.raises(BrowserError):
        await browser.navigate("data:text/html,<h1>x</h1>")
    with pytest.raises(BrowserError):
        await browser.get_dom()
    with pytest.raises(BrowserError):
        await browser.eval_js("1+1")
