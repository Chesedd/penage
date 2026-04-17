from __future__ import annotations

import logging
from typing import Any

from penage.core.rate_limit import RateLimiter
from penage.sandbox.browser_base import BrowserError

logger = logging.getLogger(__name__)


_DEFAULT_NAVIGATE_TIMEOUT_MS = 15000
_DEFAULT_WAIT_UNTIL = "load"


_INIT_SCRIPT = """
(() => {
  const setMarker = (type, msg) => {
    if (!Array.isArray(window.__penage_xss_marker__)) {
      window.__penage_xss_marker__ = [];
    }
    try {
      window.__penage_xss_marker__.push({type: type, message: String(msg)});
    } catch (_e) {
      window.__penage_xss_marker__.push({type: type, message: ''});
    }
  };
  try { window.alert = (msg) => { setMarker('alert', msg); }; } catch (_e) {}
  try { window.confirm = (msg) => { setMarker('confirm', msg); return false; }; } catch (_e) {}
  try { window.prompt = (msg) => { setMarker('prompt', msg); return null; }; } catch (_e) {}
})();
"""


class PlaywrightBrowser:
    """Async :class:`Browser` backend backed by Playwright chromium.

    The browser is lazily initialized on the first call to :meth:`navigate`
    (or any other I/O method) and is kept alive for the lifetime of the
    instance — a single chromium process, context, and page are reused
    across navigations. ``aclose`` is idempotent and MUST be awaited exactly
    once per episode (invariant #11 in ``CLAUDE.md``).

    Execution detection is wired to match
    :class:`penage.validation.browser.BrowserEvidenceValidator`: an init
    script installs overrides for ``window.alert`` / ``window.confirm`` /
    ``window.prompt`` that push structured records into
    ``window.__penage_xss_marker__`` (a JS array). The default probe
    expression ``window.__penage_xss_marker__ || ''`` therefore returns a
    non-empty array when a payload triggers one of those dialogs.

    Parameters
    ----------
    headless:
        Run chromium in headless mode (default ``True``). Tests and CI use
        the default; interactive debugging can set this to ``False``.
    navigate_wait_until:
        Playwright ``wait_until`` value for ``page.goto``. Defaults to
        ``"load"`` to match the legacy :class:`BrowserVerifier`.
    navigate_timeout_ms:
        Navigation timeout in milliseconds. Surfaced as :class:`BrowserError`.
    """

    def __init__(
        self,
        *,
        headless: bool = True,
        navigate_wait_until: str = _DEFAULT_WAIT_UNTIL,
        navigate_timeout_ms: int = _DEFAULT_NAVIGATE_TIMEOUT_MS,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._headless: bool = bool(headless)
        self._wait_until: str = str(navigate_wait_until)
        self._timeout_ms: int = int(navigate_timeout_ms)
        self._rate_limiter: RateLimiter = rate_limiter if rate_limiter is not None else RateLimiter(None)
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._closed: bool = False

    async def _ensure(self) -> None:
        if self._closed:
            raise BrowserError("PlaywrightBrowser is closed")
        if self._page is not None:
            return

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserError(
                "playwright is not installed; install the 'browser' extra"
            ) from exc

        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self._headless)
            self._context = await self._browser.new_context()
            await self._context.add_init_script(_INIT_SCRIPT)
            self._page = await self._context.new_page()
            self._page.on("dialog", self._on_dialog)
        except Exception as exc:
            # Partial startup — unwind whatever got created so a retry is clean.
            await self._teardown_quiet()
            raise BrowserError(f"playwright startup failed: {exc}") from exc

    def _on_dialog(self, dialog: Any) -> None:
        """Dismiss native dialogs that slip past the init-script override.

        The init script monkey-patches ``alert``/``confirm``/``prompt``
        before any page script runs, which covers the common XSS path.
        This handler exists only to keep Playwright from blocking if a
        real browser-level dialog manages to fire (e.g. ``beforeunload``)
        — without it Playwright suspends JS execution until dismissed.
        """
        try:
            dialog.dismiss()
        except Exception:  # LEGACY: dialog teardown is best-effort
            pass

    async def navigate(self, url: str) -> None:
        await self._ensure()
        try:
            async with self._rate_limiter.acquire(url):
                await self._page.goto(
                    url,
                    wait_until=self._wait_until,
                    timeout=self._timeout_ms,
                )
        except BrowserError:
            raise
        except Exception as exc:
            raise BrowserError(f"navigate failed: {exc}") from exc

    async def get_dom(self) -> str:
        await self._ensure()
        try:
            return await self._page.content()
        except Exception as exc:
            raise BrowserError(f"get_dom failed: {exc}") from exc

    async def eval_js(self, expr: str) -> Any:
        await self._ensure()
        try:
            return await self._page.evaluate(expr)
        except Exception as exc:
            raise BrowserError(f"eval_js failed: {exc}") from exc

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._teardown_quiet()

    async def _teardown_quiet(self) -> None:
        try:
            if self._context is not None:
                await self._context.close()
        except Exception:  # LEGACY: best-effort cleanup
            pass
        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception:  # LEGACY: best-effort cleanup
            pass
        try:
            if self._playwright is not None:
                await self._playwright.stop()
        except Exception:  # LEGACY: best-effort cleanup
            pass
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
