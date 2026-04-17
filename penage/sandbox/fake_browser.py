from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from penage.sandbox.browser_base import BrowserError


@dataclass
class FakeBrowser:
    """In-memory :class:`Browser` implementation for unit tests.

    Responses are programmable via ``dom_responses`` / ``js_responses``.
    Failures are injected via ``navigate_failures``. Every call is recorded
    so tests can assert on call order and counts. ``aclose`` is idempotent.
    """

    dom_responses: dict[str, str] = field(default_factory=dict)
    js_responses: dict[str, Any] = field(default_factory=dict)
    navigate_failures: set[str] = field(default_factory=set)

    navigations: list[str] = field(default_factory=list, init=False)
    js_calls: list[str] = field(default_factory=list, init=False)
    closed: bool = field(default=False, init=False)
    _current_url: str | None = field(default=None, init=False)

    async def navigate(self, url: str) -> None:
        self.navigations.append(url)
        if url in self.navigate_failures:
            raise BrowserError(f"fake_browser:navigate_failure:{url}")
        self._current_url = url

    async def get_dom(self) -> str:
        if self._current_url is None:
            return ""
        return self.dom_responses.get(self._current_url, "")

    async def eval_js(self, expr: str) -> Any:
        self.js_calls.append(expr)
        return self.js_responses.get(expr, None)

    async def aclose(self) -> None:
        self.closed = True
