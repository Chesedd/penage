"""Deterministic test doubles for the XSS specialist pipeline.

Extracted from ``tests/unit/test_xss_specialist.py`` so multiple test
modules (unit + golden-trace integration) can share the same fakes
without creating cross-test-dir imports.

The implementations are kept intentionally minimal:

* :class:`FakeHttp` wraps a pure responder callable, records calls, and
  ignores ``aclose``.
* :func:`vulnerable_echo` responds with the probed parameter reflected
  verbatim inside an HTML ``value="..."`` attribute (attr_quoted context).
* :func:`noop_responder` returns fixed HTML with no reflection, driving
  the ``not_reflected`` path in :class:`ReflectionAnalyzer`.
* :class:`PayloadEchoBrowser` / :class:`PayloadAwareBrowserValidator`
  solve the "payload unknown in advance" problem: they prime the fake
  browser's DOM with whatever ``browser_payload`` the specialist chose,
  so the DOM-reflection gate in
  :class:`~penage.validation.browser.BrowserEvidenceValidator` always
  matches without needing a URL-indexed lookup.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.sandbox.browser_base import Browser
from penage.validation.browser import BrowserEvidenceValidator

Responder = Callable[[Action], Observation]


@dataclass
class FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


def _reflected_param_value(action: Action, parameter: str) -> str:
    params = action.params
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def vulnerable_echo(parameter: str) -> Responder:
    """Echo the probed parameter inside an attribute position (attr_quoted)."""

    def respond(action: Action) -> Observation:
        injected = _reflected_param_value(action, parameter)
        body = (
            "<html><body><form method=\"POST\" action=\"/search\">"
            f"<input type=\"text\" name=\"{parameter}\" value=\"{injected}\" />"
            "</form></body></html>"
        )
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

    return respond


def noop_responder() -> Responder:
    """Fixed HTML response without any reflection of the probed value."""

    def respond(action: Action) -> Observation:
        body = "<html><body><p>nothing to see here</p></body></html>"
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

    return respond


class PayloadEchoBrowser:
    """Fake :class:`~penage.sandbox.browser_base.Browser` that echoes the
    current payload in the DOM."""

    def __init__(self, *, executed: bool) -> None:
        self._executed = executed
        self._current_payload: str = ""
        self._current_url: str | None = None
        self.navigations: list[str] = []
        self.js_calls: list[str] = []
        self.closed = False

    async def navigate(self, url: str) -> None:
        self.navigations.append(url)
        self._current_url = url

    async def get_dom(self) -> str:
        return f"<html><body>{self._current_payload}</body></html>"

    async def eval_js(self, expr: str) -> Any:
        self.js_calls.append(expr)
        if self._executed:
            return json.dumps([{"type": "alert", "message": "xss"}])
        return "[]"

    async def aclose(self) -> None:
        self.closed = True


class PayloadAwareBrowserValidator(BrowserEvidenceValidator):
    """Primes the fake browser's "current payload" before delegating to
    :class:`BrowserEvidenceValidator`."""

    def __init__(self, browser: PayloadEchoBrowser) -> None:
        super().__init__(browser)  # type: ignore[arg-type]
        self._echo = browser

    async def validate(self, *, action: Action, obs: Observation, state: State):
        self._echo._current_payload = str(
            (action.params or {}).get("browser_payload") or ""
        )
        return await super().validate(action=action, obs=obs, state=state)


def state_with_form(base_url: str, parameter: str) -> State:
    st = State(base_url=base_url)
    st.last_http_url = base_url
    st.forms_by_url = {
        base_url: [
            {
                "action": base_url,
                "method": "POST",
                "inputs": [{"name": parameter, "type": "text"}],
            }
        ]
    }
    return st


__all__ = [
    "Browser",
    "FakeHttp",
    "PayloadAwareBrowserValidator",
    "PayloadEchoBrowser",
    "Responder",
    "noop_responder",
    "state_with_form",
    "vulnerable_echo",
]
