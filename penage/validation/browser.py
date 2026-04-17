from __future__ import annotations

import json
import logging
from typing import Any, Optional

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.sandbox.browser_base import Browser, BrowserError
from penage.validation.base import ValidationResult

logger = logging.getLogger(__name__)


DEFAULT_EXECUTION_MARKERS: tuple[str, ...] = ("__penage_xss_marker__",)
DEFAULT_PROBE_EXPR: str = "JSON.stringify(window.__penage_xss_marker__ || [])"

_DOM_FRAGMENT_WINDOW: int = 160
_DOM_FRAGMENT_CAP: int = 512


def _dom_fragment_near(dom: str, payload: str, *, window: int = _DOM_FRAGMENT_WINDOW) -> str:
    """Return a short substring of ``dom`` centred on the first ``payload`` hit.

    Used to give the finding enough context to show where the payload landed
    without dragging the full rendered document into the trace.
    """
    if not dom or not payload:
        return ""
    idx = dom.find(payload)
    if idx < 0:
        return ""
    start = max(0, idx - window)
    end = min(len(dom), idx + len(payload) + window)
    return dom[start:end][:_DOM_FRAGMENT_CAP]


def _parse_execution_markers(js_text: str) -> list[dict[str, Any]]:
    """Parse the probe result as a JSON array of ``{type, message}`` records.

    The :class:`penage.sandbox.playwright_browser.PlaywrightBrowser` init
    script pushes dicts onto ``window.__penage_xss_marker__`` whenever a
    payload triggers ``alert``/``confirm``/``prompt``. The default probe
    serialises that array via ``JSON.stringify`` so we can read structured
    records out of the evidence. Non-JSON / non-list results degrade to an
    empty list.
    """
    if not js_text:
        return []
    try:
        parsed = json.loads(js_text)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    out: list[dict[str, Any]] = []
    for item in parsed:
        if isinstance(item, dict):
            out.append({str(k): v for k, v in item.items()})
    return out


class BrowserEvidenceValidator:
    """Evidence validator that classifies browser-relevant actions.

    Mirrors :class:`penage.validation.http.HttpEvidenceValidator` in shape
    (same keyword-only ``validate`` signature, same ``Optional[ValidationResult]``
    return) but is implemented async because the underlying
    :class:`penage.sandbox.browser_base.Browser` Protocol exposes async I/O.

    Convention: ``Action`` has no dedicated ``metadata`` field in this repo;
    this validator uses ``action.params``. A caller marks an action as a
    browser-validation target by setting:

    * ``action.params["browser_target"] = True``
    * ``action.params["url"]`` — URL to navigate.
    * ``action.params["browser_payload"]`` — string that must appear in the
      rendered DOM for reflection to count.

    If any of these are missing, :meth:`validate` returns ``None`` (the
    same sentinel ``HttpEvidenceValidator`` uses for "not mine").

    Classification:

    1. Navigate. Any :class:`BrowserError` → ``None`` (quiet degradation so
       the gate cascade can continue; browser is an external dependency).
    2. Compare ``browser_payload`` against the rendered DOM. If the payload
       is not reflected, return ``None`` without calling ``eval_js`` — no
       reflection implies no execution, and this saves a round-trip when
       the browser is rate-limited.
    3. Evaluate ``probe_expr`` and parse the result as a JSON list of
       ``{type, message}`` dialog records (matching the init script in
       :class:`penage.sandbox.playwright_browser.PlaywrightBrowser`). A
       non-empty list means the payload invoked ``alert``/``confirm``/
       ``prompt`` and the finding is ``"validated"``. If the list is empty
       but the raw probe text contains any configured ``execution_markers``
       (used by non-default probe expressions), that also counts as
       ``"validated"``. Otherwise the result is ``"evidence"`` (reflection
       present, execution unconfirmed).

    Evidence dict fields:

    * ``url``, ``payload``, ``probe_expr``, ``js_result``, ``action_type``.
    * ``reflection_dom_fragment`` — up to a few hundred chars of the rendered
      DOM around the payload hit, so consumers can show *where* it landed.
    * ``execution_markers`` — parsed dialog records from
      ``window.__penage_xss_marker__`` (empty list if nothing executed).

    The validator never imports Playwright/Selenium/etc.: it accepts any
    object implementing the :class:`Browser` Protocol.
    """

    def __init__(
        self,
        browser: Browser,
        execution_markers: tuple[str, ...] = DEFAULT_EXECUTION_MARKERS,
        probe_expr: str = DEFAULT_PROBE_EXPR,
    ) -> None:
        self._browser = browser
        self._execution_markers: tuple[str, ...] = tuple(execution_markers)
        self._probe_expr: str = probe_expr

    async def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
    ) -> Optional[ValidationResult]:
        _ = (obs, state)

        params = action.params or {}
        if not params.get("browser_target"):
            return None

        url = str(params.get("url") or "")
        payload = str(params.get("browser_payload") or "")
        if not url or not payload:
            return None

        try:
            await self._browser.navigate(url)
        except BrowserError as exc:
            logger.debug("browser validator: navigate failed for %s: %s", url, exc)
            return None

        try:
            dom = await self._browser.get_dom()
        except BrowserError as exc:
            logger.debug("browser validator: get_dom failed for %s: %s", url, exc)
            return None

        if payload not in (dom or ""):
            return None

        try:
            js_result = await self._browser.eval_js(self._probe_expr)
        except BrowserError as exc:
            logger.debug("browser validator: eval_js failed for %s: %s", url, exc)
            js_result = None

        js_text = str(js_result) if js_result is not None else ""
        execution_markers = _parse_execution_markers(js_text)

        executed = bool(execution_markers) or any(
            marker in js_text for marker in self._execution_markers
        )

        evidence: dict[str, object] = {
            "url": url,
            "payload": payload,
            "probe_expr": self._probe_expr,
            "js_result": js_text,
            "action_type": action.type.value,
            "reflection_dom_fragment": _dom_fragment_near(dom or "", payload),
            "execution_markers": execution_markers,
        }

        if executed:
            return ValidationResult(
                level="validated",
                kind="xss_browser_execution",
                summary="Browser confirmed payload execution via JS probe marker.",
                evidence=evidence,
            )

        return ValidationResult(
            level="evidence",
            kind="xss_browser_reflection",
            summary="Payload reflected in rendered DOM; execution not confirmed.",
            evidence=evidence,
        )
