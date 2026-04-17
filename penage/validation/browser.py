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
DEFAULT_PROBE_EXPR: str = "window.__penage_xss_marker__ || ''"
MARKERS_JSON_EXPR: str = "JSON.stringify(window.__penage_xss_marker__ || [])"

_DOM_FRAGMENT_CONTEXT: int = 120


def _extract_dom_fragment(dom: str, payload: str, *, context: int = _DOM_FRAGMENT_CONTEXT) -> str:
    if not dom or not payload:
        return ""
    idx = dom.find(payload)
    if idx < 0:
        return ""
    start = max(0, idx - context)
    end = min(len(dom), idx + len(payload) + context)
    return dom[start:end]


def _parse_markers(raw: Any) -> list[dict[str, Any]]:
    """Parse the JSON-stringified marker array into a list of dicts.

    The ``MARKERS_JSON_EXPR`` probe is expected to return a JSON-encoded
    string so the array survives Playwright's JS↔Python bridge intact. Any
    parse failure or non-list shape degrades to an empty list — the result
    is consumed only as evidence and as an executed-signal, both of which
    are safe under an empty default.
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [m for m in raw if isinstance(m, dict)]
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8", errors="replace")
        except Exception:  # LEGACY: bytes decode boundary
            return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except Exception:  # LEGACY: JSON parse boundary
            return []
        if isinstance(parsed, list):
            return [m for m in parsed if isinstance(m, dict)]
    return []


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
       is not reflected, return ``None`` without evaluating JS — no
       reflection implies no execution, and this saves a round-trip when
       the browser is rate-limited.
    3. Evaluate the configured ``probe_expr`` (legacy substring mode) AND
       ``MARKERS_JSON_EXPR`` (structured mode). Execution is detected when
       the configured ``execution_markers`` substring-match the probe
       result, or when the JSON marker array is non-empty. The extra
       call is also how we surface dialog records (``alert``/``confirm``/
       ``prompt`` calls) as ``execution_markers`` in the evidence dict.

    Evidence dict shape:

    * ``url`` — navigated URL.
    * ``payload`` — the string that was required to appear in the DOM.
    * ``probe_expr`` — the configured JS probe expression.
    * ``js_result`` — string form of the probe's return value.
    * ``action_type`` — the originating action's type (e.g. ``"http"``).
    * ``reflection_dom_fragment`` — ±120 chars of DOM around the first
      payload occurrence (empty string if the DOM bridge failed before the
      reflection check).
    * ``execution_markers`` — list of ``{"type": ..., "message": ...}``
      records captured by the init-script's dialog monkey-patches. Empty
      when no dialog fired (or when the secondary probe is unavailable).

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

        dom_fragment = _extract_dom_fragment(dom or "", payload)

        try:
            js_result = await self._browser.eval_js(self._probe_expr)
        except BrowserError as exc:
            logger.debug("browser validator: eval_js failed for %s: %s", url, exc)
            js_result = None

        js_text = str(js_result) if js_result is not None else ""

        try:
            markers_raw = await self._browser.eval_js(MARKERS_JSON_EXPR)
        except BrowserError as exc:
            logger.debug("browser validator: markers eval failed for %s: %s", url, exc)
            markers_raw = None

        execution_markers = _parse_markers(markers_raw)

        executed = (
            any(marker in js_text for marker in self._execution_markers)
            or bool(execution_markers)
        )

        evidence: dict[str, object] = {
            "url": url,
            "payload": payload,
            "probe_expr": self._probe_expr,
            "js_result": js_text,
            "action_type": action.type.value,
            "reflection_dom_fragment": dom_fragment,
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
