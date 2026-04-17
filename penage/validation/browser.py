from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.sandbox.browser_base import Browser, BrowserError
from penage.validation.base import ValidationResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 10.0
_DEFAULT_SCREENSHOT_DIR = Path("runs/screenshots")
_TIMEOUT_NOTE = "[penage] verification timed out"

_playwright_warning_emitted = False


def _emit_missing_playwright_warning(exc: ImportError) -> None:
    global _playwright_warning_emitted
    if _playwright_warning_emitted:
        return
    _playwright_warning_emitted = True
    logger.warning(
        "Playwright is not installed (%s); BrowserVerifier will return "
        "unavailable evidence. Install the 'browser' extra to enable browser verification.",
        exc,
    )


@dataclass(frozen=True, slots=True)
class BrowserEvidence:
    script_executed: bool
    dialog_triggered: bool
    dom_mutations: list[str] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    screenshot_path: Optional[Path] = None
    available: bool = True

    @classmethod
    def unavailable(cls) -> "BrowserEvidence":
        return cls(
            script_executed=False,
            dialog_triggered=False,
            dom_mutations=[],
            console_messages=[],
            screenshot_path=None,
            available=False,
        )


class BrowserVerifier:
    """Headless Chromium verifier for detecting JS-execution evidence.

    Uses Playwright's sync API. If Playwright is not importable, every call to
    :meth:`verify` returns :meth:`BrowserEvidence.unavailable` and a single
    warning is logged for the lifetime of the process.
    """

    def __init__(
        self,
        *,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        screenshot_dir: Path | str = _DEFAULT_SCREENSHOT_DIR,
    ) -> None:
        self._timeout_s = float(timeout_s)
        self._screenshot_dir = Path(screenshot_dir)

    def verify(self, url: str, payload: str, expectation: str) -> BrowserEvidence:
        """Render ``url`` in headless Chromium and collect execution evidence.

        The caller is responsible for embedding ``payload`` into the URL, body,
        or cookie jar before invoking this method. ``expectation`` is matched
        against console output to flag script execution and is also used in
        the screenshot filename for later correlation.
        """
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            _emit_missing_playwright_warning(exc)
            return BrowserEvidence.unavailable()

        _ = payload

        console_messages: list[str] = []
        dom_mutations: list[str] = []
        dialog_triggered = False
        timed_out = False
        screenshot_path: Optional[Path] = None
        deadline = time.monotonic() + self._timeout_s
        timeout_ms = max(1, int(self._timeout_s * 1000))

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    context = browser.new_context()
                    page = context.new_page()

                    def _on_console(msg: object) -> None:
                        try:
                            text = msg.text  # type: ignore[attr-defined]
                        except Exception:
                            text = str(msg)
                        console_messages.append(str(text))

                    def _on_dialog(dialog: object) -> None:
                        nonlocal dialog_triggered
                        dialog_triggered = True
                        try:
                            console_messages.append(f"[dialog] {dialog.message}")  # type: ignore[attr-defined]
                        except Exception:
                            pass
                        try:
                            dialog.dismiss()  # type: ignore[attr-defined]
                        except Exception:
                            pass

                    page.on("console", _on_console)
                    page.on("dialog", _on_dialog)

                    try:
                        page.goto(url, timeout=timeout_ms, wait_until="load")
                    except PlaywrightTimeoutError:
                        timed_out = True

                    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                    if remaining_ms > 0 and not timed_out:
                        try:
                            page.wait_for_load_state("networkidle", timeout=remaining_ms)
                        except PlaywrightTimeoutError:
                            timed_out = True
                        except PlaywrightError:
                            pass

                    try:
                        mutations = page.evaluate(
                            "() => Array.from(document.querySelectorAll('[data-penage-mutation]'))"
                            ".map(el => el.getAttribute('data-penage-mutation'))"
                        )
                        if isinstance(mutations, list):
                            dom_mutations = [str(m) for m in mutations if m is not None]
                    except PlaywrightTimeoutError:
                        timed_out = True
                    except PlaywrightError:
                        pass

                    shot = self._screenshot_path_for(expectation)
                    try:
                        shot.parent.mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=str(shot), full_page=True)
                        screenshot_path = shot
                    except (PlaywrightError, OSError):
                        screenshot_path = None
                finally:
                    try:
                        browser.close()
                    except PlaywrightError:
                        pass
        except PlaywrightError as exc:
            console_messages.append(f"[penage] playwright error: {exc}")

        if timed_out:
            console_messages.append(_TIMEOUT_NOTE)

        script_executed = (
            dialog_triggered
            or bool(dom_mutations)
            or (bool(expectation) and any(expectation in msg for msg in console_messages))
        )

        return BrowserEvidence(
            script_executed=script_executed,
            dialog_triggered=dialog_triggered,
            dom_mutations=list(dom_mutations),
            console_messages=list(console_messages),
            screenshot_path=screenshot_path,
            available=True,
        )

    def _screenshot_path_for(self, expectation: str) -> Path:
        token = uuid.uuid4().hex[:12]
        safe_exp = "".join(c if c.isalnum() else "_" for c in expectation)[:24] or "evidence"
        return self._screenshot_dir / f"{safe_exp}_{token}.png"


DEFAULT_EXECUTION_MARKERS: tuple[str, ...] = ("__penage_xss_marker__",)
DEFAULT_PROBE_EXPR: str = "window.__penage_xss_marker__ || ''"


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
    3. Evaluate ``probe_expr``. If its string form contains any configured
       ``execution_markers``, the finding is ``"validated"``; otherwise
       ``"evidence"`` (reflection present, execution unconfirmed).

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
        executed = any(marker in js_text for marker in self._execution_markers)

        evidence: dict[str, object] = {
            "url": url,
            "payload": payload,
            "probe_expr": self._probe_expr,
            "js_result": js_text,
            "action_type": action.type.value,
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
