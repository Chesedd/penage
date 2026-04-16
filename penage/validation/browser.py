from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
