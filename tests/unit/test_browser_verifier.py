from __future__ import annotations

import sys
import time
import types
from pathlib import Path

import pytest

from penage.validation import browser as browser_mod
from penage.validation.browser import BrowserEvidence, BrowserVerifier


def test_unavailable_evidence_has_empty_default_fields():
    evidence = BrowserEvidence.unavailable()

    assert evidence.available is False
    assert evidence.script_executed is False
    assert evidence.dialog_triggered is False
    assert evidence.dom_mutations == []
    assert evidence.console_messages == []
    assert evidence.screenshot_path is None


def test_verify_returns_unavailable_when_playwright_missing(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(browser_mod, "_playwright_warning_emitted", False)
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)

    verifier = BrowserVerifier(screenshot_dir=tmp_path)

    with caplog.at_level("WARNING", logger=browser_mod.logger.name):
        evidence = verifier.verify(
            "http://example.invalid/",
            payload="<script>alert(1)</script>",
            expectation="alert",
        )

    assert evidence == BrowserEvidence.unavailable()
    assert any("Playwright is not installed" in rec.message for rec in caplog.records)


def test_verify_warning_emitted_only_once(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(browser_mod, "_playwright_warning_emitted", False)
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)

    verifier = BrowserVerifier(screenshot_dir=tmp_path)

    with caplog.at_level("WARNING", logger=browser_mod.logger.name):
        verifier.verify("http://example.invalid/", payload="x", expectation="y")
        verifier.verify("http://example.invalid/", payload="x", expectation="y")

    warnings = [rec for rec in caplog.records if "Playwright is not installed" in rec.message]
    assert len(warnings) == 1


def _install_fake_playwright(monkeypatch, page_factory):
    """Install a synthetic playwright.sync_api module that yields ``page_factory()``."""

    class FakeError(Exception):
        pass

    class FakeTimeout(Exception):
        pass

    class FakeBrowser:
        def __init__(self, page):
            self._page = page
            self.closed = False

        def new_context(self):
            return FakeContext(self._page)

        def close(self):
            self.closed = True

    class FakeContext:
        def __init__(self, page):
            self._page = page

        def new_page(self):
            return self._page

    class FakeChromium:
        def __init__(self, page):
            self._page = page

        def launch(self, headless=True):
            assert headless is True
            return FakeBrowser(self._page)

    class FakePlaywright:
        def __init__(self, page):
            self.chromium = FakeChromium(page)

    class FakeSyncPlaywrightCM:
        def __init__(self, page):
            self._page = page

        def __enter__(self):
            return FakePlaywright(self._page)

        def __exit__(self, exc_type, exc, tb):
            return False

    def sync_playwright():
        return FakeSyncPlaywrightCM(page_factory(FakeTimeout, FakeError))

    fake_mod = types.ModuleType("playwright.sync_api")
    fake_mod.Error = FakeError
    fake_mod.TimeoutError = FakeTimeout
    fake_mod.sync_playwright = sync_playwright

    fake_pkg = types.ModuleType("playwright")
    fake_pkg.sync_api = fake_mod

    monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_mod)
    return FakeError, FakeTimeout


def test_verify_timeout_appends_timeout_note(monkeypatch, tmp_path):
    def make_page(FakeTimeout, FakeError):
        class SleepyPage:
            def __init__(self):
                self._handlers: dict[str, list] = {}

            def on(self, event, cb):
                self._handlers.setdefault(event, []).append(cb)

            def goto(self, url, timeout, wait_until):
                time.sleep(0.02)
                raise FakeTimeout(f"goto exceeded {timeout}ms for {url}")

            def wait_for_load_state(self, state, timeout):
                raise FakeTimeout("wait_for_load_state timed out")

            def evaluate(self, script):
                return []

            def screenshot(self, path, full_page=False):
                Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")

        return SleepyPage()

    _install_fake_playwright(monkeypatch, make_page)

    verifier = BrowserVerifier(timeout_s=0.01, screenshot_dir=tmp_path)
    evidence = verifier.verify(
        "http://example.invalid/",
        payload="<script>alert(1)</script>",
        expectation="alert",
    )

    assert evidence.available is True
    assert evidence.script_executed is False
    assert evidence.dialog_triggered is False
    assert evidence.dom_mutations == []
    assert any("timed out" in msg for msg in evidence.console_messages)
    assert browser_mod._TIMEOUT_NOTE in evidence.console_messages
    assert evidence.screenshot_path is not None
    assert evidence.screenshot_path.exists()
    assert evidence.screenshot_path.parent == tmp_path


@pytest.fixture(autouse=True)
def _reset_warning_flag():
    browser_mod._playwright_warning_emitted = False
    yield
    browser_mod._playwright_warning_emitted = False
