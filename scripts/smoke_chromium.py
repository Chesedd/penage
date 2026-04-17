#!/usr/bin/env python3
"""Standalone chromium smoke — run directly, NOT via pytest.

Verifies that ``playwright.async_api.async_playwright`` can launch a
headless chromium in the current environment. Stage 4.4.α uses this as a
"does the box have a usable browser?" probe before the DVWA E2E fixtures
land in 4.4.β. It intentionally does not import anything from ``penage``
to keep the check isolated from project configuration.

Exit codes:
    0 — ``CHROMIUM_SMOKE_OK`` printed to stdout.
    1 — startup failed; the exception is printed to stderr prefixed with
        ``CHROMIUM_SMOKE_FAIL``.

Usage:
    python scripts/smoke_chromium.py
"""

from __future__ import annotations

import asyncio
import sys
import traceback


async def main() -> int:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        print(f"CHROMIUM_SMOKE_FAIL import_error: {exc}", file=sys.stderr)
        print("hint: pip install 'playwright>=1.40,<2.0'", file=sys.stderr)
        return 1

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                page = await browser.new_page()
                await page.goto("about:blank")
                title = await page.title()
                print(f"CHROMIUM_SMOKE_OK title={title!r}")
            finally:
                await browser.close()
    except Exception as exc:
        print(f"CHROMIUM_SMOKE_FAIL startup_error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
