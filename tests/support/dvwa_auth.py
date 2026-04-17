"""DVWA auth helpers. Pure functions + httpx-based login flow.

The public API is:

* :func:`extract_user_token` — scrape the ``user_token`` CSRF value from a
  DVWA form page (pure string-in/string-out, unit-testable without DVWA);
* :func:`is_dvwa_healthy` — cheap reachability probe used by the E2E
  fixture to decide whether to skip the suite;
* :func:`authenticate` — walk the login → setup → security-level flow and
  return a :class:`DvwaSession` carrying the authenticated cookies.

The flow is plain HTTP forms — no JavaScript, no browser. It is explicitly
not driven through :class:`penage.sandbox.playwright_browser.PlaywrightBrowser`
because the E2E suite's interesting work (the actual XSS episode) is what
we want to spend browser cycles on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx


_USER_TOKEN_RE = re.compile(
    r"<input[^>]*name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def extract_user_token(html: str) -> str:
    """Return the ``user_token`` value from a DVWA form page.

    Raises :class:`ValueError` if no ``user_token`` input is present —
    that almost always means we were redirected to ``/login.php`` by an
    expired session or that the markup changed upstream.
    """
    match = _USER_TOKEN_RE.search(html)
    if not match:
        raise ValueError("user_token not found in HTML")
    return match.group(1)


@dataclass(frozen=True)
class DvwaSession:
    """Authenticated DVWA session handle returned by :func:`authenticate`."""

    base_url: str
    cookies: dict[str, str]


async def is_dvwa_healthy(base_url: str, *, timeout: float = 2.0) -> bool:
    """Return ``True`` iff ``GET /login.php`` at ``base_url`` looks like DVWA."""
    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
            resp = await client.get("/login.php")
            return resp.status_code == 200 and "DVWA" in resp.text
    except (httpx.RequestError, httpx.TimeoutException):
        return False


async def authenticate(
    base_url: str,
    username: str = "admin",
    password: str = "password",
    *,
    timeout: float = 10.0,
) -> DvwaSession:
    """Log into DVWA, ensure the DB is seeded, and force security ``low``.

    Returns a :class:`DvwaSession` with the authenticated cookie jar
    (typically ``PHPSESSID`` and — on newer DVWA builds —
    ``security`` / ``dvwa-security-level-cookie``).

    The function is idempotent against a warm DVWA instance: re-running
    ``create_db`` just resets the DB, and resetting security to ``low``
    is the baseline for all β-scope scenarios.
    """
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        # 1. Scrape the login-page token.
        resp = await client.get("/login.php")
        token = extract_user_token(resp.text)

        # 2. POST credentials.
        await client.post(
            "/login.php",
            data={
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": token,
            },
        )

        # 3. Scrape the setup-page token (the DB may or may not exist yet).
        resp = await client.get("/setup.php")
        token = extract_user_token(resp.text)

        # 4. (Re)create the DB so scenarios start from a clean baseline.
        await client.post(
            "/setup.php",
            data={
                "create_db": "Create / Reset Database",
                "user_token": token,
            },
        )

        # 5. Scrape the security-page token, force level ``low``.
        resp = await client.get("/security.php")
        token = extract_user_token(resp.text)
        await client.post(
            "/security.php",
            data={
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": token,
            },
        )

        return DvwaSession(base_url=base_url, cookies=dict(client.cookies))
