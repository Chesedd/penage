"""Unit tests for :mod:`tests.support.dvwa_auth`.

Exercise the pure-function CSRF scraping path against hand-crafted HTML
fragments so we can guarantee the regex survives DVWA's double- vs
single-quoted markup without needing a live container.

The :func:`authenticate` flow is exercised against a stub
:class:`httpx.MockTransport` that returns the same token-bearing HTML
for every GET and records the form-encoded body of the POST to
``/security.php`` so we can assert which ``security`` level was sent.
"""
from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from tests.support import dvwa_auth
from tests.support.dvwa_auth import authenticate, extract_user_token


def test_extract_user_token_parses_double_quoted_form() -> None:
    html = (
        "<form action='/login.php' method='post'>"
        '<input type="hidden" name="user_token" value="abc123" />'
        "</form>"
    )
    assert extract_user_token(html) == "abc123"


def test_extract_user_token_handles_single_quotes() -> None:
    html = (
        "<form action='/login.php' method='post'>"
        "<input type='hidden' name='user_token' value='xyz789' />"
        "</form>"
    )
    assert extract_user_token(html) == "xyz789"


def test_extract_user_token_is_case_insensitive() -> None:
    html = '<INPUT NAME="user_token" VALUE="CASE42" />'
    assert extract_user_token(html) == "CASE42"


def test_extract_user_token_raises_when_missing() -> None:
    html = "<html><body>no forms here</body></html>"
    with pytest.raises(ValueError, match="user_token"):
        extract_user_token(html)


def test_extract_user_token_picks_first_match() -> None:
    html = (
        '<input name="user_token" value="first" />'
        '<input name="user_token" value="second" />'
    )
    assert extract_user_token(html) == "first"


def _install_dvwa_stub_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    """Patch ``httpx.AsyncClient`` inside dvwa_auth with a MockTransport.

    Returns a list that captures the ``security`` value sent in the form
    body of every POST to ``/security.php``.
    """
    posted_security: list[str] = []
    token_html = '<input type="hidden" name="user_token" value="tok123" />'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/security.php":
            data = parse_qs(request.content.decode("utf-8"))
            posted_security.extend(data.get("security", []))
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=f"<html><body>{token_html}</body></html>",
        )

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(dvwa_auth.httpx, "AsyncClient", fake_async_client)
    return posted_security


@pytest.mark.asyncio
async def test_authenticate_defaults_to_low_security(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted_security = _install_dvwa_stub_transport(monkeypatch)

    await authenticate("http://dvwa.test")

    assert posted_security == ["low"]


@pytest.mark.asyncio
async def test_authenticate_with_medium_security_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted_security = _install_dvwa_stub_transport(monkeypatch)

    await authenticate("http://dvwa.test", security_level="medium")

    assert posted_security == ["medium"]
