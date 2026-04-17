"""Unit tests for :mod:`tests.support.dvwa_auth`.

Exercise the pure-function CSRF scraping path against hand-crafted HTML
fragments so we can guarantee the regex survives DVWA's double- vs
single-quoted markup without needing a live container.
"""
from __future__ import annotations

import pytest

from tests.support.dvwa_auth import extract_user_token


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
