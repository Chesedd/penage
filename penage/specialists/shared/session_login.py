from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Protocol
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import RoleSession

logger = logging.getLogger(__name__)

_LOGIN_PATH_HINTS = ("login", "signin", "sign-in", "auth")
_JOINED_COOKIE_SPLITTER = re.compile(r", (?=[A-Za-z0-9_!#$%&'*+\-.^`|~]+=)")


class _HttpBackend(Protocol):
    async def run(self, action: Action) -> Observation: ...


@dataclass(frozen=True, slots=True)
class LoginAttemptResult:
    """Structured outcome of a single login attempt.

    Always returned, even on failure, so callers can trace what happened.
    """

    session: RoleSession
    status_code: int | None
    response_url: str
    set_cookie_count: int
    failure_reason: str | None


async def login_role(
    *,
    http_tool: _HttpBackend,
    login_url: str,
    role_name: str,
    username: str,
    password: str,
    user_field: str = "username",
    pass_field: str = "password",
    extra_fields: dict[str, str] | None = None,
    timeout_s: float = 15.0,
    success_status_codes: tuple[int, ...] = (200, 302, 303),
    failure_body_markers: tuple[str, ...] = (
        "incorrect password",
        "invalid password",
        "invalid credentials",
        "login failed",
        "authentication failed",
        "wrong username",
        "unauthorized",
    ),
) -> LoginAttemptResult:
    """POST credentials to login_url, collect Set-Cookie, return RoleSession.

    Heuristic for success (all four must hold):
      1. HTTP status in success_status_codes.
      2. At least one Set-Cookie header present.
      3. Response body does not contain any marker from failure_body_markers
         (case-insensitive substring).
      4. If status 302/303 and Location is set, the redirect target does
         not look like another login page.

    The returned RoleSession is fully populated with role_name, username
    (never password), cookies parsed from Set-Cookie headers, established
    flag, last_login_ts, and login_error. Does not mutate any passed-in
    object and does not write to any registry.
    """
    form_data: dict[str, str] = {
        user_field: username,
        pass_field: password,
    }
    if extra_fields:
        for k, v in extra_fields.items():
            if k in (user_field, pass_field):
                continue
            form_data[k] = v

    action = Action(
        type=ActionType.HTTP,
        params={
            "method": "POST",
            "url": login_url,
            "data": form_data,
            "follow_redirects": False,
        },
        timeout_s=timeout_s,
        tags=["auth", "role_login", role_name],
    )

    session = RoleSession(role_name=role_name, username=username)
    session.last_login_ts = time.time()

    try:
        obs = await http_tool.run(action)
    except Exception as exc:  # LEGACY: HTTP boundary
        session.login_error = f"http_exception:{type(exc).__name__}"
        return LoginAttemptResult(
            session=session,
            status_code=None,
            response_url=login_url,
            set_cookie_count=0,
            failure_reason=session.login_error,
        )

    if not obs.ok or not isinstance(obs.data, dict):
        reason = f"http_not_ok:{obs.error or 'unknown'}"
        session.login_error = reason
        return LoginAttemptResult(
            session=session,
            status_code=None,
            response_url=login_url,
            set_cookie_count=0,
            failure_reason=reason,
        )

    data = obs.data
    status = data.get("status_code")
    headers = data.get("headers") or {}
    body = str(data.get("text_full") or data.get("text_excerpt") or "")
    response_url = str(data.get("url") or login_url)

    set_cookies_raw = _collect_set_cookie_headers(headers)
    parsed_cookies = _parse_set_cookies(set_cookies_raw)
    session.cookies = parsed_cookies

    status_int = status if isinstance(status, int) else 0
    failure_reason: str | None = None

    if status_int not in success_status_codes:
        failure_reason = f"status_not_in_success_set:{status_int}"

    if failure_reason is None and not parsed_cookies:
        failure_reason = "no_set_cookie"

    if failure_reason is None:
        low = body.lower()
        for marker in failure_body_markers:
            if marker in low:
                failure_reason = f"failure_marker:{marker}"
                break

    if failure_reason is None and status_int in (302, 303):
        location = _get_header(headers, "location")
        if location and _path_looks_like_login(location):
            failure_reason = "redirect_back_to_login"

    if failure_reason is None:
        session.established = True
    else:
        session.login_error = failure_reason

    return LoginAttemptResult(
        session=session,
        status_code=status_int or None,
        response_url=response_url,
        set_cookie_count=len(parsed_cookies),
        failure_reason=failure_reason,
    )


def _collect_set_cookie_headers(headers: object) -> list[str]:
    """Collect Set-Cookie values from a headers mapping.

    Response headers may be a normalised dict (one string per name) or a
    list of (name, value) tuples. httpx joins multiple Set-Cookie values
    with ", " which is ambiguous (commas also appear in Expires=); we
    split them back only when the next fragment looks like "name=value".
    """
    out: list[str] = []
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() != "set-cookie":
                continue
            if isinstance(v, (list, tuple)):
                out.extend(str(x) for x in v if x)
            else:
                s = str(v or "")
                if s:
                    out.extend(_split_joined_cookies(s))
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            name, val = item[0], item[1]
            if str(name).lower() == "set-cookie" and val:
                out.append(str(val))
    return out


def _split_joined_cookies(joined: str) -> list[str]:
    parts: list[str] = []
    for piece in _JOINED_COOKIE_SPLITTER.split(joined):
        piece = piece.strip()
        if piece:
            parts.append(piece)
    return parts


def _parse_set_cookies(raw: list[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for line in raw:
        if not line:
            continue
        try:
            jar = SimpleCookie()
            jar.load(line)
            for name, morsel in jar.items():
                cookies[name] = morsel.value
        except Exception as exc:
            logger.debug("cookie parse failed for %r: %s", line[:80], exc)
    return cookies


def _get_header(headers: object, name: str) -> str:
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == name.lower():
                return str(v or "")
    return ""


def _path_looks_like_login(url_or_path: str) -> bool:
    try:
        path = (urlparse(url_or_path).path or url_or_path).lower()
    except Exception:
        path = url_or_path.lower()
    return any(h in path for h in _LOGIN_PATH_HINTS)
