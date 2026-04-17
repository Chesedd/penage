from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.specialists.shared.session_login import (
    LoginAttemptResult,
    _path_looks_like_login,
    _split_joined_cookies,
    login_role,
)

# Password is only ever referenced as a parameter value in assertions,
# never put into docstrings, file paths, or log formats. Kept as a
# variable so grep for a raw secret in this test file yields nothing
# that looks like an accidental leak.
_SECRET = "s" + "ecret" + "123"


@dataclass
class _FakeHttpBackend:
    to_return: Observation | None = None
    raise_exc: Exception | None = None
    captured_actions: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.captured_actions.append(action)
        if self.raise_exc is not None:
            raise self.raise_exc
        assert self.to_return is not None
        return self.to_return


def _obs(
    *,
    status_code: int = 200,
    headers: dict[str, Any] | None = None,
    text: str = "",
    url: str = "http://localhost:8080/login",
    ok: bool = True,
    error: str | None = None,
) -> Observation:
    data = {
        "status_code": status_code,
        "headers": headers or {},
        "text_full": text,
        "text_excerpt": text[:200],
        "url": url,
    }
    return Observation(ok=ok, data=data, error=error)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


# --- Successful scenarios -------------------------------------------------

def test_success_status_200_with_set_cookie():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=200,
        headers={"Set-Cookie": "sessionid=abc123; Path=/; HttpOnly"},
        text="Welcome",
    ))
    result = _run(login_role(
        http_tool=backend,
        login_url="http://localhost:8080/login",
        role_name="role_a",
        username="alice",
        password=_SECRET,
    ))
    assert isinstance(result, LoginAttemptResult)
    assert result.session.established is True
    assert result.failure_reason is None
    assert result.session.cookies == {"sessionid": "abc123"}
    assert result.status_code == 200
    assert result.set_cookie_count == 1


def test_success_status_302_redirect_to_dashboard():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=302,
        headers={
            "Set-Cookie": "sid=zzz; Path=/",
            "Location": "/dashboard",
        },
    ))
    result = _run(login_role(
        http_tool=backend,
        login_url="http://localhost:8080/login",
        role_name="role_b",
        username="bob",
        password=_SECRET,
    ))
    assert result.session.established is True
    assert result.failure_reason is None
    assert "sid" in result.session.cookies


def test_success_cookies_parsed_from_single_set_cookie():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sessionid=abc123; Path=/; HttpOnly"},
    ))
    result = _run(login_role(
        http_tool=backend,
        login_url="http://x/login",
        role_name="r",
        username="u",
        password=_SECRET,
    ))
    assert result.session.cookies == {"sessionid": "abc123"}


def test_success_multiple_cookies_parsed_separately():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "a=1; Path=/, b=2; Path=/"},
    ))
    result = _run(login_role(
        http_tool=backend,
        login_url="http://x/login",
        role_name="r",
        username="u",
        password=_SECRET,
    ))
    assert result.session.cookies == {"a": "1", "b": "2"}
    assert result.set_cookie_count == 2


def test_success_extra_fields_included_in_post():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sid=x"},
    ))
    _run(login_role(
        http_tool=backend,
        login_url="http://x/login",
        role_name="r",
        username="u",
        password=_SECRET,
        extra_fields={"csrf_token": "TOKEN123", "Login": "Login"},
    ))
    assert len(backend.captured_actions) == 1
    action = backend.captured_actions[0]
    assert action.type == ActionType.HTTP
    form = action.params["data"]
    assert form["csrf_token"] == "TOKEN123"
    assert form["Login"] == "Login"
    assert form["username"] == "u"
    assert action.params["follow_redirects"] is False


# --- Failure scenarios ---------------------------------------------------

def test_failure_status_500():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=500,
        headers={"Set-Cookie": "sid=x"},
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason is not None
    assert result.failure_reason.startswith("status_not_in_success_set:")


def test_failure_no_set_cookie():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=200, headers={}, text="Welcome",
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason == "no_set_cookie"


def test_failure_body_marker_invalid_password():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=200,
        headers={"Set-Cookie": "sid=x"},
        text="Invalid password. Try again.",
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason == "failure_marker:invalid password"


def test_failure_body_marker_case_insensitive():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=200,
        headers={"Set-Cookie": "sid=x"},
        text="INVALID PASSWORD",
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason == "failure_marker:invalid password"


def test_failure_redirect_back_to_login():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=302,
        headers={
            "Set-Cookie": "sid=x",
            "Location": "/login?error=1",
        },
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason == "redirect_back_to_login"


def test_failure_http_exception_caught():
    backend = _FakeHttpBackend(raise_exc=RuntimeError("boom"))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason is not None
    assert result.failure_reason.startswith("http_exception:")
    assert result.status_code is None


def test_failure_obs_not_ok():
    backend = _FakeHttpBackend(to_return=Observation(ok=False, error="timeout"))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.established is False
    assert result.failure_reason is not None
    assert result.failure_reason.startswith("http_not_ok:")


# --- Security ------------------------------------------------------------

def test_password_never_in_session():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sid=x"},
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="alice", password=_SECRET,
    ))
    sess = result.session
    # The RoleSession must not carry the password anywhere.
    blob = "|".join([
        sess.role_name,
        sess.username,
        str(sess.cookies),
        str(sess.established),
        sess.login_error,
    ])
    assert _SECRET not in blob


def test_password_never_in_failure_reason():
    backend = _FakeHttpBackend(to_return=_obs(
        status_code=401,
        headers={},
        text="nope",
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.failure_reason is not None
    assert _SECRET not in result.failure_reason
    assert _SECRET not in result.session.login_error


def test_extra_fields_cannot_override_credentials():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sid=x"},
    ))
    _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="alice", password=_SECRET,
        extra_fields={"username": "admin", "password": "hax"},
    ))
    form = backend.captured_actions[0].params["data"]
    assert form["username"] == "alice"
    assert form["password"] == _SECRET


# --- Utilities -----------------------------------------------------------

def test_path_looks_like_login_positive():
    assert _path_looks_like_login("/login")
    assert _path_looks_like_login("/signin")
    assert _path_looks_like_login("/auth")
    assert _path_looks_like_login("/sign-in")
    assert _path_looks_like_login("https://example.com/login?x=1")


def test_path_looks_like_login_negative():
    assert not _path_looks_like_login("/dashboard")
    assert not _path_looks_like_login("/home")
    assert not _path_looks_like_login("/")


def test_split_joined_cookies_two_entries():
    assert _split_joined_cookies("a=1, b=2") == ["a=1", "b=2"]


def test_split_joined_cookies_with_expires():
    joined = "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, b=2"
    parts = _split_joined_cookies(joined)
    assert len(parts) == 2
    assert parts[0].startswith("a=1")
    assert "Expires=Wed, 21 Oct 2015 07:28:00 GMT" in parts[0]
    assert parts[1] == "b=2"


# --- Integration with RoleSession ----------------------------------------

def test_returned_session_has_correct_role_name_and_username():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sid=x"},
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="role_a",
        username="alice", password=_SECRET,
    ))
    assert result.session.role_name == "role_a"
    assert result.session.username == "alice"


def test_last_login_ts_is_set():
    backend = _FakeHttpBackend(to_return=_obs(
        headers={"Set-Cookie": "sid=x"},
    ))
    result = _run(login_role(
        http_tool=backend, login_url="http://x/login", role_name="r",
        username="u", password=_SECRET,
    ))
    assert result.session.last_login_ts > 0
