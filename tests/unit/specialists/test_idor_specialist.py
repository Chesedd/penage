from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.core.state import RoleSession
from penage.specialists.shared.session_login import LoginAttemptResult
from penage.specialists.vulns.idor import IdorSpecialist, _IdorTarget


Responder = Callable[[Action], Observation]


@dataclass
class FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


def _noop(action: Action) -> Observation:
    return Observation(ok=True, elapsed_ms=1, data={"status_code": 200, "text_full": ""})


@pytest.mark.asyncio
async def test_no_candidate_targets_returns_empty():
    specialist = IdorSpecialist(http_tool=FakeHttp(_noop))
    state = State(base_url="http://localhost")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_missing_http_tool_returns_empty():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/r?id=42"
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


def test_query_param_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users?id=42"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "query"
    assert t.id_param == "id"
    assert t.id_value == "42"
    assert t.is_numeric is True
    assert t.channel == "GET"


def test_query_param_user_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?user_id=42"
    targets = specialist._discover_targets(state)
    names = {t.id_param for t in targets}
    assert "user_id" in names


def test_query_param_non_hint_name_not_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?page=42"
    targets = specialist._discover_targets(state)
    assert targets == []


def test_path_numeric_segment_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users/42"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.path_segment_index == 1
    assert t.is_numeric is True
    assert t.id_value == "42"


def test_path_uuid_segment_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    state.last_http_url = f"http://x/doc/{uuid}"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.id_value == uuid
    assert t.is_numeric is False


def test_path_prefixed_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/o/ord_ABCD1234"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.id_value == "ord_ABCD1234"
    assert t.is_numeric is False


def test_path_non_id_segment_ignored():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users/profile"
    targets = specialist._discover_targets(state)
    assert targets == []


def test_form_hidden_order_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/cart": [
            {
                "action": "http://x/checkout",
                "method": "POST",
                "inputs": [
                    {"name": "order_id", "type": "hidden", "value": "123"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "form"
    assert t.id_param == "order_id"
    assert t.id_value == "123"
    assert t.channel == "POST"
    assert t.is_numeric is True


def test_form_visible_user_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/page": [
            {
                "action": "http://x/submit",
                "method": "POST",
                "inputs": [
                    {"name": "user_id", "type": "text", "value": "7"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "form"
    assert t.id_param == "user_id"
    assert t.is_numeric is True


def test_form_password_input_skipped():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/page": [
            {
                "action": "http://x/submit",
                "method": "POST",
                "inputs": [
                    {"name": "user_id", "type": "password", "value": "1"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert targets == []


def test_dedup_across_recent_http_memory_and_last_url():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?id=42"
    state.recent_http_memory = [{"url": "http://x/r?id=42"}]
    targets = specialist._discover_targets(state)
    query_targets = [t for t in targets if t.id_location == "query"]
    assert len(query_targets) == 1


def test_max_targets_respected():
    specialist = IdorSpecialist(http_tool=None, max_targets=3)
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {"url": f"http://x/r{i}?id={i}"} for i in range(10)
    ]
    targets = specialist._discover_targets(state)
    assert len(targets) == 3


@pytest.mark.asyncio
async def test_passwords_not_written_to_state():
    secret = "secret_role_a_pw_9371"
    secret_b = "secret_role_b_pw_4820"
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        role_a_password=secret,
        role_b_password=secret_b,
    )
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?id=1"
    await specialist.propose_async(state, config=SpecialistConfig())
    serialized = repr(state)
    assert secret not in serialized
    assert secret_b not in serialized


# ---------------------------------------------------------------------------
# Phase 0 (login)
# ---------------------------------------------------------------------------


class FakeTracer:
    """Minimal tracer that records all notes and events."""

    def __init__(self, episode_id: str = "ep-test") -> None:
        self.episode_id = episode_id
        self.notes: list[str] = []
        self.events: list[tuple[str, dict]] = []

    def record_note(self, text: str) -> None:
        self.notes.append(text)

    def write_event(self, name: str, payload: dict) -> None:
        self.events.append((name, dict(payload)))


def _seed_role(state: State, role_name: str, username: str, *, established: bool = False,
               cookies: dict[str, str] | None = None) -> None:
    state.auth_roles.upsert(
        RoleSession(
            role_name=role_name,
            username=username,
            cookies=dict(cookies or {}),
            established=established,
        )
    )


async def _call_login_phase(specialist: IdorSpecialist, state: State,
                            http_tool) -> dict[str, bool]:
    from penage.specialists.vulns.idor import _BudgetedHttpTool

    budgeted = _BudgetedHttpTool(http_tool, state, cap=specialist.max_http_budget)
    return await specialist._run_login_phase(state=state, http_tool=budgeted, step=0)


@pytest.mark.asyncio
async def test_no_credentials_skips_login():
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="",
        role_b_password="",
    )
    state = State(base_url="http://x")
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": False, "B": False}
    assert "idor:no_role_credentials_configured" in tracer.notes


@pytest.mark.asyncio
async def test_no_login_url_note():
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.forms_by_url = {
        "http://x/page": [
            {"action": "http://x/submit", "method": "POST",
             "inputs": [{"name": "user_id", "type": "text", "value": "1"}]}
        ]
    }
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": False, "B": False}
    assert "idor:no_login_url" in tracer.notes


@pytest.mark.asyncio
async def test_login_url_from_registry_used(monkeypatch):
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    seen_urls: list[str] = []

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        seen_urls.append(login_url)
        sess = RoleSession(
            role_name=role_name, username=username,
            cookies={"sid": f"{role_name}-cookie"}, established=True,
        )
        return LoginAttemptResult(
            session=sess, status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": True, "B": True}
    assert seen_urls == ["http://x/login", "http://x/login"]


@pytest.mark.asyncio
async def test_login_url_auto_discovered_from_forms_by_url(monkeypatch):
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.forms_by_url = {
        "http://x/login-page": [
            {
                "action": "http://x/do-login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
            }
        ]
    }
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    seen_urls: list[str] = []

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        seen_urls.append(login_url)
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": "c"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": True, "B": True}
    assert all(u == "http://x/do-login" for u in seen_urls)


@pytest.mark.asyncio
async def test_role_login_ok_updates_registry(monkeypatch):
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=FakeTracer(),
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": f"cookie-{role_name}"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": True, "B": True}
    sess_a = state.auth_roles.get("A")
    sess_b = state.auth_roles.get("B")
    assert sess_a is not None and sess_a.established is True
    assert sess_a.cookies == {"sid": "cookie-A"}
    assert sess_b is not None and sess_b.established is True
    assert sess_b.cookies == {"sid": "cookie-B"}


@pytest.mark.asyncio
async def test_role_login_failed_keeps_established_false(monkeypatch):
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={}, established=False,
                login_error="no_set_cookie",
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=0, failure_reason="no_set_cookie",
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": False, "B": False}
    assert any(n.startswith("idor:login_failed role=A") for n in tracer.notes)
    assert any(n.startswith("idor:login_failed role=B") for n in tracer.notes)


@pytest.mark.asyncio
async def test_already_established_role_not_re_logged(monkeypatch):
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=FakeTracer(),
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice", established=True, cookies={"sid": "already"})
    _seed_role(state, "B", "bob")

    calls: list[str] = []

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        calls.append(role_name)
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": "new"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await _call_login_phase(specialist, state, specialist.http_tool)
    assert out == {"A": True, "B": True}
    assert calls == ["B"]  # A skipped because already established


@pytest.mark.asyncio
async def test_password_not_in_trace(monkeypatch):
    tracer = FakeTracer()
    secret_a = "secret123"
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password=secret_a,
        role_b_password="secret456",
    )
    state = State(base_url="http://x")
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": "c"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    await _call_login_phase(specialist, state, specialist.http_tool)

    for note in tracer.notes:
        assert secret_a not in note
        assert "secret456" not in note
    for _name, payload in tracer.events:
        serialized = repr(payload)
        assert secret_a not in serialized
        assert "secret456" not in serialized


# ---------------------------------------------------------------------------
# Phase 2 (horizontal)
# ---------------------------------------------------------------------------


def _make_horizontal_specialist(responder) -> IdorSpecialist:
    return IdorSpecialist(
        http_tool=FakeHttp(responder),
        tracer=FakeTracer(),
    )


def _make_horizontal_state() -> tuple[State, _IdorTarget]:
    state = State(base_url="http://x")
    _seed_role(state, "A", "alice", established=True,
               cookies={"sid": "A-cookie"})
    _seed_role(state, "B", "bob", established=True,
               cookies={"sid": "B-cookie"})
    target = _IdorTarget(
        url="http://x/account",
        id_param="id",
        id_value="42",
        channel="GET",
        id_location="query",
        is_numeric=True,
    )
    return state, target


async def _run_horizontal(specialist: IdorSpecialist, state: State,
                          target: _IdorTarget):
    from penage.specialists.vulns.idor import _BudgetedHttpTool

    budgeted = _BudgetedHttpTool(
        specialist.http_tool, state, cap=specialist.max_http_budget,
    )
    return await specialist._run_horizontal_phase(
        state=state, target=target, http_tool=budgeted, step=0,
    )


@pytest.mark.asyncio
async def test_horizontal_identical_body_verified():
    body = "x" * 512  # long enough to avoid the 32-char downgrade
    def responder(action: Action) -> Observation:
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": body},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["kind"] == "idor_horizontal_identical_body"
    assert finding["mode"] == "horizontal"
    assert finding["evidence"]["a_status"] == 200
    assert finding["evidence"]["b_status"] == 200


@pytest.mark.asyncio
async def test_horizontal_shared_markers_verified():
    body_a = (
        "<html>profile for alice@real.com"
        + " padding " * 40
        + "</html>"
    )
    body_b = (
        "<html>different wrapper but alice@real.com"
        + " more " * 50
        + "</html>"
    )
    state_holder = {"next": 0}
    bodies = [body_a, body_b]

    def responder(action: Action) -> Observation:
        idx = state_holder["next"]
        state_holder["next"] += 1
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": bodies[idx]},
        )

    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["kind"] == "idor_horizontal_shared_markers"
    assert "alice@real.com" in finding["evidence"]["shared_markers"]


@pytest.mark.asyncio
async def test_horizontal_no_signal_no_finding():
    holder = {"next": 0}
    bodies = [
        "aaaaaaaaaa unique body A with no markers " * 10,
        "bbbbbbbbbb totally different body B content " * 10,
    ]
    def responder(action: Action) -> Observation:
        idx = holder["next"]; holder["next"] += 1
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": bodies[idx]},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is None


@pytest.mark.asyncio
async def test_horizontal_both_denied_no_finding():
    def responder(action: Action) -> Observation:
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 403, "text_full": "forbidden"},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is None
    key = specialist._target_key(target)
    assert specialist._observations[key][0]["signal"] == "both_denied"


@pytest.mark.asyncio
async def test_horizontal_skipped_when_role_b_not_established(monkeypatch):
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=1"
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        established = role_name == "A"
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": "c"} if established else {},
                established=established,
                login_error="" if established else "no_set_cookie",
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1 if established else 0,
            failure_reason=None if established else "no_set_cookie",
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    await specialist.propose_async(state, config=SpecialistConfig())
    assert any(n.startswith("idor:horizontal_skipped_no_roles")
               for n in tracer.notes)


@pytest.mark.asyncio
async def test_horizontal_respects_budget():
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        tracer=FakeTracer(),
        max_http_budget=2,  # remaining < 3 right from the start
    )
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is None
    assert specialist.http_tool.calls == []


@pytest.mark.asyncio
async def test_horizontal_cookies_differ_between_probes():
    body = "y" * 256
    def responder(action: Action) -> Observation:
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": body},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    await _run_horizontal(specialist, state, target)
    calls = specialist.http_tool.calls
    assert len(calls) == 2
    assert calls[0].params["cookies"] == {"sid": "A-cookie"}
    assert calls[1].params["cookies"] == {"sid": "B-cookie"}


@pytest.mark.asyncio
async def test_horizontal_evidence_includes_both_usernames():
    body = "z" * 256
    def responder(action: Action) -> Observation:
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": body},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    finding = await _run_horizontal(specialist, state, target)
    assert finding is not None
    assert finding["evidence"]["role_a_user"] == "alice"
    assert finding["evidence"]["role_b_user"] == "bob"


@pytest.mark.asyncio
async def test_horizontal_follow_redirects_false():
    body = "q" * 256
    def responder(action: Action) -> Observation:
        return Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 200, "text_full": body},
        )
    specialist = _make_horizontal_specialist(responder)
    state, target = _make_horizontal_state()
    await _run_horizontal(specialist, state, target)
    for call in specialist.http_tool.calls:
        assert call.params["follow_redirects"] is False


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------


def test_emit_verified_identical_body_score_12():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": True,
        "kind": "idor_horizontal_identical_body",
        "mode": "horizontal",
        "summary": "leak",
    })
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].score == 12.0
    assert "verified" in cands[0].action.tags


def test_emit_verified_shared_markers_score_11():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": True,
        "kind": "idor_horizontal_shared_markers",
        "mode": "horizontal",
        "summary": "leak",
    })
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].score == 11.0


def test_emit_nothing_when_no_findings():
    specialist = IdorSpecialist(http_tool=None)
    assert specialist._emit_if_any() == []


# ---------------------------------------------------------------------------
# Phase 3 (enumeration) helpers
# ---------------------------------------------------------------------------


def test_enum_set_basic_interleaved():
    from penage.specialists.vulns.idor import _build_enum_set

    assert _build_enum_set("42", 3) == ["41", "43", "40", "44", "39", "45"]


def test_enum_set_lower_bound_zero_skipped():
    from penage.specialists.vulns.idor import _build_enum_set

    out = _build_enum_set("2", 5)
    assert "0" not in out
    assert "-1" not in out
    assert "1" in out
    assert all(int(x) >= 1 for x in out)


def test_enum_set_base_one_no_below():
    from penage.specialists.vulns.idor import _build_enum_set

    assert _build_enum_set("1", 2) == ["2", "3"]


def test_enum_set_non_numeric_returns_empty():
    from penage.specialists.vulns.idor import _build_enum_set

    assert _build_enum_set("abc", 5) == []


def test_enum_set_zero_or_negative_n_returns_empty():
    from penage.specialists.vulns.idor import _build_enum_set

    assert _build_enum_set("42", 0) == []
    assert _build_enum_set("42", -3) == []


def test_replace_path_segment_basic():
    from penage.specialists.vulns.idor import _replace_path_segment

    # "/users/42/profile" — non-empty segments are ["users","42","profile"]
    # index 1 = "42".
    assert _replace_path_segment(
        "http://x/users/42/profile", 1, "41",
    ) == "http://x/users/41/profile"


def test_replace_path_segment_middle():
    from penage.specialists.vulns.idor import _replace_path_segment

    # non-empty segments: ["api","v1","orders","99","items"], idx=3 -> "99"
    assert _replace_path_segment(
        "http://x/api/v1/orders/99/items", 3, "100",
    ) == "http://x/api/v1/orders/100/items"


def test_replace_path_segment_out_of_range_returns_unchanged():
    from penage.specialists.vulns.idor import _replace_path_segment

    url = "http://x/users/42"
    assert _replace_path_segment(url, 5, "99") == url
    assert _replace_path_segment(url, -1, "99") == url


def test_replace_path_segment_preserves_query():
    from penage.specialists.vulns.idor import _replace_path_segment

    out = _replace_path_segment("http://x/users/42?ref=x", 1, "41")
    assert out == "http://x/users/41?ref=x"


# ---------------------------------------------------------------------------
# Phase 3 (enumeration) — unit
# ---------------------------------------------------------------------------


class FakeHttpByUrl:
    """Fake http-tool that dispatches by (url, data-id) to an Observation."""

    def __init__(self, routes: dict[str, Observation]) -> None:
        self.routes = routes
        self.calls: list[Action] = []

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        url = action.params.get("url", "")
        data = action.params.get("data") or {}
        # Form channel: key by data id value; query/path: key by URL.
        if data:
            for k, v in data.items():
                composite = f"{url}|form|{k}={v}"
                if composite in self.routes:
                    return self.routes[composite]
        return self.routes.get(url, Observation(
            ok=True, elapsed_ms=1,
            data={"status_code": 404, "text_full": ""},
        ))

    async def aclose(self) -> None:
        return None


def _make_enum_state() -> tuple[State, _IdorTarget]:
    state = State(base_url="http://x")
    _seed_role(state, "A", "alice", established=True,
               cookies={"sid": "A-cookie"})
    target = _IdorTarget(
        url="http://x/account",
        id_param="id",
        id_value="42",
        channel="GET",
        id_location="query",
        is_numeric=True,
    )
    return state, target


async def _run_enumeration(specialist: IdorSpecialist, state: State,
                           target: _IdorTarget):
    from penage.specialists.vulns.idor import _BudgetedHttpTool

    budgeted = _BudgetedHttpTool(
        specialist.http_tool, state, cap=specialist.max_http_budget,
    )
    return await specialist._run_enumeration_phase(
        state=state, target=target, http_tool=budgeted, step=0,
    )


def _obs(status: int, body: str) -> Observation:
    return Observation(
        ok=True, elapsed_ms=1,
        data={"status_code": status, "text_full": body},
    )


@pytest.mark.asyncio
async def test_enum_cross_owner_markers_verified():
    baseline_body = (
        "<html>profile for alice@real.com"
        + " padding " * 40
        + "</html>"
    )
    probe_body = (
        "<html>profile for bob@other.com"
        + " filler " * 40
        + "</html>"
    )
    routes = {
        "http://x/account?id=42": _obs(200, baseline_body),
        "http://x/account?id=41": _obs(200, probe_body),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["kind"] == "idor_enum_cross_owner"
    assert finding["mode"] == "enumeration"
    assert finding["probe_id"] == "41"
    assert "bob@other.com" in finding["evidence"]["cross_owner_markers"]
    # Emitted score is 12.0.
    specialist._findings.append(finding)
    cands = specialist._emit_if_any()
    assert cands[0].score == 12.0


@pytest.mark.asyncio
async def test_enum_identical_baseline_verified():
    body = "x" * 512  # length >= 32, byte-identical both ways.
    routes = {
        "http://x/account?id=42": _obs(200, body),
        "http://x/account?id=41": _obs(200, body),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["kind"] == "idor_enum_identical_baseline"
    specialist._findings.append(finding)
    cands = specialist._emit_if_any()
    assert cands[0].score == 10.0


@pytest.mark.asyncio
async def test_enum_early_exit_on_first_verified():
    baseline = "<html>alice@real.com" + " f " * 40 + "</html>"
    leak = "<html>bob@other.com" + " g " * 40 + "</html>"
    boring = "<html>nobody here" + " h " * 40 + "</html>"
    # Baseline = id=42, probe1 (id=41) -> boring, probe2 (id=43) -> leak,
    # probe3 (id=40) -> should not be fired.
    routes = {
        "http://x/account?id=42": _obs(200, baseline),
        "http://x/account?id=41": _obs(200, boring),
        "http://x/account?id=43": _obs(200, leak),
        "http://x/account?id=40": _obs(200, leak),  # would leak too if fired
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is not None
    assert finding["probe_id"] == "43"
    urls = [c.params.get("url") for c in specialist.http_tool.calls]
    assert "http://x/account?id=40" not in urls


@pytest.mark.asyncio
async def test_enum_skipped_for_uuid_target():
    routes: dict[str, Observation] = {}
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    _seed_role(state, "A", "alice", established=True,
               cookies={"sid": "A-cookie"})
    target = _IdorTarget(
        url="http://x/doc/550e8400-e29b-41d4-a716-446655440000",
        id_param="__path_seg_1__",
        id_value="550e8400-e29b-41d4-a716-446655440000",
        channel="GET",
        id_location="path",
        is_numeric=False,
        path_segment_index=1,
    )
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    assert specialist.http_tool.calls == []


@pytest.mark.asyncio
async def test_enum_skipped_when_role_a_not_established():
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl({}),
        tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    _seed_role(state, "A", "alice", established=False)
    target = _IdorTarget(
        url="http://x/account", id_param="id", id_value="42",
        channel="GET", id_location="query", is_numeric=True,
    )
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    assert specialist.http_tool.calls == []


@pytest.mark.asyncio
async def test_enum_skipped_when_baseline_returns_non_2xx():
    routes = {
        "http://x/account?id=42": _obs(500, "boom"),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    # Only baseline call fired, no probes.
    assert len(specialist.http_tool.calls) == 1


@pytest.mark.asyncio
async def test_enum_skipped_when_baseline_returns_error_obs():
    class BaselineErrorHttp:
        def __init__(self) -> None:
            self.calls: list[Action] = []

        async def run(self, action: Action) -> Observation:
            self.calls.append(action)
            return Observation(ok=False, error="net:boom", elapsed_ms=1)

        async def aclose(self) -> None:
            return None

    specialist = IdorSpecialist(
        http_tool=BaselineErrorHttp(),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    assert len(specialist.http_tool.calls) == 1


@pytest.mark.asyncio
async def test_enum_no_cross_markers_no_finding():
    # Baseline contains alice; every probe returns a body with alice only
    # (so marker set is subset of baseline).
    baseline = "<html>alice@real.com" + " f " * 40 + "</html>"
    same = "<html>alice@real.com" + " g " * 40 + "</html>"
    routes = {
        "http://x/account?id=42": _obs(200, baseline),
        "http://x/account?id=41": _obs(200, same),
        "http://x/account?id=43": _obs(200, same),
        "http://x/account?id=40": _obs(200, same),
        "http://x/account?id=44": _obs(200, same),
        "http://x/account?id=39": _obs(200, same),
        "http://x/account?id=45": _obs(200, same),
        "http://x/account?id=38": _obs(200, same),
        "http://x/account?id=46": _obs(200, same),
        "http://x/account?id=37": _obs(200, same),
        "http://x/account?id=47": _obs(200, same),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None


@pytest.mark.asyncio
async def test_enum_probes_with_non_2xx_recorded_as_non_2xx():
    baseline = "<html>alice@real.com" + " f " * 40 + "</html>"
    leak = "<html>bob@other.com" + " g " * 40 + "</html>"
    routes = {
        "http://x/account?id=42": _obs(200, baseline),
        "http://x/account?id=41": _obs(404, ""),  # probe non-2xx
        "http://x/account?id=43": _obs(200, leak),  # verified here
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is not None
    key = specialist._target_key(target)
    enum_obs = [o for o in specialist._observations[key]
                if o.get("phase") == "enumeration"]
    non_2xx = [o for o in enum_obs if o.get("result") == "non_2xx"]
    assert non_2xx and non_2xx[0]["probe_id"] == "41"


@pytest.mark.asyncio
async def test_enum_respects_http_budget_low():
    # remaining < 3 at entry -> phase skipped without firing.
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl({}),
        tracer=FakeTracer(),
        max_http_budget=2,
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    assert specialist.http_tool.calls == []


@pytest.mark.asyncio
async def test_enum_respects_http_budget_mid_loop():
    # Cap = 4: baseline uses 1, then only 2 more probes can fire (remaining
    # drops from 3 to 2 after first probe, then 1 after second — break on
    # remaining < 2 before third probe).
    baseline = "<html>alice@real.com" + " f " * 40 + "</html>"
    bland = "<html>nothing" + " h " * 40 + "</html>"
    routes = {
        "http://x/account?id=42": _obs(200, baseline),
        "http://x/account?id=41": _obs(200, bland),
        "http://x/account?id=43": _obs(200, bland),
        "http://x/account?id=40": _obs(200, bland),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=FakeTracer(),
        max_http_budget=3,
    )
    state, target = _make_enum_state()
    finding = await _run_enumeration(specialist, state, target)
    assert finding is None
    # 1 baseline + at most 2 probes before remaining<2 kicks in.
    assert len(specialist.http_tool.calls) <= 3


# ---------------------------------------------------------------------------
# Phase 3 integration via propose_async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_propose_async_phase_3_runs_after_horizontal_fails(monkeypatch):
    # Role A established, role B NOT established -> both_roles_ready is
    # False -> phase 2 is skipped. Phase 3 should still run for numeric
    # targets. Easier than mocking horizontal's internals.
    baseline = "<html>alice@real.com" + " padding " * 40 + "</html>"
    probe = "<html>bob@other.com" + " padding " * 40 + "</html>"
    routes = {
        "http://x/r?id=42": _obs(200, baseline),
        "http://x/r?id=41": _obs(200, probe),
    }
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=42"
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        established = role_name == "A"
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": "A-cookie"} if established else {},
                established=established,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1 if established else 0,
            failure_reason=None if established else "no_set_cookie",
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["kind"] == "idor_enum_cross_owner"


@pytest.mark.asyncio
async def test_propose_async_phase_3_skipped_after_horizontal_verified(
    monkeypatch,
):
    # Horizontal returns identical body for both roles A and B -> verified
    # on phase 2, loop breaks before phase 3 can fire. Count probe calls
    # to verify phase 3 did not run.
    body = "x" * 512
    routes: dict[str, Observation] = {
        # Only baseline URLs; no id=41 / id=43 routes exist — if phase 3
        # ran, we'd see a 404 call here. We assert on the URL set instead.
        "http://x/r?id=42": _obs(200, body),
    }
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=42"
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": f"{role_name}-cookie"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["kind"] == "idor_horizontal_identical_body"
    # No probe calls for ids != 42.
    probe_urls = [
        c.params.get("url") for c in specialist.http_tool.calls
        if "id=41" in (c.params.get("url") or "")
        or "id=43" in (c.params.get("url") or "")
    ]
    assert probe_urls == []


@pytest.mark.asyncio
async def test_propose_async_phase_3_cookies_from_role_a(monkeypatch):
    baseline = "<html>alice@real.com" + " padding " * 40 + "</html>"
    probe = "<html>bob@other.com" + " padding " * 40 + "</html>"
    routes = {
        "http://x/r?id=42": _obs(200, baseline),
        "http://x/r?id=41": _obs(200, probe),
    }
    tracer = FakeTracer()
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes),
        tracer=tracer,
        role_a_password="pwA",
        role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=42"
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        established = role_name == "A"
        cookies = {"sid": "A-cookie"} if established else {}
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies=cookies, established=established,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1 if established else 0,
            failure_reason=None if established else "no_set_cookie",
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    await specialist.propose_async(state, config=SpecialistConfig())
    # Filter to HTTP calls against the target URL (phase 3 baseline+probe).
    target_calls = [
        c for c in specialist.http_tool.calls
        if (c.params.get("url") or "").startswith("http://x/r?id=")
    ]
    assert target_calls, "phase 3 must have fired at least one request"
    for call in target_calls:
        assert call.params.get("cookies") == {"sid": "A-cookie"}


# ---------------------------------------------------------------------------
# Phase 4 (vertical)
# ---------------------------------------------------------------------------


def _obs_with_headers(status: int, body: str, headers: dict[str, str]) -> Observation:
    return Observation(
        ok=True, elapsed_ms=1,
        data={"status_code": status, "text_full": body, "headers": dict(headers)},
    )


async def _run_vertical(specialist: IdorSpecialist, state: State):
    from penage.specialists.vulns.idor import _BudgetedHttpTool

    budgeted = _BudgetedHttpTool(
        specialist.http_tool, state, cap=specialist.max_http_budget,
    )
    return await specialist._run_vertical_phase(
        state=state, http_tool=budgeted, step=0,
    )


@pytest.mark.asyncio
async def test_vertical_skipped_when_role_b_not_established():
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/users"
    _seed_role(state, "B", "bob", established=False)
    finding = await _run_vertical(specialist, state)
    assert finding is None
    assert specialist.http_tool.calls == []


@pytest.mark.asyncio
async def test_vertical_no_admin_paths_returns_none():
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/home"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is None
    assert specialist.http_tool.calls == []


def test_vertical_discovers_admin_url_from_last_http_url():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/users?tab=1"
    urls = specialist._discover_admin_paths(state)
    assert urls == ["http://x/admin/users"]


def test_vertical_discovers_admin_url_from_recent_http_memory():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://x")
    state.recent_http_memory = [
        {"url": "http://x/home"},
        {"url": "http://x/management/console?x=1"},
    ]
    urls = specialist._discover_admin_paths(state)
    assert "http://x/management/console" in urls


@pytest.mark.asyncio
async def test_vertical_unauth_403_b_200_verified():
    body_b = "admin dashboard welcome " * 10
    routes = {
        (empty := "http://x/admin/users"): empty,
    }
    _ = routes

    def responder(action: Action) -> Observation:
        if action.params.get("cookies") == {}:
            return _obs(403, "forbidden")
        return _obs(200, body_b)

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/users"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["kind"] == "idor_vertical_privilege"
    specialist._findings.append(finding)
    cands = specialist._emit_if_any()
    assert cands[0].score == 9.0


@pytest.mark.asyncio
async def test_vertical_unauth_redirect_to_login_b_200_verified():
    body_b = "admin settings " * 10

    def responder(action: Action) -> Observation:
        if action.params.get("cookies") == {}:
            return _obs_with_headers(302, "", {"Location": "/login?next=/admin"})
        return _obs(200, body_b)

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/settings"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is not None
    assert finding["verified"] is True
    assert finding["evidence"]["unauth_status"] == 302


@pytest.mark.asyncio
async def test_vertical_unauth_401_b_200_verified():
    body_b = "admin console content " * 10

    def responder(action: Action) -> Observation:
        if action.params.get("cookies") == {}:
            return _obs(401, "unauthorized")
        return _obs(200, body_b)

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/console"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is not None
    assert finding["verified"] is True


@pytest.mark.asyncio
async def test_vertical_both_200_no_finding():
    body = "open page content " * 10

    def responder(action: Action) -> Observation:
        return _obs(200, body)

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is None


@pytest.mark.asyncio
async def test_vertical_both_403_no_finding():
    def responder(action: Action) -> Observation:
        return _obs(403, "forbidden")

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is None


@pytest.mark.asyncio
async def test_vertical_b_body_too_short_no_finding():
    def responder(action: Action) -> Observation:
        if action.params.get("cookies") == {}:
            return _obs(403, "forbidden")
        return _obs(200, "tiny")  # <32 chars

    specialist = IdorSpecialist(
        http_tool=FakeHttp(responder), tracer=FakeTracer(),
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is None


@pytest.mark.asyncio
async def test_vertical_respects_budget():
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop), tracer=FakeTracer(),
        max_http_budget=2,  # remaining < 3
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/users"
    _seed_role(state, "B", "bob", established=True, cookies={"sid": "B-c"})
    finding = await _run_vertical(specialist, state)
    assert finding is None
    assert specialist.http_tool.calls == []


def test_vertical_max_paths_respected():
    specialist = IdorSpecialist(http_tool=None, max_vertical_paths=3)
    state = State(base_url="http://x")
    state.recent_http_memory = [
        {"url": f"http://x/admin/p{i}"} for i in range(5)
    ]
    urls = specialist._discover_admin_paths(state)
    assert len(urls) == 3


# ---------------------------------------------------------------------------
# Phase 5 (candidate)
# ---------------------------------------------------------------------------


def _make_candidate_target() -> _IdorTarget:
    return _IdorTarget(
        url="http://x/account", id_param="id", id_value="42",
        channel="GET", id_location="query", is_numeric=True,
    )


def test_candidate_status_differential_from_horizontal():
    specialist = IdorSpecialist(http_tool=None)
    target = _make_candidate_target()
    obs = [{
        "phase": "horizontal",
        "signal": "status_differential",
        "a_status": 200,
        "b_status": 500,
        "a_body_len": 1000,
        "b_body_len": 200,
    }]
    cand = specialist._finalize_candidate(target=target, observations=obs)
    assert cand is not None
    assert cand["verified"] is False
    assert cand["kind"] == "idor_status_differential"
    assert cand["mode"] == "candidate"
    specialist._findings.append(cand)
    cands = specialist._emit_if_any()
    assert cands[0].score == 3.0


def test_candidate_enum_status_spread():
    specialist = IdorSpecialist(http_tool=None)
    target = _make_candidate_target()
    obs = [
        {"phase": "enumeration", "probe_id": "41", "status": 404,
         "result": "non_2xx"},
        {"phase": "enumeration", "probe_id": "43", "status": 403,
         "result": "non_2xx"},
        {"phase": "enumeration", "probe_id": "40", "status": 500,
         "result": "non_2xx"},
    ]
    cand = specialist._finalize_candidate(target=target, observations=obs)
    assert cand is not None
    assert cand["kind"] == "idor_enum_status_spread"
    assert cand["evidence"]["status_spread"] == [403, 404, 500]
    specialist._findings.append(cand)
    cands = specialist._emit_if_any()
    assert cands[0].score == 2.0


def test_candidate_enum_all_same_status_no_candidate():
    specialist = IdorSpecialist(http_tool=None)
    target = _make_candidate_target()
    obs = [
        {"phase": "enumeration", "probe_id": str(p), "status": 404,
         "result": "non_2xx"}
        for p in (41, 43, 40, 44)
    ]
    cand = specialist._finalize_candidate(target=target, observations=obs)
    assert cand is None


def test_candidate_no_observations_returns_none():
    specialist = IdorSpecialist(http_tool=None)
    target = _make_candidate_target()
    cand = specialist._finalize_candidate(target=target, observations=[])
    assert cand is None


def test_candidate_ignored_when_verified_exists():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": False, "kind": "idor_status_differential",
        "mode": "candidate", "summary": "cand",
    })
    specialist._findings.append({
        "verified": True, "kind": "idor_horizontal_identical_body",
        "mode": "horizontal", "summary": "leak",
    })
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].score == 12.0
    assert "verified" in cands[0].action.tags


# ---------------------------------------------------------------------------
# _emit_if_any
# ---------------------------------------------------------------------------


def test_emit_prefers_verified_over_candidate():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": False, "kind": "idor_enum_status_spread",
        "mode": "candidate", "summary": "cand",
    })
    specialist._findings.append({
        "verified": True, "kind": "idor_enum_cross_owner",
        "mode": "enumeration", "summary": "leak",
    })
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].score == 12.0


def test_emit_candidate_score_3_for_status_differential():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": False, "kind": "idor_status_differential",
        "mode": "candidate", "summary": "cand",
    })
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].score == 3.0
    assert "unverified" in cands[0].action.tags


def test_emit_candidate_score_2_for_enum_status_spread():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": False, "kind": "idor_enum_status_spread",
        "mode": "candidate", "summary": "cand",
    })
    cands = specialist._emit_if_any()
    assert cands[0].score == 2.0
    assert "unverified" in cands[0].action.tags


def test_emit_empty_findings_returns_empty_list():
    specialist = IdorSpecialist(http_tool=None)
    assert specialist._emit_if_any() == []


def test_emit_vertical_privilege_score_9():
    specialist = IdorSpecialist(http_tool=None)
    specialist._findings.append({
        "verified": True, "kind": "idor_vertical_privilege",
        "mode": "vertical", "summary": "priv",
    })
    cands = specialist._emit_if_any()
    assert cands[0].score == 9.0


# ---------------------------------------------------------------------------
# Integration / flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_flow_no_creds_discovery_only():
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop), tracer=FakeTracer(),
        role_a_password="", role_b_password="",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=1"
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_full_flow_horizontal_verified_short_circuits(monkeypatch):
    # Horizontal returns identical body for A and B => verified on phase 2;
    # phases 3/4/5 must not fire.
    body = "x" * 512
    routes = {
        "http://x/r?id=42": _obs(200, body),
    }
    specialist = IdorSpecialist(
        http_tool=FakeHttpByUrl(routes), tracer=FakeTracer(),
        role_a_password="pwA", role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/r?id=42"
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": f"{role_name}-c"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    assert out[0].metadata["evidence"]["kind"] == "idor_horizontal_identical_body"
    # No probe URLs fired (phase 3) and no unauth cookies-empty probes (phase 4).
    for call in specialist.http_tool.calls:
        cookies = call.params.get("cookies")
        # Only A or B cookies observed — no "{}" unauth phase-4 probe.
        assert cookies != {}


@pytest.mark.asyncio
async def test_full_flow_vertical_runs_only_after_all_targets_exhausted(
    monkeypatch,
):
    # Phase 2/3 do not verify; phase 4 fires once and verifies.
    body_b = "admin area " * 10

    class DualHttp:
        def __init__(self) -> None:
            self.calls: list[Action] = []

        async def run(self, action: Action) -> Observation:
            self.calls.append(action)
            url = action.params.get("url") or ""
            cookies = action.params.get("cookies") or {}
            if "/admin" in url:
                if cookies == {}:
                    return _obs(403, "forbidden")
                return _obs(200, body_b)
            # Non-admin resource: distinct, marker-free bodies per role to
            # prevent horizontal/enum from verifying. Role A gets unique
            # per-URL content so enum probes do not hash-match baseline.
            sid = cookies.get("sid", "anon")
            return _obs(
                200,
                f"role {sid} page {url} " + "lorem ipsum filler " * 20,
            )

        async def aclose(self) -> None:
            return None

    specialist = IdorSpecialist(
        http_tool=DualHttp(), tracer=FakeTracer(),
        role_a_password="pwA", role_b_password="pwB",
    )
    state = State(base_url="http://x")
    state.last_http_url = "http://x/admin/users"
    state.recent_http_memory = [{"url": "http://x/r?id=42"}]
    state.auth_roles.login_url = "http://x/login"
    _seed_role(state, "A", "alice")
    _seed_role(state, "B", "bob")

    async def fake_login_role(*, http_tool, login_url, role_name, username,
                               password, user_field, pass_field):
        return LoginAttemptResult(
            session=RoleSession(
                role_name=role_name, username=username,
                cookies={"sid": f"{role_name}-c"}, established=True,
            ),
            status_code=200, response_url=login_url,
            set_cookie_count=1, failure_reason=None,
        )

    monkeypatch.setattr(
        "penage.specialists.vulns.idor.login_role", fake_login_role,
    )
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["kind"] == "idor_vertical_privilege"
    assert out[0].score == 9.0
