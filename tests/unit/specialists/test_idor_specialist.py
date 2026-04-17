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
async def test_phases_3_4_5_not_implemented_raise():
    specialist = IdorSpecialist(http_tool=None)
    with pytest.raises(NotImplementedError):
        await specialist._run_enumeration_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_vertical_phase()
    with pytest.raises(NotImplementedError):
        specialist._finalize_candidate()


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
