from __future__ import annotations

from penage.core.state import AuthRoleRegistry, AuthState, RoleSession, State


def test_role_session_defaults() -> None:
    sess = RoleSession(role_name="alice")
    assert sess.role_name == "alice"
    assert sess.username == ""
    assert sess.cookies == {}
    assert sess.established is False
    assert sess.last_login_ts == 0.0
    assert sess.login_error == ""


def test_registry_empty_returns_none_on_get() -> None:
    reg = AuthRoleRegistry()
    assert reg.get("missing") is None
    assert reg.roles == {}
    assert reg.login_url == ""


def test_registry_upsert_adds_role() -> None:
    reg = AuthRoleRegistry()
    sess = RoleSession(role_name="alice", username="alice", established=True)
    reg.upsert(sess)
    assert reg.get("alice") is sess
    assert list(reg.roles.keys()) == ["alice"]


def test_registry_upsert_replaces_existing_same_name() -> None:
    reg = AuthRoleRegistry()
    first = RoleSession(role_name="alice", username="old")
    second = RoleSession(role_name="alice", username="new", established=True)
    reg.upsert(first)
    reg.upsert(second)
    assert reg.get("alice") is second
    assert len(reg.roles) == 1


def test_registry_has_established_false_when_not_established() -> None:
    reg = AuthRoleRegistry()
    reg.upsert(RoleSession(role_name="alice", established=False))
    assert reg.has_established("alice") is False
    assert reg.has_established("bob") is False


def test_registry_has_established_true_after_upsert_with_flag() -> None:
    reg = AuthRoleRegistry()
    reg.upsert(RoleSession(role_name="alice", established=True))
    assert reg.has_established("alice") is True


def test_registry_established_roles_returns_only_established() -> None:
    reg = AuthRoleRegistry()
    reg.upsert(RoleSession(role_name="alice", established=True))
    reg.upsert(RoleSession(role_name="bob", established=False))
    reg.upsert(RoleSession(role_name="carol", established=True))
    assert sorted(reg.established_roles()) == ["alice", "carol"]


def test_state_has_auth_roles_field_default_empty() -> None:
    state = State()
    assert isinstance(state.auth_roles, AuthRoleRegistry)
    assert state.auth_roles.roles == {}
    assert state.auth_roles.login_url == ""


def test_state_auth_roles_independent_of_auth() -> None:
    state = State()
    assert isinstance(state.auth, AuthState)
    state.auth_roles.upsert(RoleSession(role_name="alice", established=True))
    assert state.auth.session_established is False
    state.auth.session_established = True
    assert state.auth_roles.has_established("alice") is True
    assert "alice" in state.auth_roles.roles


def test_role_session_cookies_are_copied_not_shared() -> None:
    a = RoleSession(role_name="alice")
    b = RoleSession(role_name="bob")
    a.cookies["session"] = "A-token"
    assert b.cookies == {}
    assert a.cookies == {"session": "A-token"}
