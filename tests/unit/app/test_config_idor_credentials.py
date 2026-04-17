from __future__ import annotations

from argparse import Namespace

import pytest

from penage.app.bootstrap import seed_role_sessions_from_config
from penage.app.config import (
    RuntimeConfig,
    _idor_cred_from_args_or_env,
    runtime_config_from_args,
)
from penage.core.state import State


IDOR_ENV_VARS = (
    "PENAGE_IDOR_ROLE_A_USER",
    "PENAGE_IDOR_ROLE_A_PASS",
    "PENAGE_IDOR_ROLE_B_USER",
    "PENAGE_IDOR_ROLE_B_PASS",
    "PENAGE_IDOR_LOGIN_URL",
)


@pytest.fixture(autouse=True)
def _clean_idor_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in IDOR_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def make_args(**overrides: object) -> Namespace:
    defaults: dict[str, object] = dict(
        base_url="http://localhost:8080",
        llm_provider="ollama",
        llm_model="llama3.1",
        ollama_model="llama3.1",
        ollama_url="http://localhost:11434",
        allowed_host=[],
        max_steps=10,
        trace="runs/trace.jsonl",
        summary_json="",
        mode="safe-http",
        allow_static=False,
        actions_per_step=1,
        max_http_requests=30,
        max_total_text_len=200_000,
        enable_specialists=False,
        policy="off",
        sandbox_backend="null",
        docker_image="python:3.12-slim",
        docker_network="none",
        early_stop_tool_calls=40,
        early_stop_cost=0.30,
        early_stop_seconds=300.0,
        memory_db="runs/memory.sqlite",
        experiment_tag="",
        idor_role_a_user="",
        idor_role_a_pass="",
        idor_role_b_user="",
        idor_role_b_pass="",
        idor_login_url="",
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _cfg_with_roles(
    *,
    a_user: str = "",
    a_pass: str = "",
    b_user: str = "",
    b_pass: str = "",
    login_url: str = "",
) -> RuntimeConfig:
    args = make_args(
        idor_role_a_user=a_user,
        idor_role_a_pass=a_pass,
        idor_role_b_user=b_user,
        idor_role_b_pass=b_pass,
        idor_login_url=login_url,
    )
    return runtime_config_from_args(args)


def test_no_idor_flags_no_env_fields_empty() -> None:
    cfg = runtime_config_from_args(make_args())
    assert cfg.idor_role_a_user == ""
    assert cfg.idor_role_a_pass == ""
    assert cfg.idor_role_b_user == ""
    assert cfg.idor_role_b_pass == ""
    assert cfg.idor_login_url == ""


def test_cli_flag_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENAGE_IDOR_ROLE_A_USER", "envalice")
    args = make_args(idor_role_a_user="cliclient")
    cfg = runtime_config_from_args(args)
    assert cfg.idor_role_a_user == "cliclient"


def test_env_fallback_when_cli_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENAGE_IDOR_ROLE_A_USER", "envalice")
    monkeypatch.setenv("PENAGE_IDOR_ROLE_A_PASS", "envpassA")
    monkeypatch.setenv("PENAGE_IDOR_ROLE_B_USER", "envbob")
    monkeypatch.setenv("PENAGE_IDOR_ROLE_B_PASS", "envpassB")
    cfg = runtime_config_from_args(make_args())
    assert cfg.idor_role_a_user == "envalice"
    assert cfg.idor_role_a_pass == "envpassA"
    assert cfg.idor_role_b_user == "envbob"
    assert cfg.idor_role_b_pass == "envpassB"


def test_idor_login_url_cli_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # env-only
    monkeypatch.setenv("PENAGE_IDOR_LOGIN_URL", "http://env/login")
    cfg_env = runtime_config_from_args(make_args())
    assert cfg_env.idor_login_url == "http://env/login"

    # CLI overrides env
    cfg_cli = runtime_config_from_args(
        make_args(idor_login_url="http://cli/login")
    )
    assert cfg_cli.idor_login_url == "http://cli/login"


def test_role_a_fully_configured_role_b_partial() -> None:
    cfg = _cfg_with_roles(
        a_user="alice",
        a_pass="pass1",
        b_user="bob",
        b_pass="",
    )
    # Config stores raw values without filtering.
    assert cfg.idor_role_a_user == "alice"
    assert cfg.idor_role_a_pass == "pass1"
    assert cfg.idor_role_b_user == "bob"
    assert cfg.idor_role_b_pass == ""


def test_seed_role_sessions_role_a_and_b_full_config() -> None:
    cfg = _cfg_with_roles(
        a_user="alice", a_pass="pass1",
        b_user="bob", b_pass="pass2",
    )
    state = State(base_url="http://localhost:8080")
    seed_role_sessions_from_config(state, cfg)

    assert set(state.auth_roles.roles.keys()) == {"A", "B"}

    role_a = state.auth_roles.roles["A"]
    assert role_a.role_name == "A"
    assert role_a.username == "alice"
    assert role_a.established is False
    assert role_a.cookies == {}

    role_b = state.auth_roles.roles["B"]
    assert role_b.role_name == "B"
    assert role_b.username == "bob"
    assert role_b.established is False


def test_seed_role_sessions_skips_role_without_full_creds() -> None:
    cfg = _cfg_with_roles(
        a_user="alice", a_pass="pass1",
        b_user="bob", b_pass="",
    )
    state = State(base_url="http://localhost:8080")
    seed_role_sessions_from_config(state, cfg)

    assert set(state.auth_roles.roles.keys()) == {"A"}


def test_seed_role_sessions_no_passwords_in_state() -> None:
    cfg = _cfg_with_roles(
        a_user="alice", a_pass="supersecretA",
        b_user="bob", b_pass="supersecretB",
        login_url="http://login/ok",
    )
    state = State(base_url="http://localhost:8080")
    seed_role_sessions_from_config(state, cfg)

    # Check every role session
    for role in state.auth_roles.roles.values():
        assert "supersecretA" not in role.username
        assert "supersecretB" not in role.username
        for k, v in role.cookies.items():
            assert "supersecretA" not in k and "supersecretA" not in v
            assert "supersecretB" not in k and "supersecretB" not in v
        assert "supersecretA" not in role.login_error
        assert "supersecretB" not in role.login_error

    assert "supersecretA" not in state.auth_roles.login_url
    assert "supersecretB" not in state.auth_roles.login_url


def test_seed_role_sessions_login_url_copied() -> None:
    cfg = _cfg_with_roles(
        a_user="alice", a_pass="pass1",
        login_url="http://target/login",
    )
    state = State(base_url="http://localhost:8080")
    seed_role_sessions_from_config(state, cfg)

    assert state.auth_roles.login_url == "http://target/login"


def test_seed_role_sessions_no_creds_leaves_registry_empty() -> None:
    cfg = _cfg_with_roles()
    state = State(base_url="http://localhost:8080")
    seed_role_sessions_from_config(state, cfg)

    assert state.auth_roles.roles == {}
    assert state.auth_roles.login_url == ""


def test_idor_cred_helper_env_name_correct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENAGE_IDOR_ROLE_A_USER", "fromenv")
    monkeypatch.setenv("WRONG_NAME", "wrong")

    args = Namespace(idor_role_a_user="")
    value = _idor_cred_from_args_or_env(
        args,
        arg_name="idor_role_a_user",
        env_name="PENAGE_IDOR_ROLE_A_USER",
    )
    assert value == "fromenv"

    # When the CLI value is non-empty, env is ignored regardless of name.
    args2 = Namespace(idor_role_a_user="fromcli")
    value2 = _idor_cred_from_args_or_env(
        args2,
        arg_name="idor_role_a_user",
        env_name="PENAGE_IDOR_ROLE_A_USER",
    )
    assert value2 == "fromcli"

    # Looks up the exact env var name supplied, not a similarly-named one.
    args3 = Namespace(idor_role_a_user="")
    value3 = _idor_cred_from_args_or_env(
        args3,
        arg_name="idor_role_a_user",
        env_name="WRONG_NAME",
    )
    assert value3 == "wrong"
