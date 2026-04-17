from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from penage.app.config import RuntimeConfig, runtime_config_from_args
from penage.app.runtime_factory import build_runtime_components
from penage.core.guard import RunMode
from penage.core.tracer import JsonlTracer


def _base_args(**overrides: object) -> Namespace:
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
        sandbox_concurrency=2,
        no_correlation_stop=False,
        validation_mode="http",
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _runtime_cfg(**overrides) -> RuntimeConfig:
    base = dict(
        base_url="http://localhost:8080",
        llm_provider="ollama",
        llm_model="llama3.1",
        ollama_model="llama3.1",
        ollama_url="http://localhost:11434",
        trace_path=Path("trace.jsonl"),
        summary_path=None,
        mode=RunMode.SAFE_HTTP,
        allow_static=False,
        actions_per_step=1,
        max_steps=5,
        max_http_requests=10,
        max_total_text_len=1000,
        enable_specialists=True,
        policy_enabled=False,
        sandbox_backend="null",
        docker_image="python:3.12-slim",
        docker_network="none",
        experiment_tag="",
        allowed_hosts=(),
    )
    base.update(overrides)
    return RuntimeConfig(**base)


def test_runtime_config_defaults_parallel_specialists_true() -> None:
    cfg = runtime_config_from_args(_base_args())
    assert cfg.parallel_specialists is True


def test_runtime_config_no_parallel_specialists_flag_disables() -> None:
    cfg = runtime_config_from_args(_base_args(no_parallel_specialists=True))
    assert cfg.parallel_specialists is False


def test_runtime_config_parallel_specialists_propagates_to_manager(tmp_path) -> None:
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="test")

    cfg_on = _runtime_cfg(parallel_specialists=True)
    components_on = build_runtime_components(cfg_on, tracer=tracer)
    assert components_on.orchestrator.specialists is not None
    assert components_on.orchestrator.specialists.parallel_specialists is True
    assert components_on.orchestrator.specialists.proposal_runner.parallel is True

    cfg_off = _runtime_cfg(parallel_specialists=False)
    components_off = build_runtime_components(cfg_off, tracer=tracer)
    assert components_off.orchestrator.specialists is not None
    assert components_off.orchestrator.specialists.parallel_specialists is False
    assert components_off.orchestrator.specialists.proposal_runner.parallel is False
