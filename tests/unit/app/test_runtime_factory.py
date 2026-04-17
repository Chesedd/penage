from __future__ import annotations

from pathlib import Path

from penage.app.config import RuntimeConfig
from penage.app.runtime_factory import (
    build_allowed_hosts,
    build_macro_executor,
    build_policy,
    build_runtime_components,
    build_specialists,
    build_sandbox,
    compute_base_url,
    rewrite_base_url_for_docker,
    use_curl_http_backend,
)
from penage.core.guard import RunMode
from penage.core.tracer import JsonlTracer
from penage.sandbox.docker import DockerSandbox
from penage.sandbox.null import NullSandbox


def _cfg(**overrides) -> RuntimeConfig:
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
        enable_specialists=False,
        policy_enabled=False,
        sandbox_backend="null",
        docker_image="python:3.12-slim",
        docker_network="none",
        experiment_tag="",
        allowed_hosts=("example.internal",),
    )
    base.update(overrides)
    return RuntimeConfig(**base)


def test_runtime_factory_uses_curl_backend_only_for_sandboxed_docker():
    assert use_curl_http_backend(_cfg(mode=RunMode.SANDBOXED, sandbox_backend="docker")) is True
    assert use_curl_http_backend(_cfg(mode=RunMode.SAFE_HTTP, sandbox_backend="docker")) is False
    assert use_curl_http_backend(_cfg(mode=RunMode.SANDBOXED, sandbox_backend="null")) is False


def test_runtime_factory_rewrites_localhost_for_docker_and_builds_allowed_hosts():
    cfg = _cfg(mode=RunMode.SANDBOXED, sandbox_backend="docker")

    assert rewrite_base_url_for_docker("http://localhost:8080") == "http://host.docker.internal:8080"
    assert compute_base_url(cfg) == "http://host.docker.internal:8080"

    hosts = build_allowed_hosts(cfg)
    assert hosts == {"localhost", "127.0.0.1", "host.docker.internal", "example.internal"}


def test_runtime_factory_builds_null_or_docker_sandbox():
    assert isinstance(build_sandbox(_cfg(sandbox_backend="null")), NullSandbox)

    sandbox = build_sandbox(_cfg(mode=RunMode.SANDBOXED, sandbox_backend="docker"))
    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.persistent is True


def test_runtime_factory_builds_optional_policy_and_specialists():
    llm_cfg = _cfg(enable_specialists=True, policy_enabled=True)
    tracer = JsonlTracer(Path("/tmp/runtime-factory-test-trace.jsonl"), episode_id="test")
    components = build_runtime_components(llm_cfg, tracer=tracer)

    assert build_policy(_cfg(policy_enabled=False)) is None
    assert build_policy(_cfg(policy_enabled=True)) is not None

    specialists = build_specialists(llm_cfg, components.llm)
    assert specialists is not None
    assert len(specialists.specialists) == 13

    macro_executor = build_macro_executor()
    assert set(macro_executor.registry.keys()) == {
        "replay_auth_session",
        "follow_authenticated_branch",
        "probe_resource_family",
    }


def test_runtime_factory_builds_runtime_components_with_expected_wiring(tmp_path):
    cfg = _cfg(enable_specialists=True, policy_enabled=True)
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="test")

    components = build_runtime_components(cfg, tracer=tracer)

    assert components.base_url == "http://localhost:8080"
    assert components.orchestrator.llm is components.llm
    assert components.orchestrator.tools is components.tools
    assert components.orchestrator.tracer is tracer
    assert components.orchestrator.policy is not None
    assert components.orchestrator.specialists is not None
    assert components.orchestrator.macro_executor is not None


def test_runtime_factory_wires_idor_specialist():
    """IdorSpecialist is registered by runtime_factory with role
    passwords from RuntimeConfig."""
    cfg = _cfg(
        enable_specialists=True,
        idor_role_a_user="alice",
        idor_role_a_pass="alice_pass",
        idor_role_b_user="bob",
        idor_role_b_pass="bob_pass",
    )
    tracer = JsonlTracer(Path("/tmp/runtime-factory-idor-trace.jsonl"), episode_id="test")
    components = build_runtime_components(cfg, tracer=tracer)
    manager = components.orchestrator.specialists

    assert manager is not None
    names = [s.name for s in manager.specialists]
    assert "idor" in names

    idor = next(s for s in manager.specialists if s.name == "idor")
    assert idor.role_a_password == "alice_pass"
    assert idor.role_b_password == "bob_pass"


def test_runtime_factory_idor_without_creds_still_registered():
    """IdorSpecialist is registered even without role credentials —
    it will simply skip phase 0/2/3 with a note."""
    cfg = _cfg(enable_specialists=True)
    tracer = JsonlTracer(Path("/tmp/runtime-factory-idor-nocreds-trace.jsonl"), episode_id="test")
    components = build_runtime_components(cfg, tracer=tracer)
    manager = components.orchestrator.specialists

    assert manager is not None
    names = [s.name for s in manager.specialists]
    assert "idor" in names

    idor = next(s for s in manager.specialists if s.name == "idor")
    assert idor.role_a_password == ""
    assert idor.role_b_password == ""


def test_runtime_factory_does_not_log_passwords(caplog):
    """Guard: role passwords never appear in factory logs."""
    caplog.set_level("DEBUG")
    cfg = _cfg(
        enable_specialists=True,
        idor_role_a_user="alice",
        idor_role_a_pass="SUPER_SECRET_1",
        idor_role_b_user="bob",
        idor_role_b_pass="SUPER_SECRET_2",
    )
    tracer = JsonlTracer(Path("/tmp/runtime-factory-idor-log-trace.jsonl"), episode_id="test")
    _ = build_runtime_components(cfg, tracer=tracer)
    all_logs = "\n".join(r.getMessage() for r in caplog.records)
    assert "SUPER_SECRET_1" not in all_logs
    assert "SUPER_SECRET_2" not in all_logs