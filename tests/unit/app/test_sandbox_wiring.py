from __future__ import annotations

from pathlib import Path

import pytest

from penage.app.config import RuntimeConfig
from penage.app.runtime_factory import (
    SANDBOX_SPECIALIST_NAMES,
    build_sandbox_agents,
    build_specialists,
)
from penage.core.guard import RunMode
from penage.llm.fake import FakeLLMClient
from penage.llm.role_tagged import RoleTaggedLLMClient
from penage.specialists.research_llm import ResearchLLMSpecialist
from penage.specialists.vulns.idor import IdorSpecialist
from penage.specialists.vulns.lfi import LfiSpecialist
from penage.specialists.vulns.sqli import SqliSpecialist
from penage.specialists.vulns.ssti import SstiSpecialist
from penage.specialists.vulns.xss import XssSpecialist
from penage.specialists.vulns.xxe import XxeSpecialist


EXPECTED_NAMES = {"xss", "sqli", "ssti", "lfi", "xxe", "idor", "research_llm"}


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


def test_sandbox_names_constant_matches_expected_set() -> None:
    assert set(SANDBOX_SPECIALIST_NAMES) == EXPECTED_NAMES


def test_build_sandbox_agents_returns_seven_agents_with_expected_keys() -> None:
    agents = build_sandbox_agents(FakeLLMClient())

    assert set(agents.keys()) == EXPECTED_NAMES
    assert len(agents) == 7
    for name, agent in agents.items():
        assert agent.specialist_name == name
        proxy = agent.llm_client
        assert isinstance(proxy, RoleTaggedLLMClient)
        assert proxy.role == "sandbox"
        assert proxy.specialist_name == name


def test_build_specialists_wires_proxy_clients_identity_equal_to_agents() -> None:
    llm = FakeLLMClient()
    agents = build_sandbox_agents(llm)

    manager = build_specialists(
        _cfg(),
        llm,
        memory=None,
        tools=None,
        tracer=None,
        sandbox_agents=agents,
    )
    assert manager is not None

    by_type: dict[type, object] = {}
    for s in manager.specialists:
        by_type.setdefault(type(s), s)

    wired_pairs = {
        "xss": by_type[XssSpecialist],
        "sqli": by_type[SqliSpecialist],
        "ssti": by_type[SstiSpecialist],
        "lfi": by_type[LfiSpecialist],
        "xxe": by_type[XxeSpecialist],
        "idor": by_type[IdorSpecialist],
    }
    for name, specialist in wired_pairs.items():
        assert specialist.llm_client is agents[name].llm_client, name

    research = by_type[ResearchLLMSpecialist]
    assert research.llm is agents["research_llm"].llm_client


def test_build_specialists_builds_agents_if_not_provided() -> None:
    llm = FakeLLMClient()
    manager = build_specialists(_cfg(), llm, memory=None, tools=None, tracer=None)

    assert manager is not None

    xss = next(s for s in manager.specialists if isinstance(s, XssSpecialist))
    proxy = xss.llm_client
    assert isinstance(proxy, RoleTaggedLLMClient)
    assert proxy.role == "sandbox"
    assert proxy.specialist_name == "xss"


def test_build_specialists_disabled_returns_none() -> None:
    manager = build_specialists(
        _cfg(enable_specialists=False),
        FakeLLMClient(),
        memory=None,
        tools=None,
        tracer=None,
        sandbox_agents=None,
    )
    assert manager is None
