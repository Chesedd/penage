from __future__ import annotations

from dataclasses import dataclass

from penage.app.config import RuntimeConfig
from penage.app.runtime_factory import build_runtime_components
from penage.core.orchestrator import Orchestrator
from penage.core.state import RoleSession, State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.tools.runner import ToolRunner


@dataclass(slots=True)
class BootstrapBundle:
    base_url: str
    tools: ToolRunner
    llm: LLMClient
    orchestrator: Orchestrator
    memory: MemoryStore


def build_runtime(cfg: RuntimeConfig, tracer: JsonlTracer) -> BootstrapBundle:
    components = build_runtime_components(cfg, tracer=tracer)
    return BootstrapBundle(
        base_url=components.base_url,
        tools=components.tools,
        llm=components.llm,
        orchestrator=components.orchestrator,
        memory=components.memory,
    )


def seed_role_sessions_from_config(state: State, cfg: RuntimeConfig) -> None:
    """Populate state.auth_roles with empty RoleSession stubs for every
    role that has both user and pass configured.

    Does NOT perform any HTTP login. The IdorSpecialist itself runs the
    login as phase 0 and updates the RoleSession in place (established=True,
    cookies={...}). This helper just ensures that the registry knows which
    role names are expected so that downstream discovery is deterministic.

    Passwords are intentionally NOT written to state — they stay in cfg and
    are passed to the login utility directly to minimise the chance of a
    password leaking into a trace or summary.
    """
    if cfg.idor_role_a_user and cfg.idor_role_a_pass:
        state.auth_roles.upsert(RoleSession(
            role_name="A",
            username=cfg.idor_role_a_user,
        ))
    if cfg.idor_role_b_user and cfg.idor_role_b_pass:
        state.auth_roles.upsert(RoleSession(
            role_name="B",
            username=cfg.idor_role_b_user,
        ))
    if cfg.idor_login_url:
        state.auth_roles.login_url = cfg.idor_login_url
