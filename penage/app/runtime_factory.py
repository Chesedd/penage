from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from penage.app.config import RuntimeConfig
from penage.core.guard import ExecutionGuard, allowed_action_types_for_mode
from penage.core.orchestrator import Orchestrator
from penage.core.tracer import JsonlTracer
from penage.core.url_guard import UrlGuard
from penage.llm.ollama import OllamaClient
from penage.macros.base import MacroExecutor
from penage.macros.follow_authenticated_branch import FollowAuthenticatedBranchMacro
from penage.macros.probe_resource_family import ProbeResourceFamilyMacro
from penage.macros.replay_auth_session import ReplayAuthSessionMacro
from penage.policy.gctr_lite import GctrLitePolicy
from penage.sandbox.base import Sandbox
from penage.sandbox.docker import DockerSandbox
from penage.sandbox.null import NullSandbox
from penage.specialists.auth_session_confusion import AuthSessionConfusionSpecialist
from penage.specialists.curl_recon import CurlReconSpecialist
from penage.specialists.login_workflow import LoginWorkflowSpecialist
from penage.specialists.manager import SpecialistManager
from penage.specialists.navigator import NavigatorSpecialist
from penage.specialists.research import ResearchSpecialist
from penage.specialists.research_llm import ResearchLLMSpecialist
from penage.specialists.sandbox_smoke import SandboxSmokeSpecialist
from penage.specialists.sqli import SqliSpecialist
from penage.specialists.xss import XssSpecialist
from penage.tools.runner import ToolRunner


@dataclass(slots=True)
class RuntimeComponents:
    base_url: str
    sandbox: Sandbox
    tools: ToolRunner
    llm: OllamaClient
    orchestrator: Orchestrator


def rewrite_base_url_for_docker(base_url: str) -> str:
    try:
        p = urlparse(base_url)
    except Exception:
        return base_url

    host = (p.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1"):
        return base_url

    new_netloc = "host.docker.internal"
    if p.port:
        new_netloc += f":{p.port}"

    return urlunparse((p.scheme, new_netloc, p.path, p.params, p.query, p.fragment))


def use_curl_http_backend(cfg: RuntimeConfig) -> bool:
    return cfg.mode.value == "sandboxed" and cfg.sandbox_backend == "docker"


def compute_base_url(cfg: RuntimeConfig) -> str:
    if use_curl_http_backend(cfg):
        return rewrite_base_url_for_docker(cfg.base_url)
    return cfg.base_url


def build_allowed_hosts(cfg: RuntimeConfig) -> set[str]:
    hosts = {"localhost", "127.0.0.1"}
    if use_curl_http_backend(cfg):
        hosts.add("host.docker.internal")
    for h in cfg.allowed_hosts:
        hosts.add(str(h))
    return hosts


def build_sandbox(cfg: RuntimeConfig) -> Sandbox:
    if cfg.sandbox_backend == "docker":
        return DockerSandbox(
            image=cfg.docker_image,
            network_mode=cfg.docker_network,
            persistent=(cfg.mode.value == "sandboxed"),
        )
    return NullSandbox()


def build_tools(cfg: RuntimeConfig, *, sandbox: Sandbox) -> ToolRunner:
    return ToolRunner.create_default(
        allowed_hosts=build_allowed_hosts(cfg),
        sandbox=sandbox,
        use_curl_http=use_curl_http_backend(cfg),
    )


def build_llm(cfg: RuntimeConfig) -> OllamaClient:
    return OllamaClient(model=cfg.ollama_model, base_url=cfg.ollama_url, max_retries=1)


def build_macro_executor() -> MacroExecutor:
    ex = MacroExecutor()
    ex.register(ReplayAuthSessionMacro())
    ex.register(FollowAuthenticatedBranchMacro())
    ex.register(ProbeResourceFamilyMacro())
    return ex


def build_specialists(cfg: RuntimeConfig, llm: OllamaClient) -> SpecialistManager | None:
    if not cfg.enable_specialists:
        return None

    return SpecialistManager(
        specialists=[
            SandboxSmokeSpecialist(),
            LoginWorkflowSpecialist(),
            AuthSessionConfusionSpecialist(),
            CurlReconSpecialist(),
            NavigatorSpecialist(),
            ResearchSpecialist(),
            ResearchLLMSpecialist(llm),
            XssSpecialist(),
            SqliSpecialist(),
        ],
        llm=llm,
    )


def build_policy(cfg: RuntimeConfig) -> GctrLitePolicy | None:
    if not cfg.policy_enabled:
        return None
    return GctrLitePolicy()


def build_orchestrator(
    cfg: RuntimeConfig,
    *,
    llm: OllamaClient,
    tools: ToolRunner,
    tracer: JsonlTracer,
) -> Orchestrator:
    return Orchestrator(
        llm=llm,
        tools=tools,
        tracer=tracer,
        guard=ExecutionGuard(allowed=allowed_action_types_for_mode(cfg.mode)),
        url_guard=UrlGuard(block_static_assets=(not cfg.allow_static)),
        policy=build_policy(cfg),
        specialists=build_specialists(cfg, llm),
        macro_executor=build_macro_executor(),
    )


def build_runtime_components(cfg: RuntimeConfig, *, tracer: JsonlTracer) -> RuntimeComponents:
    sandbox = build_sandbox(cfg)
    tools = build_tools(cfg, sandbox=sandbox)
    llm = build_llm(cfg)
    orchestrator = build_orchestrator(cfg, llm=llm, tools=tools, tracer=tracer)
    return RuntimeComponents(
        base_url=compute_base_url(cfg),
        sandbox=sandbox,
        tools=tools,
        llm=llm,
        orchestrator=orchestrator,
    )