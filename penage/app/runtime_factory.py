from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from penage.app.config import RuntimeConfig
from penage.core.errors import LLMResponseError
from penage.core.guard import ExecutionGuard, allowed_action_types_for_mode
from penage.core.orchestrator import Orchestrator
from penage.core.tracer import JsonlTracer
from penage.core.url_guard import UrlGuard
from penage.llm.base import LLMClient
from penage.llm.ollama import OllamaClient
from penage.macros.base import MacroExecutor
from penage.memory.store import MemoryStore
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
from penage.specialists.vulns.idor import IdorSpecialist
from penage.specialists.vulns.lfi import LfiSpecialist
from penage.specialists.vulns.sqli import SqliSpecialist
from penage.specialists.vulns.ssti import SstiSpecialist
from penage.specialists.vulns.xss import XssSpecialist
from penage.specialists.vulns.xxe import XxeSpecialist
from penage.tools.runner import ToolRunner
from penage.validation.browser import BrowserVerifier


@dataclass(slots=True)
class RuntimeComponents:
    base_url: str
    sandbox: Sandbox
    tools: ToolRunner
    llm: LLMClient
    orchestrator: Orchestrator
    memory: MemoryStore


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


def build_llm(cfg: RuntimeConfig) -> LLMClient:
    provider = (cfg.llm_provider or "ollama").lower()

    if provider == "ollama":
        model = cfg.llm_model or cfg.ollama_model
        if not model:
            raise LLMResponseError("ollama provider requires --llm-model or --ollama-model")
        return OllamaClient(model=model, base_url=cfg.ollama_url, max_retries=1)

    if provider == "anthropic":
        from penage.llm.anthropic import AnthropicClient, DEFAULT_MODEL as ANTHROPIC_DEFAULT
        return AnthropicClient(model=cfg.llm_model or ANTHROPIC_DEFAULT)

    if provider == "openai":
        from penage.llm.openai import OpenAIClient, DEFAULT_MODEL as OPENAI_DEFAULT
        return OpenAIClient(model=cfg.llm_model or OPENAI_DEFAULT)

    raise LLMResponseError(f"unknown llm provider: {provider}")


def build_macro_executor() -> MacroExecutor:
    ex = MacroExecutor()
    ex.register(ReplayAuthSessionMacro())
    ex.register(FollowAuthenticatedBranchMacro())
    ex.register(ProbeResourceFamilyMacro())
    return ex


def build_specialists(
    cfg: RuntimeConfig,
    llm: LLMClient,
    *,
    memory: MemoryStore | None = None,
    tools: ToolRunner | None = None,
    tracer: JsonlTracer | None = None,
) -> SpecialistManager | None:
    if not cfg.enable_specialists:
        return None

    http_backend = tools.http_backend if tools is not None else None

    xss = XssSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        browser_verifier=BrowserVerifier(),
        tracer=tracer,
    )
    sqli = SqliSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
    )
    ssti = SstiSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
    )
    lfi = LfiSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
        oob_listener=None,
    )
    xxe = XxeSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
        # shared OobListener wiring is a separate infra task; until then
        # phase 4 degrades gracefully via the is_running check.
        oob_listener=None,
    )
    idor = IdorSpecialist(
        http_tool=http_backend,
        llm_client=llm,
        memory=memory,
        tracer=tracer,
        role_a_password=cfg.idor_role_a_pass,
        role_b_password=cfg.idor_role_b_pass,
    )

    return SpecialistManager(
        specialists=[
            SandboxSmokeSpecialist(),
            LoginWorkflowSpecialist(),
            AuthSessionConfusionSpecialist(),
            CurlReconSpecialist(),
            NavigatorSpecialist(),
            ResearchSpecialist(),
            ResearchLLMSpecialist(llm),
            xss,
            sqli,
            ssti,
            lfi,
            xxe,
            idor,
        ],
        llm=llm,
        memory=memory,
    )


def build_policy(cfg: RuntimeConfig) -> GctrLitePolicy | None:
    if not cfg.policy_enabled:
        return None
    return GctrLitePolicy()


def build_memory(cfg: RuntimeConfig) -> MemoryStore:
    return MemoryStore(cfg.memory_db_path)


def build_orchestrator(
    cfg: RuntimeConfig,
    *,
    llm: LLMClient,
    tools: ToolRunner,
    tracer: JsonlTracer,
    memory: MemoryStore | None = None,
) -> Orchestrator:
    return Orchestrator(
        llm=llm,
        tools=tools,
        tracer=tracer,
        guard=ExecutionGuard(allowed=allowed_action_types_for_mode(cfg.mode)),
        url_guard=UrlGuard(block_static_assets=(not cfg.allow_static)),
        policy=build_policy(cfg),
        specialists=build_specialists(cfg, llm, memory=memory, tools=tools, tracer=tracer),
        macro_executor=build_macro_executor(),
        memory=memory,
    )


def build_runtime_components(cfg: RuntimeConfig, *, tracer: JsonlTracer) -> RuntimeComponents:
    sandbox = build_sandbox(cfg)
    tools = build_tools(cfg, sandbox=sandbox)
    llm = build_llm(cfg)
    memory = build_memory(cfg)
    orchestrator = build_orchestrator(cfg, llm=llm, tools=tools, tracer=tracer, memory=memory)
    return RuntimeComponents(
        base_url=compute_base_url(cfg),
        sandbox=sandbox,
        tools=tools,
        llm=llm,
        orchestrator=orchestrator,
        memory=memory,
    )