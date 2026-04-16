from __future__ import annotations

from dataclasses import dataclass

from penage.app.config import RuntimeConfig
from penage.app.runtime_factory import build_runtime_components
from penage.core.orchestrator import Orchestrator
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.tools.runner import ToolRunner


@dataclass(slots=True)
class BootstrapBundle:
    base_url: str
    tools: ToolRunner
    llm: LLMClient
    orchestrator: Orchestrator


def build_runtime(cfg: RuntimeConfig, tracer: JsonlTracer) -> BootstrapBundle:
    components = build_runtime_components(cfg, tracer=tracer)
    return BootstrapBundle(
        base_url=components.base_url,
        tools=components.tools,
        llm=components.llm,
        orchestrator=components.orchestrator,
    )