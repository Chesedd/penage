"""Helpers for Stage 3.9 end-to-end integration tests.

Provides a single :func:`build_e2e_orchestrator` that wires a minimal
:class:`Orchestrator` around :class:`FakeLLMClient`-backed agents so an
episode can be driven deterministically in-process without Docker or real
HTTP. All 3.x collaborators live independently of the run mode, so the
sandboxed/safe-http split is expressed via the ``mode`` argument only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from penage.agents.validation import ValidationAgent
from penage.app.runtime_factory import build_sandbox_agents
from penage.core.actions import Action
from penage.core.guard import ExecutionGuard, RunMode, allowed_action_types_for_mode
from penage.core.observations import Observation
from penage.core.orchestrator import Orchestrator
from penage.core.tracer import JsonlTracer
from penage.core.url_guard import UrlGuard
from penage.llm.fake import FakeLLMClient
from penage.validation.gate import ValidationGate
from penage.validation.http import HttpEvidenceValidator


HttpHandler = Callable[[Action], Observation]


class MockTools:
    """Minimal ToolRunner double: records actions, tracks aclose()."""

    def __init__(self, http_handler: Optional[HttpHandler] = None) -> None:
        self._handler = http_handler or (lambda a: Observation(ok=True, data={}))
        self.actions: list[Action] = []
        self.closed: bool = False

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        return self._handler(action)

    async def aclose(self) -> None:
        self.closed = True


def build_e2e_orchestrator(
    *,
    mode: str = "sandboxed",
    validation_mode: str = "http",
    parallel_specialists: bool = True,
    coordinator_llm: Optional[FakeLLMClient] = None,
    validation_llm: Optional[FakeLLMClient] = None,
    http_handler: Optional[HttpHandler] = None,
    tracer_path: Optional[Path] = None,
    episode_id: str = "e2e",
) -> tuple[Orchestrator, MockTools]:
    """Build a minimal Orchestrator wired with FakeLLMs for e2e testing.

    ``parallel_specialists`` is accepted for ablation symmetry; since this
    helper does not wire a :class:`SpecialistManager`, the flag is stored
    on the returned orchestrator via its sandbox_agents dict only.
    """
    _ = parallel_specialists  # surfaced in call signature for ablation matrix

    run_mode = RunMode(mode)
    llm = coordinator_llm or FakeLLMClient(fixed_text='{"actions":[],"stop":true,"stop_reason":"noop"}')
    tools = MockTools(http_handler=http_handler)

    tracer = JsonlTracer(
        tracer_path or Path("/tmp") / f"{episode_id}-trace.jsonl",
        episode_id=episode_id,
    )

    agent: Optional[ValidationAgent] = None
    if validation_mode == "agent":
        agent_llm = validation_llm or FakeLLMClient(
            fixed_text='{"verdict":"pass","reason":"ok"}'
        )
        agent = ValidationAgent.build(llm=agent_llm)

    gate = ValidationGate(
        http_validator=HttpEvidenceValidator(),
        validation_agent=agent,
        validation_mode=validation_mode,
    )

    orch = Orchestrator(
        llm=llm,
        tools=tools,
        tracer=tracer,
        guard=ExecutionGuard(allowed=allowed_action_types_for_mode(run_mode)),
        url_guard=UrlGuard(block_static_assets=False),
        validation_gate=gate,
        sandbox_agents=build_sandbox_agents(llm),
    )
    return orch, tools
