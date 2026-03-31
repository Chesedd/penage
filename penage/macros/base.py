from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.tools.runner import ToolRunner


@dataclass(slots=True)
class MacroExecutionContext:
    tools: ToolRunner
    state: State
    step: int
    tracer: Optional[JsonlTracer] = None


class Macro(Protocol):
    name: str

    async def run(self, *, args: Dict[str, Any], ctx: MacroExecutionContext) -> Observation:
        ...


@dataclass(slots=True)
class MacroExecutor:
    registry: Dict[str, Macro] = field(default_factory=dict)

    def register(self, macro: Macro) -> None:
        self.registry[macro.name] = macro

    async def run(
        self,
        action: Action,
        *,
        state: State,
        step: int,
        tools: ToolRunner,
        tracer: Optional[JsonlTracer] = None,
    ) -> Observation:
        if action.type != ActionType.MACRO:
            return Observation(ok=False, error="not_a_macro_action")

        params = action.params or {}
        name = str(params.get("name") or "").strip()
        args = params.get("args") or {}

        if not name:
            return Observation(ok=False, error="macro_missing_name")

        macro = self.registry.get(name)
        if macro is None:
            return Observation(ok=False, error=f"unknown_macro:{name}")

        if tracer is not None:
            tracer.record_macro_start(name, args if isinstance(args, dict) else {"raw": args}, step=step)

        ctx = MacroExecutionContext(tools=tools, state=state, step=step, tracer=tracer)
        result = await macro.run(args=args if isinstance(args, dict) else {"raw": args}, ctx=ctx)

        if tracer is not None and isinstance(result.data, dict):
            tracer.record_macro_result(name, result.data, step=step)

        return result