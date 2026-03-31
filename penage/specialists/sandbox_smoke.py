from __future__ import annotations

from dataclasses import dataclass
from typing import List

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig


@dataclass(slots=True)
class SandboxSmokeSpecialist:
    name: str = "sandbox_smoke"

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = config
        if state.tool_calls_sandbox > 0:
            return []

        a = Action(
            type=ActionType.SHELL,
            params={"command": "python -V && echo SANDBOX_OK"},
            timeout_s=30,
            tags=["sandbox", "smoke"],
        )
        return [
            CandidateAction(
                action=a,
                source=self.name,
                score=50.0,
                cost=1.0,
                reason="Verify sandbox is available (one-time probe).",
            )
        ]