from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol

from penage.core.actions import Action
from penage.core.candidates import CandidateAction
from penage.core.state import State


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    chosen: List[Action]
    reason: str
    chosen_source: str  # "specialists" | "llm" | "mixed"


class PolicyLayer(Protocol):
    name: str

    def choose_actions(
        self,
        *,
        state: State,
        llm_actions: List[Action],
        specialist_candidates: List[CandidateAction],
        actions_per_step: int,
    ) -> PolicyDecision:
        ...