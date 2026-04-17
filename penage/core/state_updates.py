from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from penage.core.action_tracking import ActionStateRecorder
from penage.core.actions import Action
from penage.core.observation_state import ObservationStateProjector
from penage.core.observations import Observation
from penage.core.research_state import ResearchStateSyncer
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.validation.base import EvidenceValidator


@dataclass(slots=True)
class StateUpdater:
    tracer: JsonlTracer
    validator: Optional[EvidenceValidator] = None

    action_recorder: ActionStateRecorder = field(init=False)
    research_state: ResearchStateSyncer = field(init=False)
    observation_projector: ObservationStateProjector = field(init=False)
    validation_recorder: ValidationRecorder = field(init=False)

    def __post_init__(self) -> None:
        self.action_recorder = ActionStateRecorder()
        self.research_state = ResearchStateSyncer()
        self.observation_projector = ObservationStateProjector(
            action_recorder=self.action_recorder,
            research_state=self.research_state,
        )
        self.validation_recorder = ValidationRecorder(
            tracer=self.tracer,
            validator=self.validator,
        )

    def store_specialist_previews(self, st: State, specialist_candidates: list) -> None:
        self.research_state.store_specialist_previews(st, specialist_candidates)

    def sync_research_memory_from_facts(self, st: State) -> None:
        self.research_state.sync_research_memory_from_facts(st)

    def promote_confirmed_pivot(
        self,
        st: State,
        *,
        ids: list[str],
        targets: list[str],
        source: str,
        reason: str,
        ttl_steps: int = 6,
    ) -> None:
        self.research_state.promote_confirmed_pivot(
            st,
            ids=ids,
            targets=targets,
            source=source,
            reason=reason,
            ttl_steps=ttl_steps,
        )

    async def validate_and_record(self, st: State, action: Action, obs: Observation, *, step: int) -> None:
        await self.validation_recorder.validate_and_record(st, action, obs, step=step)

    def update_state(self, st: State, action: Action, obs: Observation) -> None:
        self.observation_projector.project(st, action, obs)