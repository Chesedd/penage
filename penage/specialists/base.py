from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, runtime_checkable

from penage.core.candidates import CandidateAction
from penage.core.state import State


@dataclass(frozen=True, slots=True)
class SpecialistConfig:
    enabled: bool = True
    max_candidates: int = 5


@runtime_checkable
class Specialist(Protocol):
    name: str

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        ...


@runtime_checkable
class AsyncSpecialist(Protocol):
    name: str

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        ...