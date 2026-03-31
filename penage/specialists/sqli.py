from __future__ import annotations

from dataclasses import dataclass
from typing import List

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig


@dataclass(slots=True)
class SqliSpecialist:
    name: str = "sqli"

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        return []