from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import Specialist, SpecialistConfig
from penage.specialists.pipeline import CandidatePool
from penage.specialists.proposal_runner import SpecialistProposalRunner


@dataclass(slots=True)
class SpecialistManager:
    specialists: List[Specialist] = field(default_factory=list)
    configs: Dict[str, SpecialistConfig] = field(default_factory=dict)
    llm: Optional[LLMClient] = None
    memory: Optional[MemoryStore] = None
    proposal_runner: SpecialistProposalRunner = field(init=False)
    candidate_pool: CandidatePool = field(init=False)

    def __post_init__(self) -> None:
        self.proposal_runner = SpecialistProposalRunner(configs=self.configs)
        self.candidate_pool = CandidatePool(per_source_cap=4)

    def propose_all(self, state: State) -> List[CandidateAction]:
        raw = self.proposal_runner.run_sync(state, specialists=self.specialists)
        return self.candidate_pool.finalize(raw)

    async def propose_all_async(self, state: State) -> List[CandidateAction]:
        raw = await self.proposal_runner.run_mixed(state, specialists=self.specialists)
        return self.candidate_pool.finalize(raw)