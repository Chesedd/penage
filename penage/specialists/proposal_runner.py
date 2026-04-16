from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import AsyncSpecialist, Specialist, SpecialistConfig
from penage.specialists.pipeline import record_specialist_error


@dataclass(slots=True)
class SpecialistProposalRunner:
    configs: Dict[str, SpecialistConfig] = field(default_factory=dict)

    def _config_for(self, specialist_name: str) -> SpecialistConfig:
        return self.configs.get(specialist_name, SpecialistConfig())

    def _trim(self, props: List[CandidateAction], *, cfg: SpecialistConfig) -> List[CandidateAction]:
        return (props or [])[: cfg.max_candidates]

    def run_sync(self, state: State, *, specialists: Iterable[Specialist]) -> List[CandidateAction]:
        out: List[CandidateAction] = []
        for sp in specialists:
            cfg = self._config_for(str(sp.name))
            if not cfg.enabled:
                continue
            try:
                props = sp.propose(state, config=cfg) or []
            except Exception as e:
                record_specialist_error(state, specialist_name=str(sp.name), error=e)
                continue
            out.extend(self._trim(props, cfg=cfg))
        return out

    async def run_mixed(self, state: State, *, specialists: Iterable[Specialist]) -> List[CandidateAction]:
        out: List[CandidateAction] = []
        source_counts: Dict[str, int] = {}
        for sp in specialists:
            cfg = self._config_for(str(sp.name))
            if not cfg.enabled:
                continue
            try:
                if isinstance(sp, AsyncSpecialist):
                    props = await sp.propose_async(state, config=cfg)
                else:
                    props = sp.propose(state, config=cfg) or []
            except Exception as e:
                record_specialist_error(state, specialist_name=str(sp.name), error=e)
                continue
            trimmed = self._trim(props or [], cfg=cfg)
            out.extend(trimmed)
            source_counts[str(sp.name)] = len(trimmed)
        state.specialist.source_counts_preview = dict(sorted(source_counts.items(), key=lambda kv: kv[0])[:20])
        return out