from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import AsyncSpecialist, Specialist, SpecialistConfig
from penage.specialists.pipeline import record_specialist_error


@dataclass(slots=True)
class SpecialistProposalRunner:
    configs: Dict[str, SpecialistConfig] = field(default_factory=dict)
    parallel: bool = True

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

    async def _propose_one(
        self,
        sp: Specialist,
        state: State,
        cfg: SpecialistConfig,
    ) -> Tuple[str, List[CandidateAction] | None, Exception | None]:
        """Run one specialist, never raise.

        Returns a ``(name, proposals_or_None, exception_or_None)`` tuple.
        On success the proposals list is returned (possibly empty) and the
        exception slot is ``None``. On failure the proposals slot is
        ``None`` and the exception is surfaced so the caller can record it.
        """
        name = str(sp.name)
        try:
            if isinstance(sp, AsyncSpecialist):
                props = await sp.propose_async(state, config=cfg)
            else:
                props = sp.propose(state, config=cfg) or []
            return (name, props, None)
        except Exception as e:
            return (name, None, e)

    async def run_mixed(self, state: State, *, specialists: Iterable[Specialist]) -> List[CandidateAction]:
        active: List[Tuple[Specialist, SpecialistConfig]] = []
        for sp in specialists:
            cfg = self._config_for(str(sp.name))
            if not cfg.enabled:
                continue
            active.append((sp, cfg))

        if not active:
            state.specialist.source_counts_preview = {}
            return []

        if self.parallel and len(active) > 1:
            results = await asyncio.gather(
                *(self._propose_one(sp, state, cfg) for sp, cfg in active),
            )
        else:
            results = [await self._propose_one(sp, state, cfg) for sp, cfg in active]

        out: List[CandidateAction] = []
        source_counts: Dict[str, int] = {}
        for (_sp, cfg), (name, props, exc) in zip(active, results):
            if exc is not None:
                record_specialist_error(state, specialist_name=name, error=exc)
                continue
            trimmed = self._trim(props or [], cfg=cfg)
            out.extend(trimmed)
            source_counts[name] = len(trimmed)

        state.specialist.source_counts_preview = dict(
            sorted(source_counts.items(), key=lambda kv: kv[0])[:20]
        )
        return out
