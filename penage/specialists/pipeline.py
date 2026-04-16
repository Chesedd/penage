from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.utils.fingerprint import action_fingerprint


@dataclass(slots=True)
class CandidatePool:
    per_source_cap: int = 4

    def merge_unique(self, items: List[CandidateAction]) -> List[CandidateAction]:
        best_by_fp: Dict[str, CandidateAction] = {}
        for c in items:
            fp = action_fingerprint(c.action)
            prev = best_by_fp.get(fp)
            if prev is None or (c.score, -c.cost) > (prev.score, -prev.cost):
                best_by_fp[fp] = c
        out = list(best_by_fp.values())
        out.sort(key=lambda c: (c.score, -c.cost), reverse=True)
        return out

    def cap_source_dominance(self, items: List[CandidateAction]) -> List[CandidateAction]:
        counts: Dict[str, int] = {}
        out: List[CandidateAction] = []
        for c in items:
            src = str(c.source)
            used = int(counts.get(src) or 0)
            if used >= self.per_source_cap:
                continue
            counts[src] = used + 1
            out.append(c)
        return out

    def finalize(self, items: List[CandidateAction]) -> List[CandidateAction]:
        return self.cap_source_dominance(self.merge_unique(items))


def record_specialist_error(state: State, *, specialist_name: str, error: Exception) -> None:
    state.specialist.errors_preview.append(
        {
            "specialist": specialist_name,
            "error_type": type(error).__name__,
            "error": str(error)[:240],
        }
    )
    state.specialist.errors_preview = state.specialist.errors_preview[-10:]