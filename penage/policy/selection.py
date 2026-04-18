from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from penage.core.state import State
from penage.policy.base import PolicyDecision
from penage.policy.ranking import PolicyBlockStats, RankedAction
from penage.utils.fingerprint import action_fingerprint


def _is_specialist(ranked: RankedAction) -> bool:
    """True if `ranked` originated from a specialist rather than the LLM planner.

    ``PolicyRanker._rank_specialist_candidate`` stamps every specialist-sourced
    ``RankedAction`` with ``source="specialists"`` (the original specialist name
    — "sqli", "xss", ... — is kept in ``source_name`` for diagnostics). We key on
    the canonical bucket rather than enumerating individual specialist names so
    that new specialists auto-qualify without touching selection.py.
    """
    return ranked.source == "specialists"


@dataclass(slots=True)
class DiverseActionSelector:
    force_breakout_no_new_paths: int
    force_breakout_specialist_streak: int

    def choose(
        self,
        *,
        state: State,
        ranked: List[RankedAction],
        stats: PolicyBlockStats,
        actions_per_step: int,
    ) -> PolicyDecision:
        if not ranked:
            return PolicyDecision(
                chosen=[],
                reason=self._empty_reason(stats),
                chosen_source="llm",
            )

        k = max(1, int(actions_per_step))
        no_new = int(state.no_new_paths_streak or 0)
        specialist_streak = int(state.same_policy_source_streak or 0) if state.last_policy_source == "specialists" else 0

        llm_ranked = [r for r in ranked if r.source == "llm"]
        if (
            llm_ranked
            and no_new >= self.force_breakout_no_new_paths
            and specialist_streak >= self.force_breakout_specialist_streak
        ):
            llm_ranked.sort(key=lambda r: (r.adjusted_score, r.raw_score, -r.cost), reverse=True)
            chosen_ranked = llm_ranked[:k]
            return PolicyDecision(
                chosen=[r.action for r in chosen_ranked],
                reason=(
                    "forced_breakout:"
                    f" no_new_paths_streak={no_new}, specialist_source_streak={specialist_streak},"
                    f" blocked_logout={stats.blocked_logout}, blocked_repeat={stats.blocked_repeat},"
                    f" blocked_negative={stats.blocked_negative}, blocked_cooldown={stats.blocked_cooldown}"
                ),
                chosen_source="llm",
            )

        ranked = sorted(ranked, key=lambda r: (r.adjusted_score, r.raw_score, -r.cost), reverse=True)
        chosen_ranked = self._select_diverse(ranked, k=k)
        chosen = [r.action for r in chosen_ranked]

        chosen_sources = {r.source for r in chosen_ranked}
        if len(chosen_sources) >= 2:
            chosen_source = "mixed"
        elif chosen_sources == {"llm"}:
            chosen_source = "llm"
        else:
            chosen_source = "specialists"

        fam_preview = [r.family for r in chosen_ranked[:3]]
        reason = (
            f"ranked {len(ranked)} candidates, chose {len(chosen)} "
            f"(sources={sorted(chosen_sources)}, families={fam_preview}, "
            f"blocked_logout={stats.blocked_logout}, blocked_repeat={stats.blocked_repeat}, "
            f"blocked_negative={stats.blocked_negative}, blocked_cooldown={stats.blocked_cooldown})"
        )
        return PolicyDecision(chosen=chosen, reason=reason, chosen_source=chosen_source)

    def _empty_reason(self, stats: PolicyBlockStats) -> str:
        return (
            "no novel actions available "
            f"(blocked_logout={stats.blocked_logout}, blocked_repeat={stats.blocked_repeat}, "
            f"blocked_negative={stats.blocked_negative}, blocked_cooldown={stats.blocked_cooldown})"
        )

    def _select_diverse(self, ranked: List[RankedAction], *, k: int) -> List[RankedAction]:
        if k <= 1:
            top_specialist = next((r for r in ranked if _is_specialist(r)), None)
            if top_specialist is not None:
                return [top_specialist]
            return ranked[:1]

        chosen: list[RankedAction] = []
        used_fp: set[str] = set()
        used_families: set[str] = set()

        best_llm: Optional[RankedAction] = None
        best_spec: Optional[RankedAction] = None
        for r in ranked:
            if r.source == "llm" and best_llm is None:
                best_llm = r
            if r.source == "specialists" and best_spec is None:
                best_spec = r
            if best_llm and best_spec:
                break

        for seed in (best_spec, best_llm):
            if seed is None:
                continue
            fp = action_fingerprint(seed.action)
            if fp in used_fp or seed.family in used_families:
                continue
            chosen.append(seed)
            used_fp.add(fp)
            used_families.add(seed.family)
            if len(chosen) >= k:
                return chosen

        for r in ranked:
            fp = action_fingerprint(r.action)
            if fp in used_fp or r.family in used_families:
                continue
            chosen.append(r)
            used_fp.add(fp)
            used_families.add(r.family)
            if len(chosen) >= k:
                return chosen

        for r in ranked:
            fp = action_fingerprint(r.action)
            if fp in used_fp:
                continue
            chosen.append(r)
            used_fp.add(fp)
            if len(chosen) >= k:
                return chosen

        return chosen