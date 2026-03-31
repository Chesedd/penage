from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from penage.core.actions import Action
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.policy.base import PolicyDecision
from penage.policy.ranking import PolicyRanker
from penage.policy.scoring import PolicyScoringConfig
from penage.policy.selection import DiverseActionSelector


@dataclass(slots=True)
class GctrLitePolicy:
    name: str = "gctr-lite"

    specialist_threshold: float = 0.0
    llm_base_score: float = 24.0
    llm_rank_decay: float = 0.35

    promoted_pivot_bonus: float = 11.0
    promoted_pivot_unrelated_penalty: float = 10.0

    macro_commitment_bonus: float = 14.0
    macro_commitment_followup_bonus: float = 16.0
    macro_unrelated_http_penalty: float = 4.0

    promoted_pivot_guessed_idor_penalty: float = 7.0

    same_family_penalty: float = 6.0
    streak_penalty: float = 1.75
    family_count_penalty: float = 1.35
    stuck_family_penalty: float = 0.90

    recent_failure_penalty: float = 3.5
    negative_family_penalty: float = 6.0
    specialist_source_streak_penalty: float = 5.0

    llm_escape_bonus: float = 3.0
    novel_family_bonus: float = 0.5
    stuck_llm_extra_bonus: float = 2.0

    force_breakout_no_new_paths: int = 3
    force_breakout_specialist_streak: int = 4
    family_cooldown_same_streak: int = 3

    ranker: PolicyRanker = field(init=False)
    selector: DiverseActionSelector = field(init=False)

    def __post_init__(self) -> None:
        self.ranker = PolicyRanker(
            specialist_threshold=self.specialist_threshold,
            llm_base_score=self.llm_base_score,
            llm_rank_decay=self.llm_rank_decay,
            force_breakout_no_new_paths=self.force_breakout_no_new_paths,
            family_cooldown_same_streak=self.family_cooldown_same_streak,
            specialist_source_streak_penalty=self.specialist_source_streak_penalty,
        )
        self.selector = DiverseActionSelector(
            force_breakout_no_new_paths=self.force_breakout_no_new_paths,
            force_breakout_specialist_streak=self.force_breakout_specialist_streak,
        )

    def _scoring_config(self) -> PolicyScoringConfig:
        return PolicyScoringConfig(
            same_family_penalty=self.same_family_penalty,
            streak_penalty=self.streak_penalty,
            family_count_penalty=self.family_count_penalty,
            stuck_family_penalty=self.stuck_family_penalty,
            recent_failure_penalty=self.recent_failure_penalty,
            negative_family_penalty=self.negative_family_penalty,
            llm_escape_bonus=self.llm_escape_bonus,
            novel_family_bonus=self.novel_family_bonus,
            stuck_llm_extra_bonus=self.stuck_llm_extra_bonus,
            promoted_pivot_bonus=self.promoted_pivot_bonus,
            promoted_pivot_unrelated_penalty=self.promoted_pivot_unrelated_penalty,
            promoted_pivot_guessed_idor_penalty=self.promoted_pivot_guessed_idor_penalty,
            macro_commitment_bonus=self.macro_commitment_bonus,
            macro_commitment_followup_bonus=self.macro_commitment_followup_bonus,
            macro_unrelated_http_penalty=self.macro_unrelated_http_penalty,
        )

    def choose_actions(
        self,
        *,
        state: State,
        llm_actions: List[Action],
        specialist_candidates: List[CandidateAction],
        actions_per_step: int,
    ) -> PolicyDecision:
        rank_result = self.ranker.rank(
            state=state,
            llm_actions=llm_actions,
            specialist_candidates=specialist_candidates,
            scoring_cfg=self._scoring_config(),
        )
        return self.selector.choose(
            state=state,
            ranked=rank_result.ranked,
            stats=rank_result.stats,
            actions_per_step=actions_per_step,
        )