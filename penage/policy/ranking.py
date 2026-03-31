from __future__ import annotations

from dataclasses import dataclass
from typing import List

from penage.core.actions import Action
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.policy.helpers import action_family, action_path, is_logout_action
from penage.policy.scoring import PolicyScoreContext, PolicyScoringConfig, adjust_score
from penage.utils.fingerprint import action_fingerprint


@dataclass(frozen=True, slots=True)
class RankedAction:
    action: Action
    source: str
    source_name: str
    raw_score: float
    adjusted_score: float
    cost: float
    family: str
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class PolicyBlockStats:
    blocked_logout: int = 0
    blocked_repeat: int = 0
    blocked_negative: int = 0
    blocked_cooldown: int = 0

    def with_inc(self, field_name: str) -> "PolicyBlockStats":
        vals = {
            "blocked_logout": self.blocked_logout,
            "blocked_repeat": self.blocked_repeat,
            "blocked_negative": self.blocked_negative,
            "blocked_cooldown": self.blocked_cooldown,
        }
        vals[field_name] = int(vals[field_name]) + 1
        return PolicyBlockStats(**vals)


@dataclass(frozen=True, slots=True)
class PolicyRankResult:
    ranked: List[RankedAction]
    stats: PolicyBlockStats
    score_context: PolicyScoreContext


@dataclass(slots=True)
class PolicyRanker:
    specialist_threshold: float
    llm_base_score: float
    llm_rank_decay: float
    force_breakout_no_new_paths: int
    family_cooldown_same_streak: int
    specialist_source_streak_penalty: float

    def build_score_context(self, state: State) -> PolicyScoreContext:
        recent_failure_paths = {
            str(item.get("path"))
            for item in state.recent_failures[-state.recent_failures_limit :]
            if isinstance(item, dict) and item.get("path")
        }
        recent_failure_fams = {
            str(item.get("family"))
            for item in state.recent_failures[-state.recent_failures_limit :]
            if isinstance(item, dict) and item.get("family")
        }
        neg_fams = {str(x) for x in state.research_negative_families[-20:] if isinstance(x, str)}
        return PolicyScoreContext(
            recent_failure_paths=recent_failure_paths,
            recent_failure_fams=recent_failure_fams,
            neg_fams=neg_fams,
        )

    def rank(
        self,
        *,
        state: State,
        llm_actions: List[Action],
        specialist_candidates: List[CandidateAction],
        scoring_cfg: PolicyScoringConfig,
    ) -> PolicyRankResult:
        ranked: list[RankedAction] = []
        stats = PolicyBlockStats()
        score_context = self.build_score_context(state)

        neg_paths = {str(x) for x in state.research_negatives[-30:] if isinstance(x, str)}
        no_new = int(state.no_new_paths_streak or 0)
        specialist_streak = int(state.same_policy_source_streak or 0) if state.last_policy_source == "specialists" else 0

        for c in specialist_candidates:
            maybe = self._rank_specialist_candidate(
                state=state,
                candidate=c,
                scoring_cfg=scoring_cfg,
                score_context=score_context,
                neg_paths=neg_paths,
                no_new=no_new,
                specialist_streak=specialist_streak,
            )
            if maybe is None:
                reason = self._block_reason_for_candidate(state=state, candidate=c, neg_paths=neg_paths, no_new=no_new)
                if reason:
                    stats = stats.with_inc(reason)
                continue
            ranked.append(maybe)

        for idx, action in enumerate(llm_actions):
            maybe = self._rank_llm_action(
                state=state,
                action=action,
                index=idx,
                scoring_cfg=scoring_cfg,
                score_context=score_context,
                neg_paths=neg_paths,
            )
            if maybe is None:
                reason = self._block_reason_for_llm(state=state, action=action, neg_paths=neg_paths)
                if reason:
                    stats = stats.with_inc(reason)
                continue
            ranked.append(maybe)

        return PolicyRankResult(ranked=ranked, stats=stats, score_context=score_context)

    def _block_reason_for_candidate(
        self,
        *,
        state: State,
        candidate: CandidateAction,
        neg_paths: set[str],
        no_new: int,
    ) -> str | None:
        action = candidate.action
        if is_logout_action(action):
            return "blocked_logout"
        if action_fingerprint(action) in state.visited_actions_fingerprint:
            return "blocked_repeat"
        if float(candidate.score) < self.specialist_threshold:
            return None

        family = action_family(action)
        path = action_path(action)
        neg_fams = {str(x) for x in state.research_negative_families[-20:] if isinstance(x, str)}
        if path in neg_paths or family in neg_fams:
            return "blocked_negative"
        if (
            no_new >= self.force_breakout_no_new_paths
            and state.last_action_family == family
            and int(state.same_action_family_streak or 0) >= self.family_cooldown_same_streak
        ):
            return "blocked_cooldown"
        return None

    def _block_reason_for_llm(self, *, state: State, action: Action, neg_paths: set[str]) -> str | None:
        if is_logout_action(action):
            return "blocked_logout"
        if action_fingerprint(action) in state.visited_actions_fingerprint:
            return "blocked_repeat"
        family = action_family(action)
        path = action_path(action)
        neg_fams = {str(x) for x in state.research_negative_families[-20:] if isinstance(x, str)}
        if path in neg_paths and family in neg_fams:
            return "blocked_negative"
        return None

    def _rank_specialist_candidate(
        self,
        *,
        state: State,
        candidate: CandidateAction,
        scoring_cfg: PolicyScoringConfig,
        score_context: PolicyScoreContext,
        neg_paths: set[str],
        no_new: int,
        specialist_streak: int,
    ) -> RankedAction | None:
        action = candidate.action
        if is_logout_action(action):
            return None
        if action_fingerprint(action) in state.visited_actions_fingerprint:
            return None
        if float(candidate.score) < self.specialist_threshold:
            return None

        family = action_family(action)
        path = action_path(action)
        if path in neg_paths or family in score_context.neg_fams:
            return None
        if (
            no_new >= self.force_breakout_no_new_paths
            and state.last_action_family == family
            and int(state.same_action_family_streak or 0) >= self.family_cooldown_same_streak
        ):
            return None

        adjusted = adjust_score(
            cfg=scoring_cfg,
            base=float(candidate.score),
            action=action,
            family=family,
            path=path,
            state=state,
            source="specialists",
            context=score_context,
        )

        if specialist_streak >= 2 and no_new >= 2:
            adjusted -= min(8.0, self.specialist_source_streak_penalty + (specialist_streak - 2) * 1.0)

        return RankedAction(
            action=action,
            source="specialists",
            source_name=str(candidate.source),
            raw_score=float(candidate.score),
            adjusted_score=adjusted,
            cost=float(candidate.cost),
            family=family,
            path=path,
            reason=candidate.reason,
        )

    def _rank_llm_action(
        self,
        *,
        state: State,
        action: Action,
        index: int,
        scoring_cfg: PolicyScoringConfig,
        score_context: PolicyScoreContext,
        neg_paths: set[str],
    ) -> RankedAction | None:
        if is_logout_action(action):
            return None
        if action_fingerprint(action) in state.visited_actions_fingerprint:
            return None

        family = action_family(action)
        path = action_path(action)
        if path in neg_paths and family in score_context.neg_fams:
            return None

        raw = self.llm_base_score - (self.llm_rank_decay * index)
        adjusted = adjust_score(
            cfg=scoring_cfg,
            base=raw,
            action=action,
            family=family,
            path=path,
            state=state,
            source="llm",
            context=score_context,
        )

        return RankedAction(
            action=action,
            source="llm",
            source_name="llm",
            raw_score=raw,
            adjusted_score=adjusted,
            cost=1.0,
            family=family,
            path=path,
            reason="planner action",
        )