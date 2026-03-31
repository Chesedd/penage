from __future__ import annotations

from dataclasses import dataclass

from penage.core.actions import Action, ActionType
from penage.core.state import State
from penage.policy.helpers import (
    action_contains_any_id,
    is_guessed_idor_path,
    is_static_path,
    macro_commitment_active,
    macro_name,
    path_matches_any_target,
    pivot_active,
)


@dataclass(frozen=True, slots=True)
class PolicyScoringConfig:
    same_family_penalty: float
    streak_penalty: float
    family_count_penalty: float
    stuck_family_penalty: float

    recent_failure_penalty: float
    negative_family_penalty: float

    llm_escape_bonus: float
    novel_family_bonus: float
    stuck_llm_extra_bonus: float

    promoted_pivot_bonus: float
    promoted_pivot_unrelated_penalty: float
    promoted_pivot_guessed_idor_penalty: float

    macro_commitment_bonus: float
    macro_commitment_followup_bonus: float
    macro_unrelated_http_penalty: float


@dataclass(frozen=True, slots=True)
class PolicyScoreContext:
    recent_failure_paths: set[str]
    recent_failure_fams: set[str]
    neg_fams: set[str]


def adjust_score(
    *,
    cfg: PolicyScoringConfig,
    base: float,
    action: Action,
    family: str,
    path: str,
    state: State,
    source: str,
    context: PolicyScoreContext,
) -> float:
    score = float(base)

    fam_count = int((state.action_family_counts or {}).get(family) or 0)
    streak = int(state.same_action_family_streak or 0)
    no_new = int(state.no_new_paths_streak or 0)

    if family and family == state.last_action_family:
        score -= cfg.same_family_penalty
        if streak > 1:
            score -= min(8.0, (streak - 1) * cfg.streak_penalty)

    if fam_count > 0:
        score -= min(7.0, fam_count * cfg.family_count_penalty)

    if fam_count > 0 and no_new > 0:
        score -= min(6.0, no_new * cfg.stuck_family_penalty)

    if path and path in context.recent_failure_paths:
        score -= cfg.recent_failure_penalty
    if family in context.recent_failure_fams:
        score -= cfg.recent_failure_penalty * 0.75
    if family in context.neg_fams:
        score -= cfg.negative_family_penalty

    if fam_count == 0:
        score += cfg.novel_family_bonus

    if source == "llm" and no_new >= 2:
        score += cfg.llm_escape_bonus
    if source == "llm" and no_new >= 5:
        score += cfg.stuck_llm_extra_bonus

    pivot_is_active = pivot_active(state)
    pivot_targets = list(getattr(state, "promoted_pivot_targets", []) or [])
    pivot_ids = list(getattr(state, "promoted_pivot_ids", []) or [])
    commitment_active = macro_commitment_active(state)

    if is_static_path(path):
        score -= 50.0

    if pivot_is_active and (pivot_targets or pivot_ids):
        matches_target = path_matches_any_target(path, pivot_targets)
        matches_id = action_contains_any_id(action, pivot_ids)

        if action.type == ActionType.MACRO:
            name = macro_name(action)
            if name == "follow_authenticated_branch":
                score += cfg.macro_commitment_followup_bonus
            elif name in ("replay_auth_session", "probe_resource_family"):
                score += cfg.macro_commitment_bonus
            else:
                score += cfg.promoted_pivot_bonus
            return score

        if matches_target:
            score += cfg.promoted_pivot_bonus
        elif matches_id:
            score += cfg.promoted_pivot_bonus * 0.5
        elif action.type == ActionType.HTTP:
            if is_guessed_idor_path(path):
                score -= cfg.promoted_pivot_guessed_idor_penalty
            score -= cfg.promoted_pivot_unrelated_penalty

    if commitment_active:
        if action.type == ActionType.MACRO:
            name = macro_name(action)
            if name == "follow_authenticated_branch":
                score += cfg.macro_commitment_followup_bonus
            elif name in ("replay_auth_session", "probe_resource_family"):
                score += cfg.macro_commitment_bonus
            else:
                score += cfg.macro_commitment_bonus * 0.5
        elif action.type == ActionType.HTTP:
            if not path or path not in ("/dashboard", "/orders", "/logout"):
                score -= cfg.macro_unrelated_http_penalty

    return score