from __future__ import annotations

import json
from dataclasses import dataclass

from penage.core.state import State


def clip_text(text: str, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n<...clipped...>\n"


@dataclass(frozen=True, slots=True)
class PlannerContextLimits:
    last_excerpt_limit: int
    last_full_limit: int
    best_full_limit: int
    known_paths_limit: int
    recent_http_limit: int
    recent_fail_limit: int
    hyp_limit: int
    val_limit: int

    @classmethod
    def for_mode(cls, *, compact: bool) -> "PlannerContextLimits":
        return cls(
            last_excerpt_limit=800 if compact else 1200,
            last_full_limit=2000 if compact else 4000,
            best_full_limit=4000 if compact else 8000,
            known_paths_limit=25 if compact else 40,
            recent_http_limit=1 if compact else 2,
            recent_fail_limit=3 if compact else 4,
            hyp_limit=3 if compact else 4,
            val_limit=2 if compact else 3,
        )


def build_planner_context(
    *,
    step: int,
    state: State,
    extra_constraint: str | None,
    compact: bool = False,
) -> str:
    limits = PlannerContextLimits.for_mode(compact=compact)
    context_lines = [f"Step={step}"]

    if state.base_url:
        context_lines.append(f"BaseURL={state.base_url}")

    if state.last_http_status is not None:
        context_lines.append(f"LastHTTPStatus={state.last_http_status}")
    if state.last_http_url:
        context_lines.append(f"LastHTTPUrl={state.last_http_url}")
    if state.last_http_excerpt:
        context_lines.append(f"LastHTTPExcerpt={clip_text(state.last_http_excerpt, limits.last_excerpt_limit)}")
    if state.last_http_text_full:
        context_lines.append(f"LastHTTPTextFull={clip_text(state.last_http_text_full, limits.last_full_limit)}")

    if state.best_http_url:
        context_lines.append(f"BestHTTPUrl={state.best_http_url}")
        context_lines.append(f"BestHTTPScore={state.best_http_score:.3f}")
    if state.best_http_ids:
        context_lines.append(f"BestHTTPIds={state.best_http_ids[:30]}")
    if state.best_http_paths:
        context_lines.append(f"BestHTTPPaths={state.best_http_paths[:60]}")
    if state.best_http_text_full:
        context_lines.append(f"BestHTTPTextFull={clip_text(state.best_http_text_full, limits.best_full_limit)}")

    if state.known_paths:
        context_lines.append(f"KnownPaths={sorted(list(state.known_paths))[:limits.known_paths_limit]}")

    if state.last_forms:
        context_lines.append(f"LastForms={state.last_forms[:4]}")

    best_forms = []
    if state.best_http_url:
        best_forms = state.forms_by_url.get(state.best_http_url) or []
    if best_forms:
        context_lines.append(f"BestHTTPForms={best_forms[:4]}")

    if state.recent_http_memory:
        context_lines.append(
            "RecentHTTPMemory="
            + json.dumps(state.recent_http_memory[-limits.recent_http_limit :], ensure_ascii=False)
        )

    if state.recent_failures:
        context_lines.append(
            "RecentFailures="
            + json.dumps(state.recent_failures[-limits.recent_fail_limit :], ensure_ascii=False)
        )

    if state.research_summary:
        context_lines.append(f"ResearchSummary={state.research_summary}")
    if state.research_hypotheses:
        context_lines.append(
            "ResearchHypotheses=" + json.dumps(state.research_hypotheses[: limits.hyp_limit], ensure_ascii=False)
        )
    if state.research_fuzz_paths:
        context_lines.append(f"ResearchFuzzPaths={state.research_fuzz_paths[:24]}")
    if state.research_negatives:
        context_lines.append(f"ResearchNegatives={state.research_negatives[-20:]}")
    if state.research_negative_families:
        context_lines.append(f"ResearchNegativeFamilies={state.research_negative_families[-12:]}")

    if state.last_action_family:
        context_lines.append(f"LastActionFamily={state.last_action_family}")
        context_lines.append(f"SameActionFamilyStreak={state.same_action_family_streak}")
    if state.action_family_counts:
        fam_items = sorted(state.action_family_counts.items(), key=lambda kv: kv[1], reverse=True)[:12]
        context_lines.append(f"ActionFamilyCounts={fam_items}")

    if state.policy_source_counts:
        context_lines.append(f"PolicySourceCounts={dict(sorted(state.policy_source_counts.items()))}")
    if state.last_policy_source:
        context_lines.append(f"LastPolicySource={state.last_policy_source}")
        context_lines.append(f"SamePolicySourceStreak={state.same_policy_source_streak}")

    context_lines.append(f"ValidationEvidenceCount={state.validation_evidence_count}")
    context_lines.append(f"ValidationValidatedCount={state.validation_validated_count}")
    if state.validation_results:
        context_lines.append(
            "ValidationResultsPreview="
            + json.dumps(state.validation_results[-min(len(state.validation_results), limits.val_limit):], ensure_ascii=False)
        )

    pivot_active = state.orch_step <= state.promoted_pivot_active_until_step
    if pivot_active and state.promoted_pivot_targets:
        context_lines.append(f"PromotedPivotTargets={state.promoted_pivot_targets[:8]}")
    if pivot_active and state.promoted_pivot_ids:
        context_lines.append(f"PromotedPivotIds={state.promoted_pivot_ids[:8]}")
    if pivot_active and state.promoted_pivot_source:
        context_lines.append(f"PromotedPivotSource={state.promoted_pivot_source}")
    if pivot_active and state.promoted_pivot_reason:
        context_lines.append(f"PromotedPivotReason={state.promoted_pivot_reason}")

    if state.auth.confusion_last_stats:
        context_lines.append("AuthConfusionLastStats=" + json.dumps(state.auth.confusion_last_stats, ensure_ascii=False))

    if state.auth.confusion_last_hits_preview:
        context_lines.append("AuthConfusionHitsPreview=" + json.dumps(state.auth.confusion_last_hits_preview[:4], ensure_ascii=False))

    if state.auth.confusion_winning_ids:
        context_lines.append(f"AuthConfusionWinningIds={state.auth.confusion_winning_ids[:8]}")

    if state.auth.confusion_bad_form_actions:
        context_lines.append("AuthConfusionBadFormActions=" + json.dumps(state.auth.confusion_bad_form_actions[:8], ensure_ascii=False))

    context_lines.append(f"HttpRequestsUsed={state.http_requests_used}")
    context_lines.append(f"TotalTextLenSeen={state.total_text_len_seen}")
    context_lines.append(f"NoNewPathsStreak={state.no_new_paths_streak}")

    context_lines.append(f"LLMCalls={state.llm_calls}")
    context_lines.append(f"ToolCallsTotal={state.tool_calls_total}")
    context_lines.append(f"ToolCallsHttp={state.tool_calls_http}")
    context_lines.append(f"ToolCallsSandbox={state.tool_calls_sandbox}")

    context_lines.append("AvailableMacros=['replay_auth_session','follow_authenticated_branch','probe_resource_family']")

    if state.auth.session_established:
        context_lines.append("MacroSessionEstablished=true")

    if state.macro.last_name:
        context_lines.append(f"LastMacroName={state.macro.last_name}")

    last_macro_result = state.macro.last_result
    if last_macro_result:
        context_lines.append(
            "LastMacroResult="
            + json.dumps(
                {
                    "macro_name": last_macro_result.get("macro_name"),
                    "stats": last_macro_result.get("stats"),
                    "hits": (last_macro_result.get("hits") or last_macro_result.get("meaningful_hits") or [])[:4],
                    "recommended_next": (last_macro_result.get("recommended_next") or [])[:4],
                },
                ensure_ascii=False,
            )
        )

    if extra_constraint:
        context_lines.append(f"Constraint={extra_constraint}")

    return "\n".join(context_lines) + "\nReturn JSON plan."