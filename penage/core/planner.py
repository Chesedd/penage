from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from penage.core.actions import Action, ActionType
from penage.core.guard import ExecutionGuard
from penage.core.planner_context import build_planner_context
from penage.core.state import State
from penage.core.state_helpers import action_family, path_only
from penage.core.url_guard import UrlGuard
from penage.llm.base import LLMClient, LLMMessage
from penage.utils.fingerprint import action_fingerprint
from penage.utils.jsonx import parse_json_object


class ResearchMemorySyncer(Protocol):
    def sync_research_memory_from_facts(self, st: State) -> None: ...


@dataclass(frozen=True, slots=True)
class PlannerDecision:
    actions: list[Action]
    reason: Optional[str] = None
    note: Optional[str] = None
    stop_reason: Optional[str] = None


@dataclass(slots=True)
class Planner:
    llm: LLMClient
    system_prompt: str
    guard: Optional[ExecutionGuard] = None
    url_guard: Optional[UrlGuard] = None
    research_memory_syncer: Optional[ResearchMemorySyncer] = None

    async def choose_actions(
        self,
        *,
        step: int,
        user_prompt: str,
        state: State,
    ) -> PlannerDecision:
        plan_obj = await self._plan_json(
            step=step,
            user_prompt=user_prompt,
            state=state,
            extra_constraint=None,
        )
        if plan_obj is None:
            return PlannerDecision(actions=[], reason="planner_returned_invalid_json")

        note = str(plan_obj.get("note") or "").strip() or None

        if plan_obj.get("stop"):
            reason = str(plan_obj.get("stop_reason") or "planner_stop")
            return PlannerDecision(actions=[], reason=f"planner_stop:{reason}", note=note, stop_reason=reason)

        actions = self._pick_many_from_plan(plan_obj, state)
        if actions:
            return PlannerDecision(actions=actions, note=note)

        plan_obj2 = await self._plan_json(
            step=step,
            user_prompt=user_prompt,
            state=state,
            extra_constraint=(
                "All proposed actions were repeated or disallowed. "
                "Propose DIFFERENT next actions. Prefer a different action family than the recent streak. "
                "Avoid RecentFailures and ResearchNegatives. "
                "Prefer branches that already have ValidationResultsPreview evidence. "
                "Use BestHTTP*, KnownPaths, ResearchHypotheses, RecentHTTPMemory, or submit one of LastForms. "
                "Return ONLY JSON."
            ),
            compact=True,
        )
        if plan_obj2 is None:
            return PlannerDecision(actions=[], reason="planner_returned_invalid_json_after_replan", note=note)

        actions2 = self._pick_many_from_plan(plan_obj2, state)
        if actions2:
            return PlannerDecision(actions=actions2, note=note)

        return PlannerDecision(actions=[], reason="no_actions_after_guard_or_repeat_filter", note=note)

    async def _plan_json(
        self,
        *,
        step: int,
        user_prompt: str,
        state: State,
        extra_constraint: Optional[str],
        compact: bool = False,
    ) -> Optional[dict]:
        plan_text = await self._plan(
            step=step,
            user_prompt=user_prompt,
            state=state,
            extra_constraint=extra_constraint,
            compact=compact,
        )
        plan_obj = parse_json_object(plan_text)
        if not isinstance(plan_obj, dict):
            return None
        return plan_obj

    async def _plan(
        self,
        *,
        step: int,
        user_prompt: str,
        state: State,
        extra_constraint: Optional[str],
        compact: bool = False,
    ) -> str:
        if self.research_memory_syncer is not None:
            self.research_memory_syncer.sync_research_memory_from_facts(state)

        planner_context = build_planner_context(
            step=step,
            state=state,
            extra_constraint=extra_constraint,
            compact=compact,
        )

        messages = [
            LLMMessage(role="system", content=self.system_prompt),
            LLMMessage(role="user", content=user_prompt),
            LLMMessage(role="user", content=planner_context),
        ]

        state.llm_calls += 1
        resp = await self.llm.generate(messages)
        return resp.text

    def _pick_many_from_plan(self, plan_obj: dict, state: State) -> list[Action]:
        raw_actions = plan_obj.get("actions") or []
        if not raw_actions:
            return []

        candidates = [self._coerce_action(a) for a in raw_actions if isinstance(a, dict)]
        if self.guard:
            candidates = self.guard.filter(candidates)
        if self.url_guard:
            candidates = self.url_guard.filter(candidates)

        neg_paths = {path_only(x) for x in state.research_negatives[-20:]}
        neg_fams = set(state.research_negative_families[-12:])

        out: list[Action] = []
        for a in candidates:
            fp = action_fingerprint(a)
            if fp in state.visited_actions_fingerprint:
                continue

            if a.type == ActionType.HTTP:
                path = path_only(str((a.params or {}).get("url") or ""))
                fam = action_family(a)
                if path in neg_paths or fam in neg_fams:
                    continue

            out.append(a)

        return out

    def _coerce_action(self, a: dict) -> Action:
        t = str(a.get("type") or "").lower()
        try:
            at = ActionType(t)
        except Exception:
            at = ActionType.NOTE

        params = a.get("params") or {}
        timeout_s = a.get("timeout_s")
        tags = a.get("tags") or []
        return Action(type=at, params=params, timeout_s=timeout_s, tags=tags)