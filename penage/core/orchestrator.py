from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from penage.agents.coordinator import CoordinatorAgent
from penage.core.actions import Action, ActionType
from penage.core.form_assist import FormAssist
from penage.core.guard import ExecutionGuard
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.state_updates import StateUpdater
from penage.core.tracer import JsonlTracer
from penage.core.url_guard import UrlGuard
from penage.core.usage import EarlyStopThresholds, UsageTracker
from penage.llm.base import LLMClient
from penage.macros.base import MacroExecutor
from penage.memory.store import MemoryStore
from penage.policy.base import PolicyLayer
from penage.specialists.manager import SpecialistManager
from penage.tools.runner import ToolRunner
from penage.utils.fingerprint import action_fingerprint
from penage.validation.gate import ValidationGate


StopCondition = Callable[[State], Optional[str]]


@dataclass(slots=True)
class Orchestrator:
    llm: LLMClient
    tools: ToolRunner
    tracer: JsonlTracer

    guard: Optional[ExecutionGuard] = None
    url_guard: Optional[UrlGuard] = None
    form_assist: FormAssist = field(default_factory=FormAssist)
    specialists: Optional[SpecialistManager] = None
    policy: Optional[PolicyLayer] = None
    validation_gate: Optional[ValidationGate] = None
    macro_executor: Optional[MacroExecutor] = None
    state_updater: Optional[StateUpdater] = None
    coordinator: Optional[CoordinatorAgent] = None
    memory: Optional[MemoryStore] = None

    def __post_init__(self) -> None:
        if self.state_updater is None:
            self.state_updater = StateUpdater(tracer=self.tracer)

        if self.validation_gate is None:
            from penage.validation.http import HttpEvidenceValidator
            self.validation_gate = ValidationGate(
                http_validator=HttpEvidenceValidator(),
                validation_agent=None,
                validation_mode="http",
            )

        if self.coordinator is None:
            self.coordinator = CoordinatorAgent.build(
                llm=self.llm,
                guard=self.guard,
                url_guard=self.url_guard,
                research_memory_syncer=self.state_updater,
            )

    async def run_episode(
        self,
        *,
        user_prompt: str,
        state: Optional[State] = None,
        max_steps: int = 20,
        stop_condition: Optional[StopCondition] = None,
        actions_per_step: int = 1,
        max_http_requests: Optional[int] = 30,
        max_total_text_len: Optional[int] = 200_000,
        early_stop: Optional[EarlyStopThresholds] = None,
    ) -> tuple[State, UsageTracker]:
        st = state or State()
        tracker = UsageTracker()
        self.tracer.record_note("episode_start", step=0)

        episode_stopped = False
        for step in range(1, max_steps + 1):
            st.orch_step = step

            if max_http_requests is not None and st.http_requests_used >= max_http_requests:
                self.tracer.record_note("budget_exhausted:http_requests", step=step)
                st.notes.append("budget_exhausted:http_requests")
                break

            if max_total_text_len is not None and st.total_text_len_seen >= max_total_text_len:
                self.tracer.record_note("budget_exhausted:total_text_len", step=step)
                st.notes.append("budget_exhausted:total_text_len")
                break

            if stop_condition:
                reason = stop_condition(st)
                if reason:
                    self.tracer.record_note(f"stop_condition: {reason}", step=step)
                    break

            if early_stop is not None:
                stop_reason = tracker.check_early_stop(early_stop)
                if stop_reason:
                    self.tracer.record_note(f"early_stop: {stop_reason}", step=step)
                    st.notes.append(f"early_stop:{stop_reason}")
                    episode_stopped = True
                    break

            specialist_candidates = []
            if self.specialists:
                specialist_candidates = await self.specialists.propose_all_async(st)
                self.state_updater.store_specialist_previews(st, specialist_candidates)
                self.tracer.record_note(f"specialists:candidates={len(specialist_candidates)}", step=step)

                research_preview = st.research_tracking.candidates_preview
                if research_preview:
                    self.tracer.record_note(
                        "research:proposals=" + json.dumps(research_preview[:8], ensure_ascii=False),
                        step=step,
                    )

            self.state_updater.sync_research_memory_from_facts(st)

            planning = await self.coordinator.choose_actions(
                step=step, user_prompt=user_prompt, state=st, tracker=tracker,
            )

            if planning.note:
                self.tracer.record_note(planning.note, step=step)
            if planning.stop_reason:
                self.tracer.record_note(f"planner_stop: {planning.stop_reason}", step=step)
                st.notes.append(f"stop:{planning.stop_reason}")
            chosen_actions, chosen_reason = planning.actions, planning.reason

            if self.policy is not None:
                decision = self.policy.choose_actions(
                    state=st,
                    llm_actions=chosen_actions,
                    specialist_candidates=specialist_candidates,
                    actions_per_step=actions_per_step,
                )
                st.policy_name = getattr(self.policy, "name", "policy")
                st.policy_chosen_source = decision.chosen_source

                st.policy_source_counts[decision.chosen_source] = int(st.policy_source_counts.get(decision.chosen_source) or 0) + 1
                if st.last_policy_source == decision.chosen_source:
                    st.same_policy_source_streak += 1
                else:
                    st.same_policy_source_streak = 1
                st.last_policy_source = decision.chosen_source

                self.tracer.record_note(f"policy:{decision.chosen_source}:{decision.reason}", step=step)

                chosen_actions = decision.chosen
                chosen_reason = None if chosen_actions else "policy_returned_no_actions"

            if not chosen_actions:
                self.tracer.record_note(chosen_reason or "no_action_selected", step=step)
                st.notes.append(chosen_reason or "no_action_selected")
                break

            batch = chosen_actions[: max(1, actions_per_step)]
            for a in batch:
                if max_http_requests is not None and st.http_requests_used >= max_http_requests:
                    self.tracer.record_note("budget_exhausted:http_requests", step=step)
                    st.notes.append("budget_exhausted:http_requests")
                    break

                if max_total_text_len is not None and st.total_text_len_seen >= max_total_text_len:
                    self.tracer.record_note("budget_exhausted:total_text_len", step=step)
                    st.notes.append("budget_exhausted:total_text_len")
                    break

                self.tracer.record_action(a, step=step, agent="coordinator")

                a = self.form_assist.normalize_http_post(a, st)

                st.tool_calls_total += 1
                if a.type == ActionType.HTTP:
                    st.tool_calls_http += 1
                elif a.type in (ActionType.SHELL, ActionType.PYTHON, ActionType.MACRO):
                    st.tool_calls_sandbox += 1

                if a.type == ActionType.MACRO:
                    if self.macro_executor is None:
                        obs = Observation(ok=False, error="macro_executor_not_configured")
                    else:
                        obs = await self.macro_executor.run(
                            a,
                            state=st,
                            step=step,
                            tools=self.tools,
                            tracer=self.tracer,
                        )
                else:
                    obs = await self.tools.run(a)

                self.tracer.record_observation(obs, step=step)

                duration_s = (obs.elapsed_ms / 1000.0) if obs.elapsed_ms is not None else 0.0
                if obs.elapsed_ms is not None:
                    st.tool_elapsed_ms_total += int(obs.elapsed_ms)
                tracker.record_tool_call("coordinator", duration_s)

                self.tracer.record_note(
                    f"usage:llm={st.llm_calls} tools={st.tool_calls_total} http={st.tool_calls_http} sb={st.tool_calls_sandbox} ms={st.tool_elapsed_ms_total}",
                    step=step,
                )

                self.state_updater.update_state(st, a, obs)
                vres = await self.validation_gate.validate(
                    action=a, obs=obs, state=st, tracker=tracker,
                )
                if vres is not None:
                    self.state_updater.validation_recorder.record(st, a, vres, step=step)

                if self.memory is not None:
                    self._record_memory_attempt(a, obs, st)

        self.tracer.record_note("episode_end", step=max_steps)
        return st, tracker

    def _record_memory_attempt(self, action: Action, obs: Observation, st: State) -> None:
        from urllib.parse import urlparse

        params = action.params or {}
        host = ""
        parameter = ""

        if action.type == ActionType.HTTP:
            url = str(params.get("url") or "")
            try:
                parsed = urlparse(url)
                host = (parsed.netloc or "").lower()
                parameter = parsed.path or "/"
            except Exception:  # LEGACY: URL parse can fail on malformed LLM output
                host = ""
                parameter = url

        payload_fp = action_fingerprint(action)

        if obs.ok:
            if st.last_validation is not None and st.last_validation.get("level") == "validated":
                outcome = f"validated:{st.last_validation.get('kind') or ''}"
            else:
                status = obs.data.get("status_code") if isinstance(obs.data, dict) else None
                outcome = f"ok:{status}" if status is not None else "ok"
        else:
            outcome = f"error:{obs.error or 'unknown'}"

        self.memory.record_attempt(
            episode_id=self.tracer.episode_id,
            host=host,
            parameter=parameter,
            payload=payload_fp,
            outcome=outcome,
        )