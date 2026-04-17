from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import FilterModel, State
from penage.core.tracer import JsonlTracer
from penage.core.usage import UsageTracker, current_usage_tracker
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared import (
    FilterInferrer,
    PayloadMutator,
    ReflectionAnalyzer,
    ReflectionContext,
    ReflectionContextType,
    ReflectionResult,
)
from penage.tools.http_backend import HttpBackend
from penage.validation.base import ValidationResult
from penage.validation.gate import ValidationGate

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "xss.yaml"

_SKIP_INPUT_TYPES = frozenset({"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"})


@dataclass(slots=True)
class _XssTarget:
    url: str
    parameter: str
    channel: str  # "GET" | "POST"


class _BudgetedHttpTool:
    """Wraps an HttpBackend, enforcing a specialist-local HTTP cap.

    Each successful dispatch increments the episode's HTTP counters so the
    orchestrator's global budget accounting stays accurate.
    """

    def __init__(self, inner: HttpBackend, state: State, cap: int) -> None:
        self._inner = inner
        self._state = state
        self._cap = max(0, int(cap))
        self._used = 0

    async def run(self, action: Action) -> Observation:
        if self._used >= self._cap:
            return Observation(ok=False, error="xss_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"xss_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)

    @property
    def used(self) -> int:
        return self._used


@dataclass(slots=True)
class XssSpecialist(AsyncSpecialist):
    """AWE-style five-phase XSS detection pipeline.

    Phases:
        1. Parallel canary injection (ReflectionAnalyzer).
        2. Context analysis — extract ReflectionContext per reflected canary.
        3. Filter/security inference (FilterInferrer -> FilterModel).
        4. Payload mutation (PayloadMutator, deterministic YAML + LLM).
        5. Evidence-gated verification. The probe action is marked with
           ``browser_target=True`` and routed through the shared
           :class:`ValidationGate`; the gate's browser cascade produces the
           canonical :class:`ValidationResult` (``"validated"`` for
           execution-proof, ``"evidence"`` for DOM reflection only).
           When no gate/recorder is wired (ablation), the specialist still
           emits an ``xss_unverified_reflection`` finding based on HTTP
           reflection so downstream components see the reflection signal.

    The specialist short-circuits once a verified finding is produced for the
    episode; it respects a local HTTP cap that also increments the episode's
    global HTTP counters so the orchestrator's budget stays consistent.
    """

    name: ClassVar[str] = "xss"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None
    validation_gate: ValidationGate | None = None
    validation_recorder: ValidationRecorder | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 30
    max_targets: int = 3
    min_reserve_http: int = 8

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        """Sync fallback — the real pipeline runs only via :meth:`propose_async`."""
        _ = (state, config)
        return []

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        if self._done or self.http_tool is None or self.llm_client is None:
            return self._emit_if_any()

        targets = self._discover_targets(state)
        if not targets:
            return []

        if self.max_http_budget < self.min_reserve_http:
            self._note(f"xss:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"xss:budget_low remaining={budgeted.remaining}")
                break

            finding = await self._run_pipeline(
                state=state,
                target=target,
                http_tool=budgeted,
                step=step,
                config=config,
            )
            self._attempted.add(key)
            if finding is not None:
                self._findings.append(finding)
                if finding.get("verified"):
                    self._done = True
                    break

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        if not self._findings:
            return []
        finding = self._findings[-1]
        tag = "verified" if finding.get("verified") else "unverified"
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "xss_finding", "finding": finding},
            tags=["xss", tag],
        )
        reason = finding.get("summary") or "XSS finding"
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=12.0 if finding.get("verified") else 6.0,
                cost=0.0,
                reason=reason,
                evidence_ref=finding.get("screenshot_path"),
                metadata={"evidence": finding},
            )
        ]

    async def _run_pipeline(
        self,
        *,
        state: State,
        target: _XssTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        config: SpecialistConfig,
    ) -> dict[str, Any] | None:
        host = _host_of(target.url)

        self._trace_phase(
            1,
            "canary_injection",
            step=step,
            url=target.url,
            parameter=target.parameter,
        )
        analyzer = ReflectionAnalyzer()
        try:
            reflection = await analyzer.analyze(target.url, target.parameter, http_tool)
        except Exception as exc:
            self._note(f"xss:phase1_error {exc}")
            return None

        primary_ctx = _first_real_context(reflection)
        if primary_ctx is None:
            self._trace_phase(
                2,
                "context_analysis",
                step=step,
                url=target.url,
                parameter=target.parameter,
                extra={"result": "not_reflected"},
            )
            return None

        self._trace_phase(
            2,
            "context_analysis",
            step=step,
            url=target.url,
            parameter=target.parameter,
            extra={
                "contexts": [c.context_type.value for c in reflection.contexts],
                "primary": primary_ctx.context_type.value,
                "channels": reflection.channels,
            },
        )

        if http_tool.remaining < self.min_reserve_http // 2:
            self._note("xss:budget_exhausted_before_phase3")
            return None

        self._trace_phase(
            3,
            "filter_inference",
            step=step,
            url=target.url,
            parameter=target.parameter,
        )
        channel = reflection.channels[0] if reflection.channels else target.channel
        inferrer = FilterInferrer()
        try:
            filter_model = await inferrer.infer(target.url, target.parameter, channel, http_tool)
        except Exception as exc:
            self._note(f"xss:phase3_error {exc}")
            return None

        self._record_filter_model(host=host, parameter=target.parameter, model=filter_model)

        if http_tool.remaining < 1:
            self._note("xss:budget_exhausted_before_phase4")
            return None

        self._trace_phase(
            4,
            "payload_mutation",
            step=step,
            url=target.url,
            parameter=target.parameter,
            extra={
                "allowed_tags": list(filter_model.allowed_tags),
                "blocked_tags": list(filter_model.blocked_tags),
            },
        )
        mutator = PayloadMutator(
            llm_client=self.llm_client,
            payload_library_path=self.payload_library_path,
        )
        try:
            payloads = await mutator.mutate(primary_ctx, filter_model, max_candidates=config.max_candidates or 5)
        except Exception as exc:
            self._note(f"xss:phase4_error {exc}")
            payloads = []

        if not payloads:
            self._note("xss:no_payload_candidates")
            return None

        self._trace_phase(
            5,
            "verification",
            step=step,
            url=target.url,
            parameter=target.parameter,
            extra={"candidates": len(payloads)},
        )

        return await self._verify_candidates(
            state=state,
            target=target,
            channel=channel,
            context=primary_ctx,
            payloads=payloads,
            http_tool=http_tool,
            step=step,
            host=host,
        )

    async def _verify_candidates(
        self,
        *,
        state: State,
        target: _XssTarget,
        channel: str,
        context: ReflectionContext,
        payloads: list[str],
        http_tool: _BudgetedHttpTool,
        step: int,
        host: str,
    ) -> dict[str, Any] | None:
        episode_id = self._episode_id()
        unverified: dict[str, Any] | None = None

        for payload in payloads:
            if http_tool.remaining < 1:
                self._note("xss:budget_exhausted_during_phase5")
                break

            if self._already_tried(episode_id=episode_id, host=host, parameter=target.parameter, payload=payload):
                continue

            probe_url, action_params = _build_probe_action_params(target.url, target.parameter, payload, channel)
            probe_params = dict(action_params)
            probe_params["browser_target"] = True
            probe_params["browser_payload"] = payload
            probe_params.setdefault("url", probe_url)
            probe = Action(type=ActionType.HTTP, params=probe_params, timeout_s=10.0, tags=["xss", "probe"])
            obs = await http_tool.run(probe)

            response_text = ""
            status = None
            if obs.ok and isinstance(obs.data, dict):
                response_text = str(obs.data.get("text_full") or obs.data.get("text_excerpt") or "")
                status = obs.data.get("status_code")

            reflected_http = payload in response_text

            vres = await self._run_gate(state=state, probe=probe, obs=obs, step=step)

            evidence: dict[str, Any] = {
                "url": probe_url,
                "status": status,
                "context": context.context_type.value,
                "quote_char": context.quote_char,
                "tag_parent": context.tag_parent,
            }

            verified = False
            outcome = "no_reflection"

            if vres is not None:
                evidence["browser"] = dict(vres.evidence)
                evidence["validation_level"] = vres.level
                evidence["validation_kind"] = vres.kind
                if vres.level == "validated":
                    verified = True
                    outcome = "verified"
                else:
                    outcome = "reflected"
            elif reflected_http:
                # Ablation path or gate not wired: no browser validator fired
                # but the payload is reflected in the HTTP response, so we
                # still surface an evidence-level reflection finding.
                outcome = "reflected"
                evidence["browser"] = {"available": False}

            self._record_attempt(
                episode_id=episode_id,
                host=host,
                parameter=target.parameter,
                payload=payload,
                outcome=outcome,
            )

            if verified:
                finding = {
                    "verified": True,
                    "kind": "xss_browser_verified",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": channel,
                    "url": probe_url,
                    "context": context.context_type.value,
                    "evidence": evidence,
                    "screenshot_path": None,
                    "summary": f"Browser-verified XSS on {target.parameter} via {channel}",
                }
                self._note(f"xss:verified parameter={target.parameter}")
                return finding

            reflected_any = (vres is not None) or reflected_http
            if reflected_any and unverified is None:
                unverified = {
                    "verified": False,
                    "kind": "xss_unverified_reflection",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": channel,
                    "url": probe_url,
                    "context": context.context_type.value,
                    "evidence": evidence,
                    "screenshot_path": None,
                    "summary": (
                        f"Payload reflected on {target.parameter} but browser verification "
                        f"unavailable/failed"
                    ),
                }

        _ = state
        _ = step
        return unverified

    async def _run_gate(
        self,
        *,
        state: State,
        probe: Action,
        obs: Observation,
        step: int,
    ) -> ValidationResult | None:
        """Run the probe action through the shared validation gate.

        Returns the :class:`ValidationResult` (or ``None`` if the gate has
        no opinion on the action). When a recorder is also wired, the
        result is persisted to trace and ``state.last_validation`` via the
        standard :class:`ValidationRecorder` path — the same one the
        orchestrator uses for coordinator-issued actions. Errors from the
        gate degrade silently: the specialist falls back to the HTTP
        reflection heuristic and emits an unverified finding.
        """
        if self.validation_gate is None:
            return None
        tracker = current_usage_tracker() or UsageTracker()
        try:
            result = await self.validation_gate.validate(
                action=probe, obs=obs, state=state, tracker=tracker,
            )
        except Exception as exc:  # LEGACY: browser/LLM boundary must not crash
            logger.warning("xss validation gate failed: %s", exc)
            return None
        if result is not None and self.validation_recorder is not None:
            try:
                self.validation_recorder.record(state, probe, result, step=step)
            except Exception as exc:  # LEGACY: tracer boundary
                logger.warning("xss validation recorder failed: %s", exc)
        return result

    def _discover_targets(self, state: State) -> list[_XssTarget]:
        targets: list[_XssTarget] = []
        seen: set[tuple[str, str]] = set()

        for page_url, forms in (state.forms_by_url or {}).items():
            for form in forms or []:
                action_url = str(form.get("action") or page_url or "")
                if not action_url:
                    continue
                method = str(form.get("method") or "POST").upper()
                if method not in {"GET", "POST"}:
                    continue
                for inp in form.get("inputs") or []:
                    name = str(inp.get("name") or "")
                    itype = str(inp.get("type") or "").lower()
                    if not name or itype in _SKIP_INPUT_TYPES:
                        continue
                    key = (action_url, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(_XssTarget(url=action_url, parameter=name, channel=method))

        last_url = state.last_http_url
        if last_url:
            try:
                parsed = urlparse(last_url)
            except Exception:
                parsed = None
            if parsed is not None and parsed.query:
                base = urlunparse(parsed._replace(query=""))
                for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
                    key = (base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(_XssTarget(url=base, parameter=name, channel="GET"))

        return targets

    def _already_tried(self, *, episode_id: str, host: str, parameter: str, payload: str) -> bool:
        if self.memory is None:
            return False
        try:
            return self.memory.was_tried(
                episode_id=episode_id,
                host=host,
                parameter=parameter,
                payload=payload,
            )
        except Exception as exc:
            logger.warning("memory was_tried failed: %s", exc)
            return False

    def _record_attempt(self, *, episode_id: str, host: str, parameter: str, payload: str, outcome: str) -> None:
        if self.memory is None:
            return
        try:
            self.memory.record_attempt(
                episode_id=episode_id,
                host=host,
                parameter=parameter,
                payload=payload,
                outcome=outcome,
            )
        except Exception as exc:
            logger.warning("memory record_attempt failed: %s", exc)

    def _record_filter_model(self, *, host: str, parameter: str, model: FilterModel) -> None:
        if self.memory is None:
            return
        try:
            self.memory.record_attempt(
                episode_id=self._episode_id(),
                host=host,
                parameter=parameter,
                payload="__filter_model__",
                outcome="filter_inferred",
                filters_json=json.dumps(
                    {
                        "allowed_tags": list(model.allowed_tags),
                        "blocked_tags": list(model.blocked_tags),
                        "allowed_events": list(model.allowed_events),
                        "blocked_events": list(model.blocked_events),
                        "transformed_chars": dict(model.transformed_chars),
                    }
                ),
            )
        except Exception as exc:
            logger.warning("memory filter-model persist failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        url: str,
        parameter: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if self.tracer is None:
            return
        payload: dict[str, Any] = {
            "specialist": self.name,
            "phase": phase_num,
            "phase_name": name,
            "step": step,
            "url": url,
            "parameter": parameter,
        }
        if extra:
            payload.update(extra)
        try:
            self.tracer.write_event("specialist_phase", payload)
        except Exception as exc:  # LEGACY: tracer must never crash the specialist
            logger.warning("tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _first_real_context(reflection: ReflectionResult) -> ReflectionContext | None:
    for ctx in reflection.contexts:
        if ctx.context_type != ReflectionContextType.NOT_REFLECTED:
            return ctx
    return None


def _build_probe_action_params(
    url: str, parameter: str, payload: str, channel: str
) -> tuple[str, dict[str, Any]]:
    if channel.upper() == "GET":
        probe_url = _set_query_param(url, parameter, payload)
        return probe_url, {"method": "GET", "url": probe_url}
    return url, {"method": "POST", "url": url, "data": {parameter: payload}}


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for (k, v) in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""
