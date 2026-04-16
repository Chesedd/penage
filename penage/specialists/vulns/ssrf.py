from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import yaml

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import FilterModel, State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.oob_listener import OobHit, OobListener
from penage.specialists.shared.payload_mutator import PayloadMutator
from penage.specialists.shared.reflection_analyzer import (
    ReflectionContext,
    ReflectionContextType,
)
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "ssrf.yaml"

_SKIP_INPUT_TYPES = frozenset(
    {"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"}
)

_URL_PARAM_HINTS: tuple[str, ...] = (
    "url", "uri", "link", "src", "avatar", "image", "fetch", "webhook",
    "callback", "redirect", "proxy", "import", "host", "endpoint", "feed",
    "rss", "dest", "target",
)

_URL_VALUE_PREFIXES: tuple[str, ...] = ("http://", "https://", "//", "file://", "ftp://")

_PHASE3_CATEGORIES: tuple[str, ...] = (
    "internal-loopback",
    "metadata-aws",
    "metadata-gcp",
    "metadata-azure",
    "scheme-bypass",
)

_FALLBACK_MARKERS: tuple[str, ...] = (
    "root:x:0:0",
    "instance-id",
    "ami-",
    "computeMetadata",
    "redis_version",
    "STAT version",
    "[fonts]",
)

_MAX_PHASE3_TOTAL_HTTP = 12

_BASELINE_PROBE_URL = "http://0.0.0.0:1/"

_BLOCKED_STATUS_CODES = frozenset({400, 403, 502})

_SCHEME_RE_BY_PAYLOAD = (
    ("file://", "file://"),
    ("gopher://", "gopher://"),
    ("dict://", "dict://"),
    ("ftp://", "ftp://"),
)

_OUTBOUND_LATENCY_RATIO = 2.0


@dataclass(slots=True)
class _SsrfTarget:
    url: str
    parameter: str
    channel: str  # "GET" | "POST"


class _BudgetedHttpTool:
    """Caps a specialist's HTTP usage while still bumping the global counters."""

    def __init__(self, inner: HttpBackend, state: State, cap: int) -> None:
        self._inner = inner
        self._state = state
        self._cap = max(0, int(cap))
        self._used = 0

    async def run(self, action: Action) -> Observation:
        if self._used >= self._cap:
            return Observation(ok=False, error="ssrf_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"ssrf_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)

    @property
    def used(self) -> int:
        return self._used


@dataclass(slots=True)
class SsrfSpecialist(AsyncSpecialist):
    """AWE-style five-phase SSRF specialist.

    Phases:
      1. Target discovery (URL-param heuristic + form/query-string scan).
      2. OOB canary probing (via shared.oob_listener).
      3. Internal-target probing (loopback + cloud metadata + scheme
         bypass; expected_marker matching). Also records a latency
         baseline via an unreachable URL for phase 5 hint scoring.
      4. LLM/deterministic payload mutation via
         :class:`PayloadMutator` using a synthetic SSRF context and a
         filter model built from the schemes blocked in phase 3.
      5. Evidence gating & finalization. Emits verified findings as-is;
         when only partial signals exist (response markers, 5xx after a
         scheme-bypass, or an ``outbound_request_suspected`` latency
         hint), emits an unverified candidate finding.

    A finding is verified only if (a) the OOB listener observed an
    incoming request carrying our token, or (b) a payload produced an
    in-body marker uniquely tied to an internal resource. Anything
    weaker ships as ``verified=False`` so the validation gate
    (CLAUDE.md invariant #4) stays intact.
    """

    name: ClassVar[str] = "ssrf"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None
    oob_listener: OobListener | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 30
    max_targets: int = 3
    min_reserve_http: int = 10
    oob_wait_s: float = 5.0
    max_internal_probes: int = 8
    max_mutation_payloads: int = 4

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _phase3_http_used: int = field(default=0, init=False)
    _payload_entries_cache: list[dict[str, Any]] | None = field(default=None, init=False)

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        return []

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        if self._done or self.http_tool is None or self.llm_client is None:
            return self._emit_if_any()

        targets = self._discover_targets(state)
        if not targets:
            return []

        if self.max_http_budget < self.min_reserve_http:
            self._note(f"ssrf:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < 1:
                self._note(f"ssrf:budget_low remaining={budgeted.remaining}")
                break

            finding = await self._run_pipeline(
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
        mode = finding.get("mode") or "none"

        if finding.get("verified"):
            score = 13.0 if mode == "oob" else 11.0
            kind = finding.get("kind") or "ssrf_finding"
            tags = ["ssrf", "verified", mode]
            action = Action(
                type=ActionType.NOTE,
                params={"kind": kind, "finding": finding},
                tags=tags,
            )
            return [
                CandidateAction(
                    action=action,
                    source=self.name,
                    score=score,
                    cost=0.0,
                    reason=finding.get("summary") or "SSRF finding",
                    metadata={"evidence": finding},
                )
            ]

        score = 4.0
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "ssrf_candidate", "finding": finding},
            tags=["ssrf", "unverified", mode],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=score,
                cost=0.0,
                reason=finding.get("summary") or "SSRF candidate",
                metadata={"evidence": finding},
            )
        ]

    async def _run_pipeline(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        config: SpecialistConfig,
    ) -> dict[str, Any] | None:
        host = _host_of(target.url)
        phase_results: dict[str, Any] = {
            "oob_token": None,
            "oob_probe_url": None,
            "latency_with_oob": None,
            "baseline_ms": None,
            "markers_matched": [],
            "http_status": None,
            "response_excerpt": "",
            "blocked_schemes": set(),
            "http_5xx_after_bypass": False,
            "mutation_attempts": 0,
            "mutation_candidates_generated": 0,
            "step": step,
        }

        # --- Phase 1 -----------------------------------------------------
        self._trace_phase(
            1,
            "target_discovery",
            step=step,
            target=target,
        )

        # --- Phase 2: OOB canary probing --------------------------------
        oob_finding = await self._run_oob_phase(
            target=target,
            http_tool=http_tool,
            step=step,
            host=host,
            phase_results=phase_results,
        )
        if oob_finding is not None:
            return self._finalize(target, oob_finding, phase_results)

        # --- Phase 3: internal-target probing ---------------------------
        if http_tool.remaining < 1:
            self._note("ssrf:budget_exhausted_before_phase3")
            return self._finalize(target, None, phase_results)

        internal_finding = await self._run_internal_phase(
            target=target,
            http_tool=http_tool,
            step=step,
            host=host,
            phase_results=phase_results,
        )
        if internal_finding is not None:
            return self._finalize(target, internal_finding, phase_results)

        # --- Phase 4: payload mutation ----------------------------------
        mutation_finding: dict[str, Any] | None = None
        if http_tool.remaining >= self.min_reserve_http:
            mutation_finding = await self._run_mutation_phase(
                target=target,
                http_tool=http_tool,
                step=step,
                host=host,
                config=config,
                phase_results=phase_results,
            )
        else:
            self._note(
                f"ssrf:mutation_skipped_budget_low remaining={http_tool.remaining}"
            )

        # --- Phase 5: finalization --------------------------------------
        return self._finalize(target, mutation_finding, phase_results)

    async def _run_oob_phase(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        host: str,
        phase_results: dict[str, Any],
    ) -> dict[str, Any] | None:
        listener = self.oob_listener
        if listener is None or not listener.is_running:
            self._note("ssrf:oob_listener_unavailable")
            return None

        if http_tool.remaining < 1:
            self._note("ssrf:budget_exhausted_before_phase2")
            return None

        try:
            token, probe_url = await listener.register_token()
        except Exception as exc:
            logger.warning("ssrf oob register_token failed: %s", exc)
            self._note(f"ssrf:oob_register_failed:{exc}")
            return None

        phase_results["oob_token"] = token
        phase_results["oob_probe_url"] = probe_url

        self._trace_phase(
            2,
            "oob_canary_probes",
            step=step,
            target=target,
            extra={
                "target_url": target.url,
                "token_count": 1,
            },
        )

        probe_action = _build_probe_action(target, probe_url)

        shoot_coro = http_tool.run(probe_action)
        wait_coro = listener.wait_for_hit(token, self.oob_wait_s)

        shoot_result, hit = await asyncio.gather(shoot_coro, wait_coro, return_exceptions=True)

        if isinstance(hit, Exception):
            logger.warning("ssrf oob wait_for_hit failed: %s", hit)
            hit = None
        if isinstance(shoot_result, Exception):
            logger.warning("ssrf oob probe shoot failed: %s", shoot_result)
            shoot_obs: Observation = Observation(ok=False, error=f"ssrf:phase2_error:{shoot_result}")
        else:
            shoot_obs = shoot_result  # type: ignore[assignment]

        response_text = _response_text(shoot_obs)
        latency_ms = _elapsed_ms(shoot_obs)
        if latency_ms is not None:
            phase_results["latency_with_oob"] = latency_ms

        if isinstance(hit, OobHit):
            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=probe_url,
                outcome="verified_oob",
            )
            return {
                "verified": True,
                "kind": "ssrf_oob",
                "mode": "oob",
                "parameter": target.parameter,
                "payload": probe_url,
                "channel": target.channel,
                "url": target.url,
                "evidence": {
                    "mode": "oob",
                    "oob_hit": {"remote_addr": hit.remote_addr, "path": hit.path},
                    "response_markers": [],
                    "http_status": _status_of(shoot_obs),
                    "response_excerpt": response_text[:500],
                    "hints": [],
                    "latency_ms": latency_ms,
                    "baseline_ms": phase_results.get("baseline_ms"),
                },
                "mutation_attempts": 0,
                "summary": (
                    f"SSRF verified via OOB callback on {target.parameter} "
                    f"(remote={hit.remote_addr})"
                ),
                "reason": None,
            }

        self._record_attempt(
            host=host,
            parameter=target.parameter,
            payload=probe_url,
            outcome="no_signal",
        )
        return None

    async def _run_internal_phase(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        host: str,
        phase_results: dict[str, Any],
    ) -> dict[str, Any] | None:
        # Baseline probe — one HTTP call with an unreachable URL so phase 5
        # can compare phase-2 OOB latency against this lower bound.
        if http_tool.remaining >= 1:
            baseline_action = _build_probe_action(target, _BASELINE_PROBE_URL)
            baseline_obs = await http_tool.run(baseline_action)
            self._phase3_http_used += 1
            baseline_ms = _elapsed_ms(baseline_obs)
            if baseline_ms is not None:
                phase_results["baseline_ms"] = baseline_ms
            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=_BASELINE_PROBE_URL,
                outcome="baseline",
            )

        entries = self._select_internal_payloads(self.max_internal_probes)
        if not entries:
            self._trace_phase(
                3,
                "internal_probing",
                step=step,
                target=target,
                extra={"probes_sent": 0, "markers_matched": []},
            )
            return None

        probes_sent = 0
        markers_matched: list[str] = []
        verified_finding: dict[str, Any] | None = None
        blocked_schemes: set[str] = phase_results["blocked_schemes"]

        for entry in entries:
            if self._phase3_http_used >= _MAX_PHASE3_TOTAL_HTTP:
                break
            if http_tool.remaining < 1:
                break

            payload = str(entry.get("payload") or "")
            if not payload:
                continue
            expected = entry.get("expected_marker")
            expected_s = str(expected) if expected is not None else None

            probe_action = _build_probe_action(target, payload)
            obs = await http_tool.run(probe_action)
            self._phase3_http_used += 1
            probes_sent += 1

            text = _response_text(obs)
            status = _status_of(obs)
            phase_results["http_status"] = status
            if text:
                phase_results["response_excerpt"] = text[:500]

            scheme = _scheme_of(payload)
            category = str(entry.get("category") or "")
            if (
                scheme is not None
                and category == "scheme-bypass"
                and status in _BLOCKED_STATUS_CODES
            ):
                blocked_schemes.add(scheme)
            if (
                category == "scheme-bypass"
                and status is not None
                and 500 <= status < 600
            ):
                phase_results["http_5xx_after_bypass"] = True

            matched = _find_markers(text, expected_s)

            if matched:
                markers_matched.extend(matched)
                outcome = "verified_metadata"
                verified_finding = {
                    "verified": True,
                    "kind": "ssrf_metadata_leak",
                    "mode": "internal_marker",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": target.channel,
                    "url": target.url,
                    "evidence": {
                        "mode": "internal_marker",
                        "oob_hit": None,
                        "response_markers": list(matched),
                        "http_status": status,
                        "response_excerpt": text[:500],
                        "hints": [],
                        "latency_ms": _elapsed_ms(obs),
                        "baseline_ms": phase_results.get("baseline_ms"),
                    },
                    "mutation_attempts": 0,
                    "summary": (
                        f"SSRF leaked internal marker on {target.parameter} "
                        f"(payload_id={entry.get('id')}, markers={matched})"
                    ),
                    "reason": None,
                }
            elif obs.ok:
                outcome = "no_signal"
            else:
                outcome = "blocked" if obs.error and "budget" in str(obs.error) else "error"

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=payload,
                outcome=outcome,
            )
            if verified_finding is not None:
                break

        phase_results["markers_matched"] = list(markers_matched)

        self._trace_phase(
            3,
            "internal_probing",
            step=step,
            target=target,
            extra={
                "probes_sent": probes_sent,
                "markers_matched": list(markers_matched),
                "blocked_schemes": sorted(blocked_schemes),
                "baseline_ms": phase_results.get("baseline_ms"),
            },
        )
        return verified_finding

    async def _run_mutation_phase(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        host: str,
        config: SpecialistConfig,
        phase_results: dict[str, Any],
    ) -> dict[str, Any] | None:
        if self.llm_client is None:
            return None

        context = ReflectionContext(context_type=ReflectionContextType.SSRF_URL_PARAM)

        blocked_schemes: set[str] = phase_results.get("blocked_schemes") or set()
        transformed: dict[str, str] = {s: "blocked" for s in blocked_schemes}
        filter_model = FilterModel(
            parameter=target.parameter,
            channel=target.channel,
            transformed_chars=transformed,
        )

        mutator = PayloadMutator(
            llm_client=self.llm_client,
            payload_library_path=self.payload_library_path,
        )

        max_candidates = int(getattr(config, "max_candidates", 5) or 5)
        try:
            payloads = await mutator.mutate(
                context,
                filter_model,
                max_candidates=max(1, min(max_candidates, 5)),
            )
        except Exception as exc:  # LEGACY: mutator already swallows LLM errors
            logger.warning("ssrf mutation call failed: %s", exc)
            self._note(f"ssrf:phase4_error:{exc}")
            payloads = []

        phase_results["mutation_candidates_generated"] = len(payloads)

        fired = 0
        verified_finding: dict[str, Any] | None = None
        listener = self.oob_listener
        oob_token: str | None = phase_results.get("oob_token")

        for payload in payloads[: self.max_mutation_payloads]:
            if http_tool.remaining < 1:
                self._note("ssrf:mutation_budget_exhausted")
                break

            probe_action = _build_probe_action(target, payload)
            obs = await http_tool.run(probe_action)
            fired += 1

            text = _response_text(obs)
            status = _status_of(obs)
            if text:
                phase_results["response_excerpt"] = text[:500]
            if status is not None:
                phase_results["http_status"] = status

            matched = _find_markers(text, None)

            outcome = "no_signal"

            if listener is not None and listener.is_running and oob_token:
                try:
                    hit = await listener.wait_for_hit(oob_token, 0.1)
                except Exception as exc:
                    logger.warning("ssrf phase4 oob wait failed: %s", exc)
                    hit = None
                if isinstance(hit, OobHit):
                    outcome = "verified_oob"
                    self._record_attempt(
                        host=host,
                        parameter=target.parameter,
                        payload=payload,
                        outcome=outcome,
                    )
                    phase_results["mutation_attempts"] = fired
                    verified_finding = {
                        "verified": True,
                        "kind": "ssrf_oob",
                        "mode": "oob",
                        "parameter": target.parameter,
                        "payload": payload,
                        "channel": target.channel,
                        "url": target.url,
                        "evidence": {
                            "mode": "oob",
                            "oob_hit": {"remote_addr": hit.remote_addr, "path": hit.path},
                            "response_markers": [],
                            "http_status": status,
                            "response_excerpt": text[:500],
                            "hints": [],
                            "latency_ms": _elapsed_ms(obs),
                            "baseline_ms": phase_results.get("baseline_ms"),
                        },
                        "mutation_attempts": fired,
                        "summary": (
                            f"SSRF verified via OOB callback (mutation) on "
                            f"{target.parameter} (remote={hit.remote_addr})"
                        ),
                        "reason": None,
                    }
                    break

            if matched:
                outcome = "verified_metadata"
                phase_results["markers_matched"] = list(
                    dict.fromkeys((phase_results.get("markers_matched") or []) + matched)
                )
                phase_results["mutation_attempts"] = fired
                verified_finding = {
                    "verified": True,
                    "kind": "ssrf_metadata_leak",
                    "mode": "internal_marker",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": target.channel,
                    "url": target.url,
                    "evidence": {
                        "mode": "internal_marker",
                        "oob_hit": None,
                        "response_markers": list(matched),
                        "http_status": status,
                        "response_excerpt": text[:500],
                        "hints": [],
                        "latency_ms": _elapsed_ms(obs),
                        "baseline_ms": phase_results.get("baseline_ms"),
                    },
                    "mutation_attempts": fired,
                    "summary": (
                        f"SSRF leaked internal marker on {target.parameter} "
                        f"via mutated payload (markers={matched})"
                    ),
                    "reason": None,
                }
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome=outcome,
                )
                break

            if not obs.ok:
                outcome = "error"

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=payload,
                outcome=outcome,
            )

        phase_results["mutation_attempts"] = fired
        self._trace_phase(
            4,
            "payload_mutation",
            step=step,
            target=target,
            extra={
                "candidates_generated": len(payloads),
                "payloads_fired": fired,
            },
        )
        return verified_finding

    def _finalize(
        self,
        target: _SsrfTarget,
        verified_finding: dict[str, Any] | None,
        phase_results: dict[str, Any],
    ) -> dict[str, Any] | None:
        if verified_finding is not None:
            self._trace_phase(
                5,
                "evidence_finalization",
                step=int(phase_results.get("step") or 0),
                target=target,
                extra={
                    "verified": True,
                    "mode": verified_finding.get("mode"),
                    "reason": verified_finding.get("reason"),
                },
            )
            return verified_finding

        markers = list(phase_results.get("markers_matched") or [])
        status = phase_results.get("http_status")
        http_5xx = bool(phase_results.get("http_5xx_after_bypass"))
        latency_oob = phase_results.get("latency_with_oob")
        baseline_ms = phase_results.get("baseline_ms")

        hints: list[str] = []
        if (
            isinstance(latency_oob, int)
            and isinstance(baseline_ms, int)
            and baseline_ms > 0
            and latency_oob > _OUTBOUND_LATENCY_RATIO * baseline_ms
        ):
            hints.append("outbound_request_suspected")

        has_signal = bool(markers) or http_5xx or bool(hints)
        if not has_signal:
            self._trace_phase(
                5,
                "evidence_finalization",
                step=int(phase_results.get("step") or 0),
                target=target,
                extra={"verified": False, "mode": "none", "reason": "no_signal"},
            )
            return None

        mode = "hints_only"
        reason_bits: list[str] = []
        if markers:
            mode = "internal_marker"
            reason_bits.append(f"response_markers={markers}")
        elif http_5xx:
            mode = "internal_marker"
            reason_bits.append(f"5xx_after_scheme_bypass status={status}")
        if hints:
            reason_bits.append("outbound_request_suspected")
        reason = "; ".join(reason_bits) or "partial_signal"

        mutation_attempts = int(phase_results.get("mutation_attempts") or 0)

        finding = {
            "verified": False,
            "kind": "ssrf_candidate",
            "mode": mode,
            "parameter": target.parameter,
            "payload": phase_results.get("oob_probe_url") or "",
            "channel": target.channel,
            "url": target.url,
            "evidence": {
                "mode": mode,
                "oob_hit": None,
                "response_markers": markers,
                "http_status": status,
                "response_excerpt": str(phase_results.get("response_excerpt") or ""),
                "hints": hints,
                "latency_ms": latency_oob if isinstance(latency_oob, int) else None,
                "baseline_ms": baseline_ms if isinstance(baseline_ms, int) else None,
            },
            "mutation_attempts": mutation_attempts,
            "summary": (
                f"SSRF candidate on {target.parameter} (mode={mode}, "
                f"mutation_attempts={mutation_attempts})"
            ),
            "reason": reason,
        }

        self._trace_phase(
            5,
            "evidence_finalization",
            step=int(phase_results.get("step") or 0),
            target=target,
            extra={"verified": False, "mode": mode, "reason": reason},
        )
        return finding

    # ---- target discovery ----------------------------------------------

    def _discover_targets(self, state: State) -> list[_SsrfTarget]:
        targets: list[_SsrfTarget] = []
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
                    value = str(inp.get("value") or "")
                    if not _is_ssrf_candidate(name, value):
                        continue
                    key = (action_url, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(_SsrfTarget(url=action_url, parameter=name, channel=method))

        last_url = state.last_http_url
        if last_url:
            try:
                parsed = urlparse(last_url)
            except Exception:
                parsed = None
            if parsed is not None and parsed.query:
                base = urlunparse(parsed._replace(query=""))
                for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                    if not _is_ssrf_candidate(name, value):
                        continue
                    key = (base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(_SsrfTarget(url=base, parameter=name, channel="GET"))

        return targets

    # ---- payload YAML handling -----------------------------------------

    def _load_payload_entries(self) -> list[dict[str, Any]]:
        if self._payload_entries_cache is not None:
            return self._payload_entries_cache
        try:
            with Path(self.payload_library_path).open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or []
        except Exception as exc:
            logger.warning("ssrf payload library load failed: %s", exc)
            self._payload_entries_cache = []
            return self._payload_entries_cache
        entries = [e for e in data if isinstance(e, dict)]
        self._payload_entries_cache = entries
        return entries

    def _select_internal_payloads(self, k: int) -> list[dict[str, Any]]:
        entries = self._load_payload_entries()
        by_cat: dict[str, list[dict[str, Any]]] = {cat: [] for cat in _PHASE3_CATEGORIES}
        for entry in entries:
            cat = entry.get("category")
            if cat in by_cat:
                by_cat[cat].append(entry)

        selected: list[dict[str, Any]] = []
        idx = 0
        active = [c for c in _PHASE3_CATEGORIES if by_cat.get(c)]
        while len(selected) < k and active:
            cat = active[idx % len(active)]
            bucket = by_cat[cat]
            if bucket:
                selected.append(bucket.pop(0))
                idx += 1
            if not bucket:
                active.remove(cat)
                if not active:
                    break
                # keep idx relative to new active length by not changing it;
                # modulo normalises next iteration.
        return selected

    # ---- memory / tracing ----------------------------------------------

    def _record_attempt(self, *, host: str, parameter: str, payload: str, outcome: str) -> None:
        if self.memory is None:
            return
        try:
            self.memory.record_attempt(
                episode_id=self._episode_id(),
                host=host,
                parameter=parameter,
                payload=payload,
                outcome=outcome,
            )
        except Exception as exc:
            logger.warning("ssrf memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _SsrfTarget,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if self.tracer is None:
            return
        payload: dict[str, Any] = {
            "specialist": self.name,
            "phase": phase_num,
            "phase_name": name,
            "step": step,
            "url": target.url,
            "parameter": target.parameter,
            "channel": target.channel,
        }
        if extra:
            payload.update(extra)
        try:
            self.tracer.write_event("specialist_phase", payload)
        except Exception as exc:
            logger.warning("ssrf tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("ssrf tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


# -----------------------------------------------------------------------
# module-level helpers
# -----------------------------------------------------------------------


def _is_ssrf_candidate(parameter: str, value: str) -> bool:
    lname = parameter.lower()
    if any(hint in lname for hint in _URL_PARAM_HINTS):
        return True
    v = (value or "").lower()
    return any(v.startswith(p) for p in _URL_VALUE_PREFIXES)


def _build_probe_action(target: _SsrfTarget, payload: str) -> Action:
    if target.channel == "GET":
        probe_url = _set_query_param(target.url, target.parameter, payload)
        return Action(
            type=ActionType.HTTP,
            params={
                "method": "GET",
                "url": probe_url,
                "follow_redirects": False,
                "max_redirects": 1,
            },
            timeout_s=10.0,
            tags=["ssrf", "probe"],
        )
    return Action(
        type=ActionType.HTTP,
        params={
            "method": "POST",
            "url": target.url,
            "data": {target.parameter: payload},
            "follow_redirects": False,
            "max_redirects": 1,
        },
        timeout_s=10.0,
        tags=["ssrf", "probe"],
    )


def _response_text(obs: Observation) -> str:
    if not obs.ok or not isinstance(obs.data, dict):
        return ""
    return str(obs.data.get("text_full") or obs.data.get("text_excerpt") or "")


def _status_of(obs: Observation) -> int | None:
    if not obs.ok or not isinstance(obs.data, dict):
        return None
    status = obs.data.get("status_code")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


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


def _elapsed_ms(obs: Observation) -> int | None:
    if obs.elapsed_ms is None:
        return None
    try:
        return int(obs.elapsed_ms)
    except (TypeError, ValueError):
        return None


def _scheme_of(payload: str) -> str | None:
    low = (payload or "").lower()
    for prefix, scheme in _SCHEME_RE_BY_PAYLOAD:
        if low.startswith(prefix):
            return scheme
    return None


def _find_markers(text: str, expected: str | None) -> list[str]:
    if not text:
        return []
    if expected is not None:
        return [expected] if expected and expected in text else []
    matched: list[str] = []
    for marker in _FALLBACK_MARKERS:
        if marker in text:
            matched.append(marker)
    return matched


__all__ = ["SsrfSpecialist"]
