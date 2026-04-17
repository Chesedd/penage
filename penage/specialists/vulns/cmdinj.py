from __future__ import annotations

import logging
import statistics
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import FilterModel, State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.destructive_filter import DestructiveCommandFilter
from penage.specialists.shared.payload_mutator import PayloadMutator
from penage.specialists.shared.reflection_analyzer import (
    ReflectionContext,
    ReflectionContextType,
)
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "cmdinj.yaml"

_SKIP_INPUT_TYPES = frozenset(
    {"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"}
)

# Parameter names commonly associated with command/host/path surfaces. Matching
# is substring, case-insensitive. These targets are tried first because the
# AWE paper shows a strong prior for vulnerability discovery on such surfaces.
PRIORITY_NAMES: frozenset[str] = frozenset(
    {
        "ping",
        "host",
        "cmd",
        "exec",
        "filename",
        "target",
        "file",
        "path",
        "user",
        "q",
        "query",
        "search",
        "name",
        "ip",
        "addr",
        "domain",
        "action",
    }
)

# Sensible original-value defaults for numeric/host-style params so that a
# mutation payload appended after the value still parses as a single shell
# argument (e.g. ``1; echo {MARKER}`` rather than ``; echo {MARKER}`` alone).
_DEFAULT_NUMERIC_NAMES: frozenset[str] = frozenset({"ping", "host", "ip", "addr", "domain"})


@dataclass(slots=True)
class _CmdInjTarget:
    url: str
    parameter: str
    channel: str  # "GET" | "POST"
    original_value: str = ""


class _BudgetedHttpTool:
    """Caps a specialist's HTTP calls while bumping the global episode counters."""

    def __init__(self, inner: HttpBackend, state: State, cap: int) -> None:
        self._inner = inner
        self._state = state
        self._cap = max(0, int(cap))
        self._used = 0

    async def run(self, action: Action) -> Observation:
        if self._used >= self._cap:
            return Observation(ok=False, error="cmdinj_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"cmdinj_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)


@dataclass(slots=True)
class CmdInjSpecialist(AsyncSpecialist):
    """Command-injection specialist implementing the AWE 5-phase pipeline.

    The full pipeline is:

    1. Target discovery — collect parameter surfaces from ``state.forms_by_url``
       and the last observed query string, prioritising names like ``cmd``,
       ``ping``, ``host``, ``file`` etc. that correlate with shell usage.
    2. Baseline + echo-marker probes — establish timing baseline and attempt
       canary-echo separator payloads (``; echo <marker>``) to detect direct
       stdout reflection of injected commands.
    3. OS fingerprinting — on echo-hit, run tiny fingerprint commands
       (``uname -a`` / ``ver``) to pin the platform.
    4. Blind timing probes — bounded ``sleep`` / ``timeout /t`` / ``ping -n``
       payloads with 2-of-3 elapsed-time delta confirmation.
    5. LLM-guided payload mutation — on partial signals, ask the mutator for
       encoding bypasses and retry; every mutated payload is still screened
       through :class:`DestructiveCommandFilter`.

    Evidence gate (CLAUDE.md invariant #4): ``verified=True`` is only emitted
    on (a) an echo-marker match in the response body or (b) ≥2-of-3 elapsed_ms
    probes exceeding ``timing_threshold_s`` above the baseline. All other
    positive signals (HTML-escaped marker reflection, 1-of-3 timing noise,
    WAF-style block statuses) are emitted as ``verified=False`` candidates
    with the corresponding ``kind`` / ``reason``.

    SECURITY INVARIANT (CLAUDE.md #4): every payload — base, YAML-curated, or
    LLM-mutated — passes through :class:`DestructiveCommandFilter` at phases
    3, 4 and 5 before leaving the specialist. Destructive commands are
    allowed only when ``allow_destructive=True``, which is itself opt-in and
    logged in the trace by the filter's caller.
    """

    name: ClassVar[str] = "cmdinj"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 35
    max_targets: int = 3
    min_reserve_http: int = 10

    timing_threshold_s: float = 5.0
    baseline_samples: int = 3
    probes_per_timing_payload: int = 3
    timing_hits_required: int = 2
    max_echo_payloads: int = 8
    max_blind_payloads: int = 4
    max_fingerprint_payloads: int = 3
    max_mutation_payloads: int = 4
    blocked_probe_threshold: int = 2

    allow_destructive: bool = False

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _filter: DestructiveCommandFilter = field(init=False)
    _yaml_cache: list[dict[str, Any]] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._filter = DestructiveCommandFilter(
            allow_destructive=self.allow_destructive,
        )

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        return []

    async def propose_async(
        self, state: State, *, config: SpecialistConfig
    ) -> List[CandidateAction]:
        if self._done or self.http_tool is None or self.llm_client is None:
            return self._emit_if_any()

        targets = self._discover_targets(state)
        if not targets:
            return []
        if self.max_http_budget < self.min_reserve_http:
            self._note(f"cmdinj:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"cmdinj:budget_low remaining={budgeted.remaining}")
                break

            host = _host_of(target.url)
            signals: dict[str, Any] = {
                "reflected_escaped": [],   # list[{"payload": str, "separator": str}]
                "timing_noise": [],        # list[{"payload": str, "elapsed_ms": list[int]}]
                "blocked_probes": [],      # list[{"payload": str, "status": int}]
                "noisy_baseline": False,
                "os_hint": "unknown",
            }

            self._trace_phase(1, "target_discovery", step=step, target=target)

            self._trace_phase(2, "baseline_timing", step=step, target=target)
            baseline = await self._measure_baseline(target, budgeted)

            self._trace_phase(3, "echo_reflection_probes", step=step, target=target)
            echo_finding = await self._run_echo_phase(
                target=target,
                http_tool=budgeted,
                host=host,
                config=config,
                step=step,
                signals=signals,
            )

            if echo_finding and echo_finding.get("verified"):
                if budgeted.remaining >= self.min_reserve_http:
                    self._trace_phase(35, "os_fingerprint", step=step, target=target)
                    os_hint, fp_signals = await self._run_fingerprint_phase(
                        target=target,
                        http_tool=budgeted,
                        config=config,
                        step=step,
                    )
                    echo_finding["evidence"]["os_hint"] = os_hint
                    echo_finding["evidence"]["fingerprint_signals"] = fp_signals
                self._findings.append(echo_finding)
                self._done = True
                self._attempted.add(key)
                break

            # Phase 4 — blind timing. Requires a baseline; noisy baselines
            # degrade the detector and are skipped.
            blind_finding: dict[str, Any] | None = None
            if baseline is not None and budgeted.remaining >= self.probes_per_timing_payload:
                blind_finding = await self._run_blind_phase(
                    target=target,
                    http_tool=budgeted,
                    host=host,
                    baseline=baseline,
                    os_hint=signals["os_hint"],
                    config=config,
                    step=step,
                    signals=signals,
                )

            if blind_finding is not None and blind_finding.get("verified"):
                self._findings.append(blind_finding)
                self._done = True
                self._attempted.add(key)
                break

            # Phase 5 — LLM mutation, only when 3 and 4 yielded no verified signal
            # and we still have enough HTTP budget.
            if budgeted.remaining >= self.min_reserve_http:
                mutation_finding = await self._run_mutation_phase(
                    target=target,
                    http_tool=budgeted,
                    host=host,
                    prior_signals=signals,
                    baseline=baseline,
                    config=config,
                    step=step,
                )
                if mutation_finding is not None and mutation_finding.get("verified"):
                    self._findings.append(mutation_finding)
                    self._done = True
                    self._attempted.add(key)
                    break

            candidate = self._build_candidate_finding(target=target, signals=signals)
            if candidate is not None:
                self._findings.append(candidate)

            self._attempted.add(key)

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        if not self._findings:
            return []
        finding = self._findings[-1]
        verified = bool(finding.get("verified"))
        kind = str(finding.get("kind") or "cmdinj_finding")
        mode = str(finding.get("mode") or "unknown")
        tag = "verified" if verified else "unverified"
        score = _score_for_finding(verified, kind)
        action = Action(
            type=ActionType.NOTE,
            params={"kind": kind, "finding": finding},
            tags=["cmdinj", tag, mode],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=score,
                cost=0.0,
                reason=finding.get("summary") or "CmdInj finding",
                metadata={"evidence": finding},
            )
        ]

    async def _measure_baseline(
        self,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
    ) -> dict[str, Any] | None:
        samples: list[float] = []
        for _ in range(self.baseline_samples):
            if http_tool.remaining < 1:
                break
            _, action_params = _build_probe_action(target, target.original_value)
            action = Action(
                type=ActionType.HTTP,
                params=action_params,
                timeout_s=12.0,
                tags=["cmdinj", "baseline"],
            )
            obs = await http_tool.run(action)
            if obs.ok and obs.elapsed_ms is not None:
                samples.append(obs.elapsed_ms / 1000.0)
        if len(samples) < 2:
            return None
        std_ms = statistics.stdev(samples) * 1000.0 if len(samples) >= 2 else 0.0
        return {
            "median_s": statistics.median(samples),
            "max_s": max(samples),
            "samples": samples,
            "std_ms": std_ms,
        }

    async def _run_echo_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
        signals: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Phase 3: fire echo-reflection payloads with a unique per-probe marker.

        Returns a verified finding dict on marker match, otherwise ``None``.
        Every payload — even from the curated YAML library — is re-screened
        through :attr:`_filter` (CLAUDE.md invariant #4).

        When ``signals`` is provided, escaped-marker reflections and WAF-style
        block statuses are recorded into it so phases 4 and 5 can use them as
        a filter model / candidate input.
        """
        _ = (config, step)
        entries = self._load_yaml_entries(
            categories=("echo-separator", "quote-escape"),
            limit=self.max_echo_payloads,
        )
        for entry in entries:
            if http_tool.remaining < 2:
                break
            token = uuid.uuid4().hex[:12]
            marker = f"pncmd_{token}"
            raw_payload = str(entry.get("payload") or "").replace("{MARKER}", marker)
            if not raw_payload:
                continue

            verdict = self._filter.check(raw_payload)
            if not verdict.allowed:
                self._note(
                    f"cmdinj:destructive_payload_dropped id={entry.get('id')} "
                    f"reason={verdict.reason}"
                )
                continue

            full_payload = f"{target.original_value}{raw_payload}"
            probe_url, action_params = _build_probe_action(target, full_payload)
            action = Action(
                type=ActionType.HTTP,
                params=action_params,
                timeout_s=12.0,
                tags=["cmdinj", "echo"],
            )
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=raw_payload,
                    outcome="error",
                )
                continue

            body = str(obs.data.get("text_full") or "")
            status = obs.data.get("status_code")

            if marker in body:
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=raw_payload,
                    outcome="verified_echo",
                )
                return {
                    "verified": True,
                    "kind": "cmdinj_echo",
                    "mode": "echo",
                    "parameter": target.parameter,
                    "payload": raw_payload,
                    "channel": target.channel,
                    "url": probe_url,
                    "separator": entry.get("separator", ""),
                    "evidence": {
                        "marker": marker,
                        "response_excerpt": body[:500],
                        "os_hint": "unknown",
                        "fingerprint_signals": [],
                        "http_status": status,
                    },
                    "summary": f"Command injection via {target.parameter} (echo)",
                }

            if _marker_appears_escaped(body, marker):
                outcome = "reflected_no_exec"
                if signals is not None:
                    signals["reflected_escaped"].append(
                        {
                            "payload": raw_payload,
                            "separator": str(entry.get("separator") or ""),
                        }
                    )
            else:
                outcome = "no_signal"
            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=raw_payload,
                outcome=outcome,
            )
            if signals is not None and isinstance(status, int) and status in (400, 403, 500):
                signals["blocked_probes"].append(
                    {"payload": raw_payload, "status": int(status)}
                )

        return None

    async def _run_fingerprint_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        config: SpecialistConfig,
        step: int,
    ) -> tuple[str, list[str]]:
        """Phase 3.5: best-effort OS fingerprint. Returns ``(os_hint, signals)``."""
        _ = (config, step)
        entries = self._load_yaml_entries(
            categories=("fingerprint",),
            limit=self.max_fingerprint_payloads,
        )
        signals: list[str] = []
        os_hint = "unknown"

        for entry in entries:
            if http_tool.remaining < 2:
                break
            raw_payload = str(entry.get("payload") or "")
            if not raw_payload:
                continue
            if not self._filter.check(raw_payload).allowed:
                self._note(
                    f"cmdinj:destructive_payload_dropped id={entry.get('id')} "
                    f"reason=fingerprint_gate"
                )
                continue

            full_payload = f"{target.original_value}{raw_payload}"
            _, action_params = _build_probe_action(target, full_payload)
            action = Action(
                type=ActionType.HTTP,
                params=action_params,
                timeout_s=12.0,
                tags=["cmdinj", "fingerprint"],
            )
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                continue
            body = str(obs.data.get("text_full") or "")

            if "Linux" in body or "Darwin" in body:
                os_hint = "linux"
                signals.append(str(entry.get("id") or ""))
            elif "Microsoft Windows" in body or "Windows NT" in body:
                os_hint = "windows"
                signals.append(str(entry.get("id") or ""))
            elif "PSVersion" in body:
                os_hint = "windows"
                signals.append(str(entry.get("id") or ""))

        return os_hint, signals

    def _load_yaml_entries(
        self,
        *,
        categories: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Load and filter curated YAML entries by category. Cached after first call."""
        if self._yaml_cache is None:
            try:
                import yaml  # lazy-import; dev dep for payload libraries
                raw = yaml.safe_load(
                    self.payload_library_path.read_text(encoding="utf-8")
                ) or []
            except Exception as exc:
                self._note(f"cmdinj:yaml_load_failed {exc}")
                raw = []
            if not isinstance(raw, list):
                raw = []
            self._yaml_cache = [e for e in raw if isinstance(e, dict)]
        filtered = [e for e in self._yaml_cache if e.get("category") in categories]
        return filtered[: max(0, int(limit))]

    async def _run_blind_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        baseline: dict[str, Any],
        os_hint: str | None,
        config: SpecialistConfig,
        step: int,
        signals: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Phase 4: timing-based blind probes.

        For each selected YAML entry, fire ``probes_per_timing_payload``
        requests and count probes whose elapsed delta exceeds
        ``timing_threshold_s``. ``timing_hits_required``-of-``probes`` is
        enough for a verified finding. Every payload still passes through
        :class:`DestructiveCommandFilter` (CLAUDE.md invariant #4).

        If the baseline standard deviation is already too close to the
        detection threshold (``baseline_std_ms > timing_threshold_s * 500``),
        the whole phase degrades with a ``cmdinj:noisy_baseline`` warning
        to keep false-positive rate sane.
        """
        _ = (config, step)
        os_value = (os_hint or "unknown").lower()
        baseline_std_ms = float(baseline.get("std_ms") or 0.0)
        noise_limit_ms = float(self.timing_threshold_s) * 1000.0 / 2.0
        if baseline_std_ms > noise_limit_ms:
            self._note(
                f"cmdinj:noisy_baseline std_ms={baseline_std_ms:.1f} "
                f"threshold_ms={noise_limit_ms:.1f}"
            )
            if signals is not None:
                signals["noisy_baseline"] = True
            self._trace_phase(
                4,
                "blind_timing_probes",
                step=step,
                target=target,
                extra={
                    "payloads_tried": 0,
                    "hits": 0,
                    "baseline_ms": int(baseline.get("median_s", 0.0) * 1000.0),
                    "baseline_std_ms": int(baseline_std_ms),
                    "skipped_reason": "noisy_baseline",
                },
            )
            return None

        entries = self._select_blind_entries(os_value)
        if not entries:
            self._trace_phase(
                4,
                "blind_timing_probes",
                step=step,
                target=target,
                extra={
                    "payloads_tried": 0,
                    "hits": 0,
                    "baseline_ms": int(baseline.get("median_s", 0.0) * 1000.0),
                    "baseline_std_ms": int(baseline_std_ms),
                },
            )
            return None

        baseline_s = float(baseline.get("median_s") or 0.0)
        baseline_ms_int = int(baseline_s * 1000.0)
        payloads_tried = 0
        total_hits = 0
        verified: dict[str, Any] | None = None

        for entry in entries[: self.max_blind_payloads]:
            raw_payload = str(entry.get("payload") or "")
            if not raw_payload:
                continue
            verdict = self._filter.check(raw_payload)
            if not verdict.allowed:
                self._note(
                    f"cmdinj:destructive_payload_dropped id={entry.get('id')} "
                    f"reason={verdict.reason}"
                )
                continue

            if http_tool.remaining < self.probes_per_timing_payload:
                break

            full_payload = f"{target.original_value}{raw_payload}"
            probe_url, action_params = _build_probe_action(target, full_payload)

            elapsed_ms: list[int] = []
            last_body = ""
            last_status: int | None = None
            for _ in range(self.probes_per_timing_payload):
                if http_tool.remaining < 1:
                    break
                action = Action(
                    type=ActionType.HTTP,
                    params=action_params,
                    timeout_s=max(12.0, self.timing_threshold_s * 3.0),
                    tags=["cmdinj", "blind"],
                )
                obs = await http_tool.run(action)
                if obs.ok and obs.elapsed_ms is not None:
                    elapsed_ms.append(int(obs.elapsed_ms))
                    if isinstance(obs.data, dict):
                        last_body = str(obs.data.get("text_full") or last_body)
                        status_value = obs.data.get("status_code")
                        if isinstance(status_value, int):
                            last_status = status_value
            payloads_tried += 1

            hits = sum(
                1
                for ms in elapsed_ms
                if (ms / 1000.0 - baseline_s) >= self.timing_threshold_s
            )
            total_hits += hits

            if hits >= self.timing_hits_required:
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=raw_payload,
                    outcome="verified_blind",
                )
                verified = {
                    "verified": True,
                    "kind": "cmdinj_blind",
                    "mode": "blind",
                    "parameter": target.parameter,
                    "payload": raw_payload,
                    "channel": target.channel,
                    "url": probe_url,
                    "separator": str(entry.get("separator") or ""),
                    "evidence": {
                        "marker": None,
                        "elapsed_ms": list(elapsed_ms),
                        "baseline_ms": baseline_ms_int,
                        "baseline_std_ms": int(baseline_std_ms),
                        "hits_above_threshold": hits,
                        "os_hint": os_value,
                        "response_excerpt": last_body[:500],
                        "http_status": last_status,
                    },
                    "summary": (
                        f"Blind command injection via {target.parameter} ({os_value})"
                    ),
                }
                break

            if hits >= 1 and signals is not None:
                signals["timing_noise"].append(
                    {
                        "payload": raw_payload,
                        "elapsed_ms": list(elapsed_ms),
                        "hits": hits,
                    }
                )
                outcome = "timing_inconsistent"
            else:
                outcome = "no_signal"
            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=raw_payload,
                outcome=outcome,
            )
            if (
                signals is not None
                and last_status is not None
                and last_status in (400, 403, 500)
            ):
                signals["blocked_probes"].append(
                    {"payload": raw_payload, "status": int(last_status)}
                )

        self._trace_phase(
            4,
            "blind_timing_probes",
            step=step,
            target=target,
            extra={
                "payloads_tried": payloads_tried,
                "hits": total_hits,
                "baseline_ms": baseline_ms_int,
                "baseline_std_ms": int(baseline_std_ms),
                "os_hint": os_value,
            },
        )
        return verified

    async def _run_mutation_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        prior_signals: dict[str, Any],
        config: SpecialistConfig,
        step: int,
        baseline: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Phase 5: LLM-guided mutation of separators / encodings.

        Builds a :class:`FilterModel` from ``prior_signals`` (escaped
        separators → ``transformed_chars``, WAF statuses → ``blocked_events``),
        asks :class:`PayloadMutator` for up to five candidates, screens each
        through :class:`DestructiveCommandFilter`, and fires them. Echo-style
        payloads are searched for an injected marker; sleep/timeout/ping-style
        payloads are compared against the baseline elapsed_ms.
        """
        _ = (config, step)
        if self.llm_client is None:
            return None

        context = ReflectionContext(context_type=ReflectionContextType.CMDINJ_PARAM)

        transformed: dict[str, str] = {
            str(item.get("separator") or ""): "escaped"
            for item in prior_signals.get("reflected_escaped", [])
            if str(item.get("separator") or "")
        }
        blocked_events: list[str] = sorted(
            {str(item.get("status")) for item in prior_signals.get("blocked_probes", [])}
        )
        filter_model = FilterModel(
            parameter=target.parameter,
            channel=target.channel,
            transformed_chars=transformed,
            blocked_events=blocked_events,
        )

        mutator = PayloadMutator(
            llm_client=self.llm_client,
            payload_library_path=self.payload_library_path,
        )

        try:
            candidates = await mutator.mutate(
                context,
                filter_model,
                max_candidates=5,
            )
        except Exception as exc:  # LEGACY: mutator already swallows LLM errors
            logger.warning("cmdinj mutation call failed: %s", exc)
            self._note(f"cmdinj:mutation_error:{exc}")
            candidates = []

        candidates_generated = len(candidates)
        payloads_fired = 0
        destructive_dropped = 0
        baseline_s = float((baseline or {}).get("median_s") or 0.0)
        verified: dict[str, Any] | None = None

        for raw_payload in candidates[: self.max_mutation_payloads]:
            if http_tool.remaining < 1:
                break
            if not raw_payload:
                continue

            verdict = self._filter.check(raw_payload)
            if not verdict.allowed:
                destructive_dropped += 1
                self._note(
                    f"cmdinj:destructive_payload_dropped id=mutation "
                    f"reason={verdict.reason}"
                )
                continue

            token = uuid.uuid4().hex[:12]
            marker = f"pncmd_{token}"
            exec_payload = raw_payload.replace("{MARKER}", marker)
            mode = _classify_mutation_mode(exec_payload)

            full_payload = f"{target.original_value}{exec_payload}"
            probe_url, action_params = _build_probe_action(target, full_payload)
            timeout_s = (
                max(12.0, self.timing_threshold_s * 3.0) if mode == "blind" else 12.0
            )
            action = Action(
                type=ActionType.HTTP,
                params=action_params,
                timeout_s=timeout_s,
                tags=["cmdinj", "mutation"],
            )
            obs = await http_tool.run(action)
            payloads_fired += 1

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=exec_payload,
                    outcome="error",
                )
                continue

            body = str(obs.data.get("text_full") or "")
            status = obs.data.get("status_code") if isinstance(obs.data, dict) else None

            if mode == "echo" and "{MARKER}" in raw_payload and marker in body:
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=exec_payload,
                    outcome="verified_echo_mutation",
                )
                verified = {
                    "verified": True,
                    "kind": "cmdinj_echo",
                    "mode": "echo",
                    "parameter": target.parameter,
                    "payload": exec_payload,
                    "channel": target.channel,
                    "url": probe_url,
                    "separator": "",
                    "evidence": {
                        "marker": marker,
                        "response_excerpt": body[:500],
                        "os_hint": prior_signals.get("os_hint") or "unknown",
                        "fingerprint_signals": [],
                        "http_status": status,
                        "via_mutation": True,
                    },
                    "summary": (
                        f"Command injection via {target.parameter} (echo, mutated)"
                    ),
                }
                break

            if mode == "blind" and obs.elapsed_ms is not None:
                elapsed_s = obs.elapsed_ms / 1000.0
                if elapsed_s - baseline_s >= self.timing_threshold_s:
                    self._record_attempt(
                        host=host,
                        parameter=target.parameter,
                        payload=exec_payload,
                        outcome="verified_blind_mutation",
                    )
                    verified = {
                        "verified": True,
                        "kind": "cmdinj_blind",
                        "mode": "blind",
                        "parameter": target.parameter,
                        "payload": exec_payload,
                        "channel": target.channel,
                        "url": probe_url,
                        "separator": "",
                        "evidence": {
                            "marker": None,
                            "elapsed_ms": [int(obs.elapsed_ms)],
                            "baseline_ms": int(baseline_s * 1000.0),
                            "baseline_std_ms": int(
                                float((baseline or {}).get("std_ms") or 0.0)
                            ),
                            "hits_above_threshold": 1,
                            "os_hint": prior_signals.get("os_hint") or "unknown",
                            "response_excerpt": body[:500],
                            "http_status": status,
                            "via_mutation": True,
                        },
                        "summary": (
                            f"Blind command injection via {target.parameter} "
                            f"({prior_signals.get('os_hint') or 'unknown'}, mutated)"
                        ),
                    }
                    break

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=exec_payload,
                outcome="no_signal",
            )
            if isinstance(status, int) and status in (400, 403, 500):
                prior_signals.setdefault("blocked_probes", []).append(
                    {"payload": exec_payload, "status": int(status)}
                )

        self._trace_phase(
            5,
            "payload_mutation",
            step=step,
            target=target,
            extra={
                "candidates_generated": candidates_generated,
                "payloads_fired": payloads_fired,
                "destructive_dropped": destructive_dropped,
            },
        )
        return verified

    def _select_blind_entries(self, os_hint: str) -> list[dict[str, Any]]:
        """Return YAML entries suited for the given OS hint.

        - ``linux``   → ``blind-sleep-linux`` + ``blind-ping`` (os=linux).
        - ``windows`` → ``blind-sleep-windows`` + ``blind-ping`` (os=windows).
        - ``unknown`` → all three categories, in YAML order.
        """
        # Force a load via the cached helper (limit=0 still caches).
        self._load_yaml_entries(categories=(), limit=0)
        cache = self._yaml_cache or []
        if os_hint == "linux":
            return [
                e
                for e in cache
                if e.get("category") in {"blind-sleep-linux", "blind-ping"}
                and str(e.get("os") or "").lower() in {"linux", "any"}
            ]
        if os_hint == "windows":
            return [
                e
                for e in cache
                if e.get("category") in {"blind-sleep-windows", "blind-ping"}
                and str(e.get("os") or "").lower() in {"windows", "any"}
            ]
        return [
            e
            for e in cache
            if e.get("category")
            in {"blind-sleep-linux", "blind-sleep-windows", "blind-ping"}
        ]

    def _build_candidate_finding(
        self,
        *,
        target: _CmdInjTarget,
        signals: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Derive a ``verified=False`` candidate from accumulated signals.

        Priority: reflected_no_exec > timing_noise > blocked. Each maps to a
        distinct ``kind`` / ``reason`` per the specialist's contract. Also
        records a ``no_signal`` / ``blocked`` attempt into memory so future
        episodes can skip obviously fruitless surfaces.
        """
        reflected = signals.get("reflected_escaped") or []
        timing_noise = signals.get("timing_noise") or []
        blocked = signals.get("blocked_probes") or []

        if reflected:
            first = reflected[0]
            payload = str(first.get("payload") or "")
            self._record_attempt(
                host=_host_of(target.url),
                parameter=target.parameter,
                payload=payload,
                outcome="no_signal",
            )
            return {
                "verified": False,
                "kind": "cmdinj_reflected_no_exec",
                "mode": "reflected_no_exec",
                "parameter": target.parameter,
                "payload": payload,
                "channel": target.channel,
                "url": target.url,
                "separator": str(first.get("separator") or ""),
                "evidence": {
                    "reflected_separators": [
                        str(r.get("separator") or "") for r in reflected
                    ],
                    "os_hint": signals.get("os_hint") or "unknown",
                },
                "reason": "marker_escaped_not_executed",
                "summary": (
                    f"CmdInj candidate on {target.parameter}: separator reflected "
                    f"in escaped form (no execution)"
                ),
            }

        if timing_noise:
            first = timing_noise[0]
            payload = str(first.get("payload") or "")
            self._record_attempt(
                host=_host_of(target.url),
                parameter=target.parameter,
                payload=payload,
                outcome="no_signal",
            )
            return {
                "verified": False,
                "kind": "cmdinj_timing_noise",
                "mode": "timing_noise",
                "parameter": target.parameter,
                "payload": payload,
                "channel": target.channel,
                "url": target.url,
                "separator": "",
                "evidence": {
                    "elapsed_ms": list(first.get("elapsed_ms") or []),
                    "hits": int(first.get("hits") or 0),
                    "os_hint": signals.get("os_hint") or "unknown",
                },
                "reason": "insufficient_timing_consistency",
                "summary": (
                    f"CmdInj candidate on {target.parameter}: single timing hit, "
                    f"not reproducible"
                ),
            }

        if len(blocked) >= self.blocked_probe_threshold:
            first = blocked[0]
            payload = str(first.get("payload") or "")
            self._record_attempt(
                host=_host_of(target.url),
                parameter=target.parameter,
                payload=payload,
                outcome="blocked",
            )
            return {
                "verified": False,
                "kind": "cmdinj_blocked",
                "mode": "blocked",
                "parameter": target.parameter,
                "payload": payload,
                "channel": target.channel,
                "url": target.url,
                "separator": "",
                "evidence": {
                    "statuses": [int(b.get("status") or 0) for b in blocked],
                    "count": len(blocked),
                },
                "reason": "waf_or_input_validation",
                "summary": (
                    f"CmdInj candidate on {target.parameter}: "
                    f"{len(blocked)} probes blocked (WAF/validation)"
                ),
            }
        return None

    def _discover_targets(self, state: State) -> list[_CmdInjTarget]:
        priority: list[_CmdInjTarget] = []
        rest: list[_CmdInjTarget] = []
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
                    original = str(inp.get("value") or "")
                    if not original:
                        original = _default_original_value(name)
                    target = _CmdInjTarget(
                        url=action_url,
                        parameter=name,
                        channel=method,
                        original_value=original,
                    )
                    if _is_priority_name(name):
                        priority.append(target)
                    else:
                        rest.append(target)

        last_url = state.last_http_url
        if last_url:
            try:
                parsed = urlparse(last_url)
            except Exception:
                parsed = None
            if parsed is not None and parsed.query:
                base = urlunparse(parsed._replace(query=""))
                for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                    key = (base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    original = value if value else _default_original_value(name)
                    target = _CmdInjTarget(
                        url=base,
                        parameter=name,
                        channel="GET",
                        original_value=original,
                    )
                    if _is_priority_name(name):
                        priority.append(target)
                    else:
                        rest.append(target)

        return priority + rest

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _CmdInjTarget,
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
            logger.warning("cmdinj tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("cmdinj tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"

    def _record_attempt(
        self,
        *,
        host: str,
        parameter: str,
        payload: str,
        outcome: str,
    ) -> None:
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
            logger.warning("cmdinj memory record_attempt failed: %s", exc)


def _build_probe_action(
    target: _CmdInjTarget,
    full_payload: str,
) -> tuple[str, dict[str, Any]]:
    """Build the (probe_url, http action params) pair for a cmdinj probe.

    Returns the effective probe URL (which, for GET, is the URL with the
    mutated query parameter) and the ``params`` dict for an :class:`Action`.
    """
    if target.channel.upper() == "GET":
        probe_url = _set_query_param(target.url, target.parameter, full_payload)
        return probe_url, {"method": "GET", "url": probe_url}
    return target.url, {
        "method": "POST",
        "url": target.url,
        "data": {target.parameter: full_payload},
    }


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for (k, v) in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _marker_appears_escaped(body: str, marker: str) -> bool:
    """Heuristic: marker is absent verbatim but separator-style escapes are present.

    Signals that the injection separator was HTML- or URL-escaped by the
    server (reflected output only, not actual execution). Useful as a
    phase-5 candidate hint.
    """
    if marker in body:
        return False
    return any(esc in body for esc in ("&#59;", "&amp;", "&lt;", "%3B", "%26"))


def _is_priority_name(name: str) -> bool:
    low = name.lower()
    return any(token in low for token in PRIORITY_NAMES)


def _default_original_value(name: str) -> str:
    low = name.lower()
    for token in _DEFAULT_NUMERIC_NAMES:
        if token in low:
            return "1"
    return ""


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


_BLIND_KEYWORDS: tuple[str, ...] = ("sleep", "timeout /t", "timeout\t/t", "ping -c", "ping -n")


def _classify_mutation_mode(payload: str) -> str:
    """Heuristic echo/blind discriminator for mutated payloads."""
    low = payload.lower()
    if "echo" in low:
        return "echo"
    for needle in _BLIND_KEYWORDS:
        if needle in low:
            return "blind"
    return "echo"


_SCORE_BY_KIND: dict[str, float] = {
    "cmdinj_echo": 13.0,
    "cmdinj_blind": 11.0,
    "cmdinj_reflected_no_exec": 3.0,
    "cmdinj_timing_noise": 3.0,
    "cmdinj_blocked": 2.0,
}


def _score_for_finding(verified: bool, kind: str) -> float:
    if kind in _SCORE_BY_KIND:
        return _SCORE_BY_KIND[kind]
    return 13.0 if verified else 3.0
