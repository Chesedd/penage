from __future__ import annotations

import logging
import re
import statistics
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
from penage.specialists.shared import PayloadMutator
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "sqli.yaml"

_SKIP_INPUT_TYPES = frozenset({"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"})

# DB fingerprinting — substrings in the response body. Case-insensitive.
_BACKEND_ERROR_SIGNATURES: dict[str, tuple[str, ...]] = {
    "mysql": (
        "you have an error in your sql syntax",
        "mysql server version",
        "check the manual that corresponds to your mysql",
        "mysql_fetch_",
        "mysqli_num_rows",
        "warning: mysql",
    ),
    "postgres": (
        "postgresql",
        "pg_query",
        "unterminated quoted string at or near",
        "syntax error at or near",
        "pg::syntaxerror",
    ),
    "sqlite": (
        "sqlite3::",
        "sqlite3.operationalerror",
        "unrecognized token",
        "sql logic error",
        'near "',
    ),
    "mssql": (
        "microsoft ole db",
        "unclosed quotation mark",
        "incorrect syntax near",
        "conversion failed when converting",
        "microsoft sql server",
    ),
}

_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "mysql": re.compile(r"\b([3-9]|10)\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?", re.IGNORECASE),
    "postgres": re.compile(r"PostgreSQL\s+\d+\.\d+", re.IGNORECASE),
    "sqlite": re.compile(r"\b3\.\d+\.\d+\b"),
    "mssql": re.compile(r"Microsoft SQL Server\s+\d{4}", re.IGNORECASE),
}


@dataclass(slots=True)
class _SqliTarget:
    """Descriptor of a single parameter probe surface for the SQLi specialist.

    Fields:
      url: endpoint URL (query string may already carry context params on GET).
      parameter: name of the parameter under test; its value is mutated on each probe.
      channel: transport — ``"GET"`` (query-string) or ``"POST"`` (form body).
      baseline_params: **sibling** fields that must accompany every probe for the
        endpoint to reach its SQL execution path. For GET: extra query-string
        pairs shipped alongside ``parameter``. For POST: default form-field
        values (e.g., DVWA's ``Submit=Submit`` submit-button field — without it
        the handler early-returns before query dispatch).

    Invariant: ``parameter`` **always overrides** any sibling with the same name.
    Merge order is baseline first, probe value last (see ``_send_probe``).

    Backstory: wired up in δ.β.2.b.ii after root-cause audit of a DVWA SQLi E2E
    failure — probes without the ``Submit=Submit`` sibling never reached MySQL.
    """

    url: str
    parameter: str
    channel: str  # "GET" | "POST"
    baseline_params: dict[str, Any] = field(default_factory=dict)


class _BudgetedHttpTool:
    """Caps a specialist's HTTP calls while bumping the global episode counters."""

    def __init__(self, inner: HttpBackend, state: State, cap: int) -> None:
        self._inner = inner
        self._state = state
        self._cap = max(0, int(cap))
        self._used = 0

    async def run(self, action: Action) -> Observation:
        if self._used >= self._cap:
            return Observation(ok=False, error="sqli_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"sqli_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)


@dataclass(slots=True)
class SqliSpecialist(AsyncSpecialist):
    """Error-based + blind-timing SQL injection specialist.

    Detection phases per target parameter:

    1. Baseline timing — three no-injection requests build a median elapsed_ms
       baseline used by the blind-timing mode.
    2. Error-based probes — type-confusion payloads (quote, comment, UNION,
       integer overflow) are sent and the response is scanned for backend
       signatures. If a backend is fingerprinted, backend-specific extraction
       payloads run to pull a version string.
    3. Blind-timing probes — payloads with SLEEP / pg_sleep / WAITFOR / RANDOMBLOB
       are sent three times each; 2-of-3 elapsed_ms deltas above ``timing_threshold_s``
       counts as a positive detection.

    Validated evidence:
      - error-based: extracted version string or a strong backend signature.
      - blind:       consistent ≥2/3 timing differential.

    The specialist short-circuits once a verified finding lands for the
    episode and respects a local HTTP cap that also increments the episode's
    global HTTP counters.
    """

    name: ClassVar[str] = "sqli"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 35
    max_targets: int = 2
    min_reserve_http: int = 10

    timing_threshold_s: float = 5.0
    baseline_samples: int = 3
    probes_per_timing_payload: int = 3
    timing_hits_required: int = 2
    max_error_payloads: int = 4
    max_extraction_payloads: int = 3
    max_blind_payloads: int = 3

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)

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
            self._note(f"sqli:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"sqli:budget_low remaining={budgeted.remaining}")
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
            params={"kind": "sqli_finding", "finding": finding},
            tags=["sqli", tag, finding.get("mode", "unknown")],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=11.0 if finding.get("verified") else 5.0,
                cost=0.0,
                reason=finding.get("summary") or "SQLi finding",
                metadata={"evidence": finding},
            )
        ]

    async def _run_pipeline(
        self,
        *,
        state: State,
        target: _SqliTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        config: SpecialistConfig,
    ) -> dict[str, Any] | None:
        host = _host_of(target.url)
        _ = state

        self._trace_phase(1, "baseline_timing", step=step, target=target)
        baseline = await self._measure_baseline(target, http_tool)
        if baseline is None:
            self._note("sqli:baseline_unavailable")
            return None

        if http_tool.remaining < 2:
            return None

        self._trace_phase(
            2,
            "error_based_probes",
            step=step,
            target=target,
            extra={"baseline_ms": int(baseline["median_s"] * 1000)},
        )
        error_finding = await self._run_error_phase(
            target=target,
            http_tool=http_tool,
            host=host,
            config=config,
            step=step,
        )
        if error_finding and error_finding.get("verified"):
            return error_finding

        if http_tool.remaining < 2:
            return error_finding

        backend = error_finding.get("backend") if error_finding else None

        self._trace_phase(
            3,
            "blind_timing_probes",
            step=step,
            target=target,
            extra={"backend_hint": backend},
        )
        blind_finding = await self._run_blind_phase(
            target=target,
            http_tool=http_tool,
            host=host,
            backend=backend,
            baseline=baseline,
            config=config,
            step=step,
        )
        if blind_finding is not None:
            return blind_finding

        return error_finding

    async def _measure_baseline(
        self,
        target: _SqliTarget,
        http_tool: _BudgetedHttpTool,
    ) -> dict[str, Any] | None:
        samples: list[float] = []
        for _ in range(self.baseline_samples):
            if http_tool.remaining < 1:
                break
            action = _build_probe_action(target, "baseline")
            obs = await http_tool.run(action)
            if obs.ok and obs.elapsed_ms is not None:
                samples.append(obs.elapsed_ms / 1000.0)
        if len(samples) < 2:
            return None
        return {
            "median_s": statistics.median(samples),
            "max_s": max(samples),
            "samples": samples,
        }

    async def _run_error_phase(
        self,
        *,
        target: _SqliTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        mutator = self._build_mutator()
        try:
            probes = await mutator.mutate_by_category(
                "error_trigger",
                FilterModel(parameter=target.parameter, channel=target.channel),
                max_candidates=max(1, self.max_error_payloads),
            )
        except Exception as exc:
            self._note(f"sqli:error_mutate_failed {exc}")
            probes = []

        if not probes:
            return None

        detected_backend: str | None = None
        probe_evidence: list[dict[str, Any]] = []
        triggering_payload: str | None = None

        for payload in probes[: self.max_error_payloads]:
            if http_tool.remaining < 1:
                break
            if self._already_tried(host=host, parameter=target.parameter, payload=payload):
                continue

            obs = await http_tool.run(_build_probe_action(target, payload))
            text = _response_text(obs)
            backend = _fingerprint_backend(text)
            outcome = f"error_probe:{backend or 'none'}"
            self._record_attempt(host=host, parameter=target.parameter, payload=payload, outcome=outcome)

            probe_evidence.append(
                {
                    "payload": payload,
                    "status": _status_of(obs),
                    "backend_hit": backend,
                }
            )
            if backend is not None and detected_backend is None:
                detected_backend = backend
                triggering_payload = payload
                break

        if detected_backend is None:
            return None

        # backend detected — try extraction payloads for this backend.
        extracted: str | None = None
        extraction_payload: str | None = None
        try:
            extraction_candidates = await mutator.mutate_by_category(
                "error_extract",
                FilterModel(parameter=target.parameter, channel=target.channel),
                backend=detected_backend,
                max_candidates=max(1, self.max_extraction_payloads),
            )
        except Exception as exc:
            self._note(f"sqli:extract_mutate_failed {exc}")
            extraction_candidates = []

        for payload in extraction_candidates[: self.max_extraction_payloads]:
            if http_tool.remaining < 1:
                break
            if self._already_tried(host=host, parameter=target.parameter, payload=payload):
                continue
            obs = await http_tool.run(_build_probe_action(target, payload))
            text = _response_text(obs)
            match = _extract_version(text, detected_backend)
            outcome = f"error_extract:{detected_backend}:{'hit' if match else 'miss'}"
            self._record_attempt(host=host, parameter=target.parameter, payload=payload, outcome=outcome)

            probe_evidence.append(
                {
                    "payload": payload,
                    "status": _status_of(obs),
                    "extracted": match,
                }
            )
            if match:
                extracted = match
                extraction_payload = payload
                break

        _ = (config, step)

        verified = extracted is not None
        summary = (
            f"Error-based SQLi ({detected_backend}); extracted={extracted!r}"
            if verified
            else f"Backend fingerprinted via error signature ({detected_backend}); no data extracted"
        )
        return {
            "verified": verified,
            "mode": "error_based",
            "backend": detected_backend,
            "parameter": target.parameter,
            "url": target.url,
            "channel": target.channel,
            "payload": extraction_payload or triggering_payload,
            "extracted": extracted,
            "probes": probe_evidence,
            "summary": summary,
            "kind": "sqli_error_verified" if verified else "sqli_error_fingerprint",
        }

    async def _run_blind_phase(
        self,
        *,
        target: _SqliTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        backend: str | None,
        baseline: dict[str, Any],
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        mutator = self._build_mutator()
        try:
            payloads = await mutator.mutate_by_category(
                "blind_timing",
                FilterModel(parameter=target.parameter, channel=target.channel),
                backend=backend,
                max_candidates=max(1, self.max_blind_payloads),
            )
        except Exception as exc:
            self._note(f"sqli:blind_mutate_failed {exc}")
            payloads = []

        if not payloads:
            return None

        baseline_s = float(baseline.get("median_s") or 0.0)
        _ = (config, step)

        for payload in payloads[: self.max_blind_payloads]:
            if http_tool.remaining < self.probes_per_timing_payload:
                break
            if self._already_tried(host=host, parameter=target.parameter, payload=payload):
                continue

            deltas: list[float] = []
            elapsed_samples: list[float] = []
            for _ in range(self.probes_per_timing_payload):
                if http_tool.remaining < 1:
                    break
                obs = await http_tool.run(_build_probe_action(target, payload))
                if obs.ok and obs.elapsed_ms is not None:
                    elapsed_s = obs.elapsed_ms / 1000.0
                    elapsed_samples.append(elapsed_s)
                    deltas.append(elapsed_s - baseline_s)

            hits = sum(1 for d in deltas if d >= self.timing_threshold_s)
            outcome = f"blind_probe:{hits}/{len(deltas)}"
            self._record_attempt(host=host, parameter=target.parameter, payload=payload, outcome=outcome)

            if hits >= self.timing_hits_required:
                return {
                    "verified": True,
                    "mode": "blind_timing",
                    "backend": backend,
                    "parameter": target.parameter,
                    "url": target.url,
                    "channel": target.channel,
                    "payload": payload,
                    "baseline_s": baseline_s,
                    "threshold_s": self.timing_threshold_s,
                    "deltas_s": deltas,
                    "hits": hits,
                    "probes": len(deltas),
                    "summary": (
                        f"Blind-timing SQLi: {hits}/{len(deltas)} probes exceeded "
                        f"{self.timing_threshold_s:.1f}s delta (backend={backend or 'unknown'})"
                    ),
                    "kind": "sqli_blind_timing_verified",
                }

        return None

    def _build_mutator(self) -> PayloadMutator:
        assert self.llm_client is not None
        return PayloadMutator(
            llm_client=self.llm_client,
            payload_library_path=self.payload_library_path,
        )

    def _discover_targets(self, state: State) -> list[_SqliTarget]:
        targets: list[_SqliTarget] = []
        seen: set[tuple[str, str]] = set()

        for page_url, forms in (state.forms_by_url or {}).items():
            for form in forms or []:
                action_url = str(form.get("action") or page_url or "")
                if not action_url:
                    continue
                method = str(form.get("method") or "POST").upper()
                if method not in {"GET", "POST"}:
                    continue
                inputs = form.get("inputs") or []
                for inp in inputs:
                    name = str(inp.get("name") or "")
                    itype = str(inp.get("type") or "").lower()
                    if not name or itype in _SKIP_INPUT_TYPES:
                        continue
                    key = (action_url, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    siblings: dict[str, Any] = {}
                    for other in inputs:
                        other_name = str(other.get("name") or "")
                        if not other_name or other_name == name:
                            continue
                        siblings[other_name] = str(other.get("value") or "")
                    targets.append(
                        _SqliTarget(
                            url=action_url,
                            parameter=name,
                            channel=method,
                            baseline_params=siblings,
                        )
                    )

        last_url = state.last_http_url
        if last_url:
            try:
                parsed = urlparse(last_url)
            except Exception:
                parsed = None
            if parsed is not None and parsed.query:
                base = urlunparse(parsed._replace(query=""))
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                for name, _value in pairs:
                    key = (base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    siblings = {k: v for k, v in pairs if k != name}
                    targets.append(
                        _SqliTarget(
                            url=base,
                            parameter=name,
                            channel="GET",
                            baseline_params=siblings,
                        )
                    )

        return targets

    def _already_tried(self, *, host: str, parameter: str, payload: str) -> bool:
        if self.memory is None:
            return False
        try:
            return self.memory.was_tried(
                episode_id=self._episode_id(),
                host=host,
                parameter=parameter,
                payload=payload,
            )
        except Exception as exc:
            logger.warning("sqli memory was_tried failed: %s", exc)
            return False

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
            logger.warning("sqli memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _SqliTarget,
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
            logger.warning("sqli tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("sqli tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _build_probe_action(target: _SqliTarget, payload: str) -> Action:
    if target.channel == "GET":
        probe_url = target.url
        for sib_name, sib_value in target.baseline_params.items():
            probe_url = _set_query_param(probe_url, sib_name, str(sib_value))
        probe_url = _set_query_param(probe_url, target.parameter, payload)
        return Action(type=ActionType.HTTP, params={"method": "GET", "url": probe_url}, timeout_s=12.0, tags=["sqli", "probe"])
    body: dict[str, Any] = {k: str(v) for k, v in target.baseline_params.items()}
    body[target.parameter] = payload
    return Action(
        type=ActionType.HTTP,
        params={"method": "POST", "url": target.url, "data": body},
        timeout_s=12.0,
        tags=["sqli", "probe"],
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


def _fingerprint_backend(text: str) -> str | None:
    if not text:
        return None
    low = text.lower()
    for backend, signatures in _BACKEND_ERROR_SIGNATURES.items():
        for sig in signatures:
            if sig in low:
                return backend
    return None


def _extract_version(text: str, backend: str) -> str | None:
    if not text:
        return None
    pattern = _VERSION_PATTERNS.get(backend)
    if pattern is None:
        return None
    m = pattern.search(text)
    return m.group(0) if m else None


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
