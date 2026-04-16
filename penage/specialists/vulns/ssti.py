from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared import PayloadMutator
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "ssti.yaml"

_SKIP_INPUT_TYPES = frozenset({"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"})

_KNOWN_ENGINES: tuple[str, ...] = ("jinja2", "twig", "freemarker", "velocity", "erb", "pebble", "nunjucks")


@dataclass(slots=True)
class _SstiTarget:
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
            return Observation(ok=False, error="ssti_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"ssti_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)


@dataclass(slots=True)
class SstiSpecialist(AsyncSpecialist):
    """Server-side template injection specialist.

    Three phases per target parameter:

    1. **Engine fingerprinting.** A matrix of arithmetic-disambiguation probes
       (``{{7*7}}``, ``${7*7}``, ``<%= 7*7 %>``, ``#{7*7}``, ``{{7*'7'}}``)
       is sent. Each probe's expected output (from YAML ``prerequisites.expected``)
       is searched for in the response. ``{{7*'7'}}`` uniquely disambiguates
       Jinja2 (``7777777``) from Twig (``49``).
    2. **Engine-specific exploitation.** Once the engine is pinned, payloads
       carrying that engine's gadget chain plus a deterministic marker are
       sent from ``penage/payloads/ssti.yaml``.
    3. **Evidence collection.** A payload is validated when the marker
       appears in the response together with engine-specific signal
       (command output markers, class names, introspection leakage).

    The specialist short-circuits once a verified finding exists for the
    episode and respects a local HTTP cap that also bumps the episode's
    global HTTP counters.
    """

    name: ClassVar[str] = "ssti"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 30
    max_targets: int = 2
    min_reserve_http: int = 8
    max_exploits_per_engine: int = 4

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
            self._note(f"ssti:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http // 2:
                self._note(f"ssti:budget_low remaining={budgeted.remaining}")
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
        tag = "verified" if finding.get("verified") else "unverified"
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "ssti_finding", "finding": finding},
            tags=["ssti", tag, finding.get("engine") or "unknown-engine"],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=11.0 if finding.get("verified") else 5.0,
                cost=0.0,
                reason=finding.get("summary") or "SSTI finding",
                metadata={"evidence": finding},
            )
        ]

    async def _run_pipeline(
        self,
        *,
        target: _SstiTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        config: SpecialistConfig,
    ) -> dict[str, Any] | None:
        host = _host_of(target.url)
        mutator = PayloadMutator(
            llm_client=self.llm_client,  # type: ignore[arg-type]
            payload_library_path=self.payload_library_path,
        )

        self._trace_phase(1, "engine_fingerprint", step=step, target=target)
        engine, fp_evidence = await self._fingerprint_engine(
            target=target,
            http_tool=http_tool,
            host=host,
            mutator=mutator,
        )
        if engine is None:
            # Benign endpoints echo arithmetic probes verbatim — never surface a
            # finding just because the probes ran. Only emit an unverified
            # record later if we actually fingerprinted an engine.
            return None

        _ = config

        self._trace_phase(
            2,
            "engine_exploit",
            step=step,
            target=target,
            extra={"engine": engine},
        )
        exploit_entries = mutator.library_entries("ssti_exploit")
        exploit_entries = [e for e in exploit_entries if (e["prerequisites"].get("engine") or "").lower() == engine]

        if not exploit_entries:
            return self._build_unverified(
                target=target,
                phase_evidence=fp_evidence,
                engine=engine,
                reason="no_exploit_payloads_for_engine",
            )

        self._trace_phase(
            3,
            "evidence_collection",
            step=step,
            target=target,
            extra={"engine": engine, "exploit_candidates": len(exploit_entries)},
        )

        probed: list[dict[str, Any]] = []
        for entry in exploit_entries[: self.max_exploits_per_engine]:
            if http_tool.remaining < 1:
                break

            payload = str(entry["template"] or "")
            marker = str(entry["prerequisites"].get("marker") or "")
            if not payload or not marker:
                continue
            if self._already_tried(host=host, parameter=target.parameter, payload=payload):
                continue

            obs = await http_tool.run(_build_probe_action(target, payload))
            text = _response_text(obs)
            marker_present = marker in text
            # Stricter evidence check: require the marker AND some change beyond the echo.
            echoed_verbatim = payload in text
            verified = marker_present and not echoed_verbatim

            outcome = "exploit:verified" if verified else (
                "exploit:echoed" if echoed_verbatim else ("exploit:marker_only" if marker_present else "exploit:no_hit")
            )
            self._record_attempt(host=host, parameter=target.parameter, payload=payload, outcome=outcome)

            probe_record = {
                "payload_id": entry.get("id"),
                "payload": payload,
                "marker": marker,
                "marker_present": marker_present,
                "echoed_verbatim": echoed_verbatim,
                "status": _status_of(obs),
            }
            probed.append(probe_record)

            if verified:
                return {
                    "verified": True,
                    "kind": "ssti_exploit_verified",
                    "engine": engine,
                    "parameter": target.parameter,
                    "url": target.url,
                    "channel": target.channel,
                    "payload": payload,
                    "payload_id": entry.get("id"),
                    "marker": marker,
                    "fingerprint_evidence": fp_evidence,
                    "exploit_probes": probed,
                    "summary": (
                        f"SSTI verified on {target.parameter} (engine={engine}, "
                        f"payload_id={entry.get('id')})"
                    ),
                }

        return {
            "verified": False,
            "kind": "ssti_engine_fingerprint",
            "engine": engine,
            "parameter": target.parameter,
            "url": target.url,
            "channel": target.channel,
            "fingerprint_evidence": fp_evidence,
            "exploit_probes": probed,
            "summary": (
                f"Template engine fingerprinted ({engine}) but no exploit payload "
                f"produced verified evidence"
            ),
        }

    async def _fingerprint_engine(
        self,
        *,
        target: _SstiTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        mutator: PayloadMutator,
    ) -> tuple[str | None, list[dict[str, Any]]]:
        entries = mutator.library_entries("ssti_fingerprint")
        evidence: list[dict[str, Any]] = []
        engine_hits: dict[str, int] = {}
        first_hit_for: dict[str, str] = {}

        for entry in entries:
            if http_tool.remaining < 1:
                break
            payload = str(entry["template"] or "")
            if not payload:
                continue
            if self._already_tried(host=host, parameter=target.parameter, payload=payload):
                continue

            expected = str(entry["prerequisites"].get("expected") or "")
            declared_engine = str(entry["prerequisites"].get("engine") or "").lower()

            obs = await http_tool.run(_build_probe_action(target, payload))
            text = _response_text(obs)
            echoed_verbatim = payload in text
            expected_present = bool(expected) and expected in text and not echoed_verbatim
            outcome = (
                "fingerprint:hit"
                if expected_present
                else ("fingerprint:echoed" if echoed_verbatim else "fingerprint:miss")
            )
            self._record_attempt(host=host, parameter=target.parameter, payload=payload, outcome=outcome)

            evidence.append(
                {
                    "payload_id": entry.get("id"),
                    "payload": payload,
                    "expected": expected,
                    "expected_present": expected_present,
                    "declared_engine": declared_engine or None,
                    "echoed_verbatim": echoed_verbatim,
                }
            )

            if not expected_present:
                continue

            if declared_engine:
                engine_hits[declared_engine] = engine_hits.get(declared_engine, 0) + 2
                first_hit_for.setdefault(declared_engine, payload)
                continue

            # Ambiguous probe ({{7*7}}, ${7*7}): tentatively bump all candidates.
            for candidate in _candidate_engines_for_payload(payload):
                engine_hits[candidate] = engine_hits.get(candidate, 0) + 1
                first_hit_for.setdefault(candidate, payload)

        if not engine_hits:
            return None, evidence

        best_engine = max(engine_hits.items(), key=lambda kv: (kv[1], kv[0]))
        return best_engine[0], evidence

    def _build_unverified(
        self,
        *,
        target: _SstiTarget,
        phase_evidence: list[dict[str, Any]],
        engine: str | None = None,
        reason: str,
    ) -> dict[str, Any] | None:
        if not phase_evidence:
            return None
        return {
            "verified": False,
            "kind": "ssti_fingerprint_only",
            "engine": engine,
            "parameter": target.parameter,
            "url": target.url,
            "channel": target.channel,
            "fingerprint_evidence": phase_evidence,
            "summary": f"SSTI pipeline halted early: {reason}",
        }

    def _discover_targets(self, state: State) -> list[_SstiTarget]:
        targets: list[_SstiTarget] = []
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
                    targets.append(_SstiTarget(url=action_url, parameter=name, channel=method))

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
                    targets.append(_SstiTarget(url=base, parameter=name, channel="GET"))

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
            logger.warning("ssti memory was_tried failed: %s", exc)
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
            logger.warning("ssti memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _SstiTarget,
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
            logger.warning("ssti tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("ssti tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _candidate_engines_for_payload(payload: str) -> list[str]:
    if "{{" in payload and "}}" in payload:
        return ["jinja2", "twig", "nunjucks"]
    if "${" in payload and "}" in payload:
        return ["freemarker", "velocity"]
    if "<%=" in payload:
        return ["erb"]
    if "#{" in payload:
        return ["pebble"]
    return []


def _build_probe_action(target: _SstiTarget, payload: str) -> Action:
    if target.channel == "GET":
        probe_url = _set_query_param(target.url, target.parameter, payload)
        return Action(
            type=ActionType.HTTP,
            params={"method": "GET", "url": probe_url},
            timeout_s=10.0,
            tags=["ssti", "probe"],
        )
    return Action(
        type=ActionType.HTTP,
        params={"method": "POST", "url": target.url, "data": {target.parameter: payload}},
        timeout_s=10.0,
        tags=["ssti", "probe"],
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


__all__ = ["SstiSpecialist", "_KNOWN_ENGINES"]
