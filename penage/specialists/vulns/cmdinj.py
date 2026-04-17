from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlparse, urlunparse

from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.destructive_filter import DestructiveCommandFilter
from penage.tools.http_backend import HttpBackend

# Re-used by the specialist in later sub-sessions.
from penage.core.actions import Action  # noqa: F401  (kept for phase 2+)
from penage.core.observations import Observation

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

    This iteration implements only **phase 1** (target discovery) and the
    scaffolding for the rest. Phases 2-5 raise ``NotImplementedError`` and
    are filled in by sessions 2.9b-ii / 2.9b-iii / 2.9b-iv / 2.9c.

    SECURITY INVARIANT (CLAUDE.md #4): every payload — base or mutated — must
    pass through ``self._filter.check(...)`` before leaving the specialist.
    Destructive commands are allowed only when ``allow_destructive=True``,
    which is itself opt-in and logged in the trace by the filter's caller.
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

    allow_destructive: bool = False

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _filter: DestructiveCommandFilter = field(init=False)

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

        _ = config
        step = int(getattr(state, "orch_step", 0))

        # Phase 1 only in this iteration: trace discovered targets and stop.
        # Phases 2-5 will consume ``targets`` via _run_pipeline in 2.9b-ii+.
        for target in targets[: self.max_targets]:
            self._trace_phase(1, "target_discovery", step=step, target=target)
        return []

    def _emit_if_any(self) -> List[CandidateAction]:
        # Phase 2+ findings aren't produced yet. Finalised in 2.9c.
        return []

    async def _measure_baseline(
        self,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
    ) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.9b-ii")

    async def _run_echo_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.9b-ii")

    async def _run_fingerprint_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.9b-ii")

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
    ) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.9c")

    async def _run_mutation_phase(
        self,
        *,
        target: _CmdInjTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        prior_signals: dict[str, Any],
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.9c")

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
