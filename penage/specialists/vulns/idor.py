from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar, List
from urllib.parse import parse_qsl, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_ID_PARAM_NAME_HINTS = frozenset(
    {
        "id",
        "uid",
        "user_id",
        "userid",
        "account_id",
        "accountid",
        "order_id",
        "orderid",
        "document_id",
        "documentid",
        "doc_id",
        "docid",
        "post_id",
        "postid",
        "item_id",
        "itemid",
        "ticket_id",
        "ticketid",
        "record_id",
        "recordid",
        "invoice_id",
        "invoiceid",
        "object_id",
        "objectid",
        "resource_id",
        "resourceid",
    }
)

_NUMERIC_SEG_RE = re.compile(r"^\d{1,12}$")
_UUID_SEG_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PREFIXED_ID_RE = re.compile(r"^[a-z]{1,4}[_\-][A-Za-z0-9]{4,24}$")

_SKIP_INPUT_TYPES = frozenset(
    {
        "submit",
        "reset",
        "button",
        "file",
        "image",
        "checkbox",
        "radio",
        "password",
    }
)


@dataclass(slots=True)
class _IdorTarget:
    """A candidate endpoint+parameter that carries an ID-like value.

    id_location:
      - "path":  numeric/uuid segment in URL path (e.g. /users/42).
                 id_param is a synthetic name like "__path_seg_2__".
      - "query": ?id=42 / ?user_id=42 in query string.
      - "form":  hidden/visible form input carrying an id.
    is_numeric: True if id_value is pure digits (enables sequential
                enumeration in phase 3).
    """

    url: str
    id_param: str
    id_value: str
    channel: str
    id_location: str
    is_numeric: bool
    path_segment_index: int = -1


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
            return Observation(ok=False, error="idor_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"idor_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)


@dataclass(slots=True)
class IdorSpecialist(AsyncSpecialist):
    """AWE-style IDOR specialist (phases 0-5).

    Phase 0 — login role A and role B via shared/session_login. (IDOR-3)
    Phase 1 — target discovery (THIS SESSION). Scans state for endpoints
              that carry ID-like parameters in query, path, or form.
    Phase 2 — horizontal differential (role A vs role B on same resource).
              (IDOR-3)
    Phase 3 — sequential enumeration (role A tries id+/-1..+/-5). (IDOR-4)
    Phase 4 — vertical (unauthenticated vs role B on admin-like paths).
              (IDOR-4)
    Phase 5 — candidate finalization.                           (IDOR-4)

    Verified iff compare_responses returns LEAK_IDENTICAL_BODY or
    LEAK_SHARED_MARKERS. STATUS_DIFFERENTIAL -> candidate only.

    DESIGN NOTE: like XXE, IDOR is purely deterministic. LLM-based
    enumeration of ID values is low-ROI; we rely on sequential and
    known-ID-based probes instead.

    SAFETY: role passwords are passed in via constructor kwargs by
    runtime_factory, never persisted to state or trace. RoleSession
    in state.auth_roles carries cookies only; no password lands there.
    """

    name: ClassVar[str] = "idor"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None

    role_a_password: str = ""
    role_b_password: str = ""

    login_user_field: str = "username"
    login_pass_field: str = "password"

    max_http_budget: int = 30
    max_targets: int = 4
    min_reserve_http: int = 8
    max_enumeration_probes: int = 5

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _observations: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict, init=False,
    )

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        return []

    async def propose_async(
        self, state: State, *, config: SpecialistConfig
    ) -> List[CandidateAction]:
        if self._done or self.http_tool is None:
            return self._emit_if_any()

        targets = self._discover_targets(state)
        if not targets:
            return []
        if self.max_http_budget < self.min_reserve_http:
            self._note(f"idor:insufficient_budget cap={self.max_http_budget}")
            return []

        step = int(getattr(state, "orch_step", 0))
        for target in targets[: self.max_targets]:
            self._trace_phase(1, "target_discovery", step=step, target=target)

        return []

    def _emit_if_any(self) -> List[CandidateAction]:
        # In this session _findings is always empty; return [].
        # Full emission logic lands in IDOR-4.
        return []

    async def _run_login_phase(self, *args: Any, **kwargs: Any) -> Any:
        """Phase 0 - login role A and role B. Implemented in IDOR-3."""
        raise NotImplementedError("Implemented in IDOR-3")

    async def _run_horizontal_phase(self, *args: Any, **kwargs: Any) -> Any:
        """Phase 2 - role A vs role B on same resource. Implemented in IDOR-3."""
        raise NotImplementedError("Implemented in IDOR-3")

    async def _run_enumeration_phase(self, *args: Any, **kwargs: Any) -> Any:
        """Phase 3 - role A tries id+/-1..+/-5. Implemented in IDOR-4."""
        raise NotImplementedError("Implemented in IDOR-4")

    async def _run_vertical_phase(self, *args: Any, **kwargs: Any) -> Any:
        """Phase 4 - unauth vs role B on admin paths. Implemented in IDOR-4."""
        raise NotImplementedError("Implemented in IDOR-4")

    def _finalize_candidate(self, *args: Any, **kwargs: Any) -> Any:
        """Phase 5 - candidate from status differential. Implemented in IDOR-4."""
        raise NotImplementedError("Implemented in IDOR-4")

    def _discover_targets(self, state: State) -> list[_IdorTarget]:
        found: list[_IdorTarget] = []
        seen: set[tuple[str, str, str]] = set()

        urls: list[str] = []
        last_url = getattr(state, "last_http_url", None)
        if last_url:
            urls.append(str(last_url))
        for rec in (getattr(state, "recent_http_memory", None) or []):
            if isinstance(rec, dict):
                u = rec.get("url")
                if u:
                    urls.append(str(u))

        # A. Query-param hints.
        for url in urls:
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            if not parsed.query:
                continue
            base = urlunparse(parsed._replace(query=""))
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                if name.lower() not in _ID_PARAM_NAME_HINTS:
                    continue
                if not value:
                    continue
                key = (base, "query", name)
                if key in seen:
                    continue
                seen.add(key)
                found.append(
                    _IdorTarget(
                        url=base,
                        id_param=name,
                        id_value=value,
                        channel="GET",
                        id_location="query",
                        is_numeric=_NUMERIC_SEG_RE.match(value) is not None,
                        path_segment_index=-1,
                    )
                )

        # C. Form-input hints (hidden inputs ARE allowed for IDOR).
        forms_by_url = getattr(state, "forms_by_url", {}) or {}
        for page_url, forms in forms_by_url.items():
            for form in forms or []:
                action_url = str(form.get("action") or page_url or "")
                if not action_url:
                    continue
                method = str(form.get("method") or "POST").upper()
                if method not in {"GET", "POST"}:
                    continue
                for inp in (form.get("inputs") or []):
                    name = str(inp.get("name") or "").strip()
                    itype = str(inp.get("type") or "").lower()
                    value = str(inp.get("value") or "").strip()
                    if not name:
                        continue
                    # Hidden inputs are a valid IDOR target (order_id in
                    # POST forms is commonly hidden). Every other skip
                    # type still excludes the input.
                    if itype in _SKIP_INPUT_TYPES:
                        continue
                    if name.lower() not in _ID_PARAM_NAME_HINTS:
                        continue
                    if not value:
                        continue
                    key = (action_url, "form", name)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(
                        _IdorTarget(
                            url=action_url,
                            id_param=name,
                            id_value=value,
                            channel=method,
                            id_location="form",
                            is_numeric=_NUMERIC_SEG_RE.match(value) is not None,
                            path_segment_index=-1,
                        )
                    )

        # B. Path-segments that look like IDs.
        for url in urls:
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            path = parsed.path or ""
            if not path or path == "/":
                continue
            segments = [s for s in path.split("/") if s]
            for idx, seg in enumerate(segments):
                is_numeric = bool(_NUMERIC_SEG_RE.match(seg))
                is_uuid = bool(_UUID_SEG_RE.match(seg))
                is_prefixed = bool(_PREFIXED_ID_RE.match(seg))
                if not (is_numeric or is_uuid or is_prefixed):
                    continue
                synth = f"__path_seg_{idx}__"
                key = (url, "path", synth)
                if key in seen:
                    continue
                seen.add(key)
                found.append(
                    _IdorTarget(
                        url=url,
                        id_param=synth,
                        id_value=seg,
                        channel="GET",
                        id_location="path",
                        is_numeric=is_numeric,
                        path_segment_index=idx,
                    )
                )

        return found[: self.max_targets]

    def _record_attempt(
        self, *, host: str, parameter: str, payload: str, outcome: str
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
            logger.warning("idor memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _IdorTarget,
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
            "channel": target.channel,
            "id_location": target.id_location,
            "id_param": target.id_param,
            "is_numeric": target.is_numeric,
        }
        if extra:
            payload.update(extra)
        try:
            self.tracer.write_event("specialist_phase", payload)
        except Exception as exc:
            logger.warning("idor tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("idor tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


__all__ = ["IdorSpecialist"]
