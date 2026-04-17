from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
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
from penage.specialists.shared.differential import (
    DifferentialSignal,
    compare_responses,
)
from penage.specialists.shared.session_login import login_role
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

_ADMIN_PATH_HINTS = (
    "/admin",
    "/administration",
    "/dashboard/admin",
    "/settings/admin",
    "/admin/users",
    "/admin/settings",
    "/console",
    "/manage",
    "/management",
    "/backoffice",
    "/internal",
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
    """AWE-style IDOR specialist (phases 0-5, all implemented).

    Phase 0 — login role A and role B via shared/session_login.
    Phase 1 — target discovery. Scans state for endpoints carrying
              ID-like parameters in query, path, or form.
    Phase 2 — horizontal differential (role A vs role B on same
              resource). Verified iff compare_responses returns
              LEAK_IDENTICAL_BODY or LEAK_SHARED_MARKERS.
    Phase 3 — sequential enumeration (role A tries id+/-1..+/-N on
              numeric targets). Verified on identical-to-baseline
              body or cross-owner markers.
    Phase 4 — vertical privilege probe (unauthenticated vs role B on
              admin-like paths). Runs ONCE per episode (not per
              target) and only if no prior phase produced a verified
              finding.
    Phase 5 — candidate finalization per target. Assembles an
              unverified candidate (status-differential from phase 2
              or enumeration status-spread from phase 3) when no
              phase produced a verified finding for that target.

    STATUS_DIFFERENTIAL and enumeration status-spread yield
    unverified candidates (CLAUDE.md invariant #4: validation gate).

    Vertical IDOR is a weak class of signals: without admin-role
    ground-truth credentials we detect it as "regular user (role B)
    can access an admin-like path that unauthenticated requests
    cannot". Not proof of an admin-only leak; manual confirmation
    advised.

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
    max_vertical_paths: int = 3

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

        budgeted = _BudgetedHttpTool(self.http_tool, state, cap=self.max_http_budget)
        step = int(getattr(state, "orch_step", 0))

        login_outcome = await self._run_login_phase(
            state=state, http_tool=budgeted, step=step,
        )
        role_a_ready = bool(login_outcome.get("A", False))
        role_b_ready = bool(login_outcome.get("B", False))
        both_roles_ready = role_a_ready and role_b_ready

        for target in targets[: self.max_targets]:
            key = self._target_key(target)
            if key in self._attempted:
                continue
            if budgeted.remaining < self.min_reserve_http:
                self._note(f"idor:budget_low remaining={budgeted.remaining}")
                break

            self._trace_phase(1, "target_discovery", step=step, target=target)

            # Phase 2: horizontal (requires both roles).
            if both_roles_ready:
                self._trace_phase(
                    2, "horizontal_differential", step=step, target=target,
                )
                finding = await self._run_horizontal_phase(
                    state=state, target=target, http_tool=budgeted, step=step,
                )
                if finding and finding.get("verified"):
                    self._findings.append(finding)
                    self._done = True
                    self._attempted.add(key)
                    break
            else:
                self._note(
                    f"idor:horizontal_skipped_no_roles "
                    f"a={role_a_ready} b={role_b_ready}"
                )

            # Phase 3: sequential enumeration (role A, numeric only).
            if (
                role_a_ready
                and target.is_numeric
                and budgeted.remaining >= self.min_reserve_http
            ):
                self._trace_phase(
                    3, "sequential_enumeration", step=step, target=target,
                )
                enum_finding = await self._run_enumeration_phase(
                    state=state, target=target, http_tool=budgeted, step=step,
                )
                if enum_finding and enum_finding.get("verified"):
                    self._findings.append(enum_finding)
                    self._done = True
                    self._attempted.add(key)
                    break

            # Phase 5: candidate from partial signals on this target.
            self._trace_phase(
                5, "candidate_finalization", step=step, target=target,
            )
            candidate = self._finalize_candidate(
                target=target,
                observations=self._observations.get(key, []),
            )
            if candidate is not None:
                self._findings.append(candidate)

            self._attempted.add(key)

        # Phase 4: vertical (once per episode, only if nothing verified yet).
        if (
            not self._done
            and role_b_ready
            and budgeted.remaining >= 6
        ):
            self._trace_phase(
                4, "vertical_privilege_probe", step=step, target=None,
            )
            vert_finding = await self._run_vertical_phase(
                state=state, http_tool=budgeted, step=step,
            )
            if vert_finding and vert_finding.get("verified"):
                self._findings.append(vert_finding)
                self._done = True

        return self._emit_if_any()

    def _emit_if_any(self) -> List[CandidateAction]:
        """Emit a single CandidateAction — verified preferred over candidate.

        CLAUDE.md invariant #4: candidate findings must not masquerade as
        verified. If any verified finding is present, it is emitted
        (score >= 9.0). Otherwise, the last candidate is emitted with
        score < 5.0 and tag "unverified".
        """
        if not self._findings:
            return []
        verified = [f for f in self._findings if f.get("verified")]
        chosen = verified[-1] if verified else self._findings[-1]

        is_verified = bool(chosen.get("verified"))
        mode = chosen.get("mode", "unknown")
        kind = chosen.get("kind", "") or "unknown"
        tag = "verified" if is_verified else "unverified"
        action = Action(
            type=ActionType.NOTE,
            params={"kind": "idor_finding", "finding": chosen},
            tags=["idor", tag, mode, kind],
        )

        if is_verified:
            if kind == "idor_horizontal_identical_body":
                score = 12.0
            elif kind == "idor_enum_cross_owner":
                score = 12.0
            elif kind == "idor_horizontal_shared_markers":
                score = 11.0
            elif kind == "idor_enum_identical_baseline":
                score = 10.0
            elif kind == "idor_vertical_privilege":
                score = 9.0
            else:
                score = 8.0
        else:
            if kind == "idor_status_differential":
                score = 3.0
            elif kind == "idor_enum_status_spread":
                score = 2.0
            else:
                score = 2.0

        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=score,
                cost=0.0,
                reason=chosen.get("summary") or "IDOR finding",
                metadata={"evidence": chosen},
            )
        ]

    async def _run_login_phase(
        self,
        *,
        state: State,
        http_tool: _BudgetedHttpTool,
        step: int,
    ) -> dict[str, bool]:
        """Phase 0: login role A and role B via shared.session_login.login_role.

        Writes the resulting RoleSession back into state.auth_roles via
        .upsert(). Returns {"A": bool, "B": bool} indicating which roles
        are established after login.

        SAFETY: passwords stay inside this method's stack. They never land
        in trace, note, logger, or state.
        """
        registry = state.auth_roles
        outcome: dict[str, bool] = {"A": False, "B": False}

        role_passwords: dict[str, str] = {}
        if self.role_a_password:
            role_passwords["A"] = self.role_a_password
        if self.role_b_password:
            role_passwords["B"] = self.role_b_password

        if not role_passwords:
            self._note("idor:no_role_credentials_configured")
            return outcome

        login_url = registry.login_url or self._discover_login_url(state)
        if not login_url:
            self._note("idor:no_login_url")
            return outcome

        for role_name, password in role_passwords.items():
            existing = registry.get(role_name)
            if existing is None:
                self._note(f"idor:role_not_seeded role={role_name}")
                continue
            if existing.established:
                outcome[role_name] = True
                continue

            self._trace_phase(
                0,
                "role_login",
                step=step,
                target=None,
                extra={"role": role_name, "login_url": login_url},
            )

            try:
                result = await login_role(
                    http_tool=http_tool,
                    login_url=login_url,
                    role_name=role_name,
                    username=existing.username,
                    password=password,
                    user_field=self.login_user_field,
                    pass_field=self.login_pass_field,
                )
            except Exception as exc:  # LEGACY: boundary
                self._note(
                    f"idor:login_exception role={role_name} "
                    f"type={type(exc).__name__}"
                )
                continue

            registry.upsert(result.session)
            outcome[role_name] = result.session.established

            if not result.session.established:
                self._note(
                    f"idor:login_failed role={role_name} "
                    f"reason={result.failure_reason or 'unknown'}"
                )
            else:
                self._note(
                    f"idor:login_ok role={role_name} "
                    f"cookies={result.set_cookie_count}"
                )

        return outcome

    def _discover_login_url(self, state: State) -> str:
        """Scan state.forms_by_url for the first form with a password input."""
        forms_by_url = getattr(state, "forms_by_url", {}) or {}
        for page_url, forms in forms_by_url.items():
            for form in forms or []:
                inputs = form.get("inputs") or []
                has_password = any(
                    str(inp.get("type") or "").lower() == "password"
                    for inp in inputs
                )
                if has_password:
                    action = str(form.get("action") or page_url or "")
                    if action:
                        return action
        return ""

    async def _run_horizontal_phase(
        self,
        *,
        state: State,
        target: _IdorTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 2: same resource, role A vs role B.

        Fires the same request under role A's cookies, then role B's
        cookies, and classifies the pair via compare_responses. Returns
        a verified finding only on LEAK_IDENTICAL_BODY or
        LEAK_SHARED_MARKERS; otherwise records the observation and
        returns None.
        """
        _ = step
        registry = state.auth_roles
        role_a = registry.get("A")
        role_b = registry.get("B")
        if role_a is None or role_b is None:
            return None
        if not (role_a.established and role_b.established):
            return None

        if http_tool.remaining < 3:
            return None

        base_params = self._build_target_request(target)

        a_params = dict(base_params)
        a_params["cookies"] = dict(role_a.cookies)
        obs_a = await http_tool.run(Action(type=ActionType.HTTP, params=a_params))

        b_params = dict(base_params)
        b_params["cookies"] = dict(role_b.cookies)
        obs_b = await http_tool.run(Action(type=ActionType.HTTP, params=b_params))

        a_body, a_status = _extract_body_status(obs_a)
        b_body, b_status = _extract_body_status(obs_b)

        comparison = compare_responses(
            a_body=a_body,
            a_status=a_status,
            b_body=b_body,
            b_status=b_status,
        )

        key = self._target_key(target)
        self._observations.setdefault(key, []).append(
            {
                "phase": "horizontal",
                "signal": comparison.signal.value,
                "a_status": a_status,
                "b_status": b_status,
                "a_body_len": comparison.a_body_len,
                "b_body_len": comparison.b_body_len,
                "shared_markers_count": len(comparison.shared_markers),
            }
        )

        verified = comparison.signal in (
            DifferentialSignal.LEAK_IDENTICAL_BODY,
            DifferentialSignal.LEAK_SHARED_MARKERS,
        )

        if not verified:
            self._record_attempt(
                host=_host_of(target.url),
                parameter=target.id_param,
                payload=target.id_value,
                outcome=f"horizontal_{comparison.signal.value}",
            )
            return None

        self._record_attempt(
            host=_host_of(target.url),
            parameter=target.id_param,
            payload=target.id_value,
            outcome=f"verified_horizontal_{comparison.signal.value}",
        )

        kind = (
            "idor_horizontal_identical_body"
            if comparison.signal == DifferentialSignal.LEAK_IDENTICAL_BODY
            else "idor_horizontal_shared_markers"
        )

        return {
            "verified": True,
            "kind": kind,
            "mode": "horizontal",
            "parameter": target.id_param,
            "id_location": target.id_location,
            "id_value": target.id_value,
            "channel": target.channel,
            "url": target.url,
            "evidence": {
                "signal": comparison.signal.value,
                "shared_markers": list(comparison.shared_markers),
                "a_status": a_status,
                "b_status": b_status,
                "a_body_len": comparison.a_body_len,
                "b_body_len": comparison.b_body_len,
                "a_body_hash": comparison.a_body_hash,
                "b_body_hash": comparison.b_body_hash,
                "role_a_user": role_a.username,
                "role_b_user": role_b.username,
                "notes": list(comparison.notes),
            },
            "summary": (
                f"IDOR: role B sees role A's resource at "
                f"{target.id_location}={target.id_param} "
                f"({comparison.signal.value})"
            ),
        }

    def _build_target_request(self, target: _IdorTarget) -> dict[str, Any]:
        """Construct httpx-style action.params for target, without cookies."""
        if target.id_location == "query":
            url = _set_query_param(target.url, target.id_param, target.id_value)
            return {
                "method": "GET",
                "url": url,
                "follow_redirects": False,
            }
        if target.id_location == "path":
            return {
                "method": "GET",
                "url": target.url,
                "follow_redirects": False,
            }
        method = target.channel if target.channel in {"GET", "POST"} else "POST"
        return {
            "method": method,
            "url": target.url,
            "data": {target.id_param: target.id_value},
            "follow_redirects": False,
        }

    def _target_key(self, target: _IdorTarget) -> str:
        return f"{target.url}|{target.id_location}|{target.id_param}"

    def _probe_params_with_id(
        self,
        target: _IdorTarget,
        probe_id: str,
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        """Build action.params for a phase-3 probe with an arbitrary id."""
        if target.id_location == "query":
            url = _set_query_param(target.url, target.id_param, probe_id)
            return {
                "method": "GET",
                "url": url,
                "cookies": dict(cookies),
                "follow_redirects": False,
            }
        if target.id_location == "path":
            url = _replace_path_segment(
                target.url, target.path_segment_index, probe_id,
            )
            return {
                "method": "GET",
                "url": url,
                "cookies": dict(cookies),
                "follow_redirects": False,
            }
        method = target.channel if target.channel in {"GET", "POST"} else "POST"
        return {
            "method": method,
            "url": target.url,
            "data": {target.id_param: probe_id},
            "cookies": dict(cookies),
            "follow_redirects": False,
        }

    async def _run_enumeration_phase(
        self,
        *,
        state: State,
        target: _IdorTarget,
        http_tool: _BudgetedHttpTool,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 3: sequential ID enumeration using role A.

        Only runs for numeric targets. Role A queries id+/-1..+/-N; any probe
        that returns owner-scoped markers NOT present in A's own baseline,
        OR a body byte-identical to A's baseline, is verified IDOR.
        """
        _ = step
        if not target.is_numeric:
            return None

        registry = state.auth_roles
        role_a = registry.get("A")
        if role_a is None or not role_a.established:
            return None

        if http_tool.remaining < 3:
            return None

        from penage.specialists.shared.differential import extract_markers

        base_params = self._build_target_request(target)
        base_params["cookies"] = dict(role_a.cookies)

        obs_baseline = await http_tool.run(
            Action(type=ActionType.HTTP, params=base_params)
        )
        body_base, status_base = _extract_body_status(obs_baseline)
        if status_base is None or not (200 <= status_base < 300):
            self._note(
                f"idor:enum_baseline_unavailable status={status_base} "
                f"target={target.id_param}"
            )
            return None

        markers_baseline = extract_markers(body_base)
        baseline_tokens = markers_baseline.all_tokens()
        baseline_hash = _hash_short(body_base)
        key = self._target_key(target)

        enum_ids = _build_enum_set(target.id_value, self.max_enumeration_probes)
        if not enum_ids:
            return None

        probes_fired = 0
        for probe_id in enum_ids:
            if http_tool.remaining < 2:
                break
            probes_fired += 1

            probe_params = self._probe_params_with_id(
                target, probe_id, role_a.cookies,
            )
            obs_probe = await http_tool.run(
                Action(type=ActionType.HTTP, params=probe_params)
            )
            body_probe, status_probe = _extract_body_status(obs_probe)

            if status_probe is None or not (200 <= status_probe < 300):
                self._observations.setdefault(key, []).append({
                    "phase": "enumeration",
                    "probe_id": probe_id,
                    "status": status_probe,
                    "result": "non_2xx",
                })
                continue

            probe_hash = _hash_short(body_probe)
            if (
                len(body_probe) >= 32
                and probe_hash == baseline_hash
                and probe_id != target.id_value
            ):
                self._observations.setdefault(key, []).append({
                    "phase": "enumeration",
                    "probe_id": probe_id,
                    "status": status_probe,
                    "result": "identical_to_baseline",
                })
                self._record_attempt(
                    host=_host_of(target.url),
                    parameter=target.id_param,
                    payload=probe_id,
                    outcome="verified_enum_identical_baseline",
                )
                return {
                    "verified": True,
                    "kind": "idor_enum_identical_baseline",
                    "mode": "enumeration",
                    "parameter": target.id_param,
                    "id_location": target.id_location,
                    "id_value": target.id_value,
                    "probe_id": probe_id,
                    "channel": target.channel,
                    "url": target.url,
                    "evidence": {
                        "signal": "identical_body_across_ids",
                        "baseline_id": target.id_value,
                        "probe_id": probe_id,
                        "a_status": status_base,
                        "probe_status": status_probe,
                        "a_body_len": len(body_base),
                        "probe_body_len": len(body_probe),
                        "a_body_hash": baseline_hash,
                        "probe_body_hash": probe_hash,
                        "role_a_user": role_a.username,
                        "probes_fired": probes_fired,
                    },
                    "summary": (
                        f"IDOR: probe id={probe_id} returns byte-identical "
                        f"body to baseline id={target.id_value}"
                    ),
                }

            markers_probe = extract_markers(body_probe)
            probe_tokens = markers_probe.all_tokens()
            cross_tokens = sorted(probe_tokens - baseline_tokens)

            self._observations.setdefault(key, []).append({
                "phase": "enumeration",
                "probe_id": probe_id,
                "status": status_probe,
                "result": "ok",
                "cross_tokens_count": len(cross_tokens),
                "probe_body_len": len(body_probe),
            })

            if cross_tokens:
                self._record_attempt(
                    host=_host_of(target.url),
                    parameter=target.id_param,
                    payload=probe_id,
                    outcome="verified_enum_cross_owner_markers",
                )
                return {
                    "verified": True,
                    "kind": "idor_enum_cross_owner",
                    "mode": "enumeration",
                    "parameter": target.id_param,
                    "id_location": target.id_location,
                    "id_value": target.id_value,
                    "probe_id": probe_id,
                    "channel": target.channel,
                    "url": target.url,
                    "evidence": {
                        "signal": "cross_owner_markers",
                        "cross_owner_markers": cross_tokens[:16],
                        "baseline_id": target.id_value,
                        "probe_id": probe_id,
                        "a_status": status_base,
                        "probe_status": status_probe,
                        "a_body_len": len(body_base),
                        "probe_body_len": len(body_probe),
                        "role_a_user": role_a.username,
                        "probes_fired": probes_fired,
                    },
                    "summary": (
                        f"IDOR: role A probing id={probe_id} sees "
                        f"{len(cross_tokens)} owner-scoped token(s) "
                        f"not in own baseline"
                    ),
                }

            self._record_attempt(
                host=_host_of(target.url),
                parameter=target.id_param,
                payload=probe_id,
                outcome="enum_no_cross_markers",
            )

        return None

    def _discover_admin_paths(self, state: State) -> list[str]:
        """Return up to max_vertical_paths URLs that look admin-scoped.

        Scans state.last_http_url and state.recent_http_memory for URLs
        whose path contains an admin hint (see _ADMIN_PATH_HINTS). Deduped
        by scheme+netloc+path (query and fragment are stripped).
        """
        urls: list[str] = []
        seen: set[str] = set()

        candidate_urls: list[str] = []
        if getattr(state, "last_http_url", None):
            candidate_urls.append(str(state.last_http_url))
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
            if not any(h in path for h in _ADMIN_PATH_HINTS):
                continue
            base = url.split("#", 1)[0].split("?", 1)[0]
            if base in seen:
                continue
            seen.add(base)
            urls.append(base)
            if len(urls) >= self.max_vertical_paths:
                break

        return urls

    async def _run_vertical_phase(
        self,
        *,
        state: State,
        http_tool: _BudgetedHttpTool,
        step: int,
    ) -> dict[str, Any] | None:
        """Phase 4: privilege-escalation signal — role B sees admin-like
        pages that unauthenticated requests cannot.

        Runs once per episode (NOT per target). Uses role B + an empty
        cookie probe. Role A is intentionally not used: A may own
        admin-scoped resources (e.g. A is the admin) and that is not an
        IDOR. We want a regular user (B) seeing admin content that
        anonymous cannot.

        DESIGN NOTE: vertical IDOR is a weak class of signals without
        admin-role ground-truth credentials. In penage we catch it as
        "regular user sees admin page that unauth does not" — imperfect
        but useful; manual confirmation advised.
        """
        _ = step
        registry = state.auth_roles
        role_b = registry.get("B")
        if role_b is None or not role_b.established:
            return None

        admin_urls = self._discover_admin_paths(state)
        if not admin_urls:
            return None

        if http_tool.remaining < 3:
            return None

        for admin_url in admin_urls:
            if http_tool.remaining < 3:
                break

            unauth_params = {
                "method": "GET",
                "url": admin_url,
                "cookies": {},
                "follow_redirects": False,
            }
            obs_unauth = await http_tool.run(
                Action(type=ActionType.HTTP, params=unauth_params)
            )
            body_unauth, status_unauth = _extract_body_status(obs_unauth)

            b_params = {
                "method": "GET",
                "url": admin_url,
                "cookies": dict(role_b.cookies),
                "follow_redirects": False,
            }
            obs_b = await http_tool.run(
                Action(type=ActionType.HTTP, params=b_params)
            )
            body_b, status_b = _extract_body_status(obs_b)

            self._observations.setdefault("__vertical__", []).append({
                "phase": "vertical",
                "url": admin_url,
                "unauth_status": status_unauth,
                "b_status": status_b,
                "unauth_body_len": len(body_unauth),
                "b_body_len": len(body_b),
            })

            unauth_denied = (
                status_unauth is not None
                and status_unauth in (401, 403)
            ) or (
                status_unauth in (302, 303)
                and _location_looks_like_login(obs_unauth)
            )
            b_ok = (
                status_b is not None
                and 200 <= status_b < 300
                and len(body_b) >= 32
            )

            if unauth_denied and b_ok:
                self._record_attempt(
                    host=_host_of(admin_url),
                    parameter="__vertical__",
                    payload=admin_url,
                    outcome="verified_vertical",
                )
                return {
                    "verified": True,
                    "kind": "idor_vertical_privilege",
                    "mode": "vertical",
                    "parameter": "__vertical__",
                    "id_location": "path",
                    "id_value": "",
                    "channel": "GET",
                    "url": admin_url,
                    "evidence": {
                        "signal": "role_b_sees_admin_path",
                        "unauth_status": status_unauth,
                        "b_status": status_b,
                        "unauth_body_len": len(body_unauth),
                        "b_body_len": len(body_b),
                        "role_b_user": role_b.username,
                        "note": (
                            "Regular user (role B) accesses admin-like "
                            "path that unauthenticated requests cannot. "
                            "This is a privilege-escalation signal, not "
                            "proof of an admin-only resource leak; "
                            "manual confirmation advised."
                        ),
                    },
                    "summary": (
                        f"Vertical IDOR: role B accesses {admin_url} "
                        f"(unauth {status_unauth}, B {status_b})"
                    ),
                }

        return None

    def _finalize_candidate(
        self,
        *,
        target: _IdorTarget,
        observations: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Phase 5: assemble a candidate finding from partial signals.

        Priority:
          1. Horizontal phase recorded STATUS_DIFFERENTIAL → candidate
             with score 3.0.
          2. Enumeration phase non_2xx probes with >=2 distinct status
             codes (e.g. id-10 → 404, id-11 → 403, id-12 → 500) — the
             server distinguishes between missing, forbidden, and
             erroring IDs, which is an information leak → score 2.0.
          3. Otherwise None.

        Candidates are unverified (verified=False) — they do NOT cross
        the CLAUDE.md invariant #4 validation gate.
        """
        if not observations:
            return None

        horiz_diff = next(
            (
                o for o in observations
                if o.get("phase") == "horizontal"
                and o.get("signal") == DifferentialSignal.STATUS_DIFFERENTIAL.value
            ),
            None,
        )
        if horiz_diff is not None:
            return {
                "verified": False,
                "kind": "idor_status_differential",
                "mode": "candidate",
                "parameter": target.id_param,
                "id_location": target.id_location,
                "id_value": target.id_value,
                "channel": target.channel,
                "url": target.url,
                "evidence": {
                    "signal": "horizontal_status_differential",
                    "a_status": horiz_diff.get("a_status"),
                    "b_status": horiz_diff.get("b_status"),
                    "a_body_len": horiz_diff.get("a_body_len"),
                    "b_body_len": horiz_diff.get("b_body_len"),
                },
                "reason": "status_or_length_differential",
                "summary": (
                    f"IDOR candidate: horizontal request yields "
                    f"status/length differential on {target.id_param}"
                ),
            }

        enum_statuses: list[int] = []
        for o in observations:
            if o.get("phase") != "enumeration":
                continue
            st = o.get("status")
            if isinstance(st, int) and not (200 <= st < 300):
                enum_statuses.append(st)
        if len(set(enum_statuses)) >= 2:
            return {
                "verified": False,
                "kind": "idor_enum_status_spread",
                "mode": "candidate",
                "parameter": target.id_param,
                "id_location": target.id_location,
                "id_value": target.id_value,
                "channel": target.channel,
                "url": target.url,
                "evidence": {
                    "signal": "enumeration_status_spread",
                    "status_spread": sorted(set(enum_statuses)),
                    "probes_count": len(enum_statuses),
                },
                "reason": "server_leaks_id_existence_via_status_codes",
                "summary": (
                    f"IDOR candidate: enumeration shows status spread "
                    f"{sorted(set(enum_statuses))} across probes"
                ),
            }

        return None

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
        target: "_IdorTarget | None" = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if self.tracer is None:
            return
        payload: dict[str, Any] = {
            "specialist": self.name,
            "phase": phase_num,
            "phase_name": name,
            "step": step,
        }
        if target is not None:
            payload.update(
                {
                    "url": target.url,
                    "channel": target.channel,
                    "id_location": target.id_location,
                    "id_param": target.id_param,
                    "is_numeric": target.is_numeric,
                }
            )
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


def _extract_body_status(obs: Observation) -> tuple[str, int | None]:
    if not obs.ok or not isinstance(obs.data, dict):
        return "", None
    body = str(obs.data.get("text_full") or obs.data.get("text_excerpt") or "")
    status = obs.data.get("status_code")
    return body, (int(status) if isinstance(status, int) else None)


def _location_looks_like_login(obs: Observation) -> bool:
    """Does the Location header of a 3xx response point to a login page?"""
    if not obs.ok or not isinstance(obs.data, dict):
        return False
    headers = obs.data.get("headers") or {}
    location = ""
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "location":
                location = str(v or "")
                break
    if not location:
        return False
    try:
        path = (urlparse(location).path or location).lower()
    except Exception:
        path = location.lower()
    return any(h in path for h in ("login", "signin", "sign-in", "auth"))


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [
        (k, v)
        for (k, v) in parse_qsl(parsed.query, keep_blank_values=True)
        if k != name
    ]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True)))


def _replace_path_segment(url: str, seg_index: int, new_value: str) -> str:
    """Replace a non-empty path segment by zero-based index (matches discovery).

    path_segment_index in _IdorTarget counts non-empty segments (see
    `_discover_targets`, where segments are filtered via
    ``[s for s in path.split("/") if s]``). This helper reproduces that
    indexing. Returns the url unchanged if seg_index is out of range.
    """
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    non_empty_indices = [i for i, s in enumerate(segments) if s]
    if seg_index < 0 or seg_index >= len(non_empty_indices):
        return url
    real_idx = non_empty_indices[seg_index]
    new_segments = list(segments)
    new_segments[real_idx] = new_value
    return urlunparse(parsed._replace(path="/".join(new_segments)))


def _build_enum_set(id_value: str, n: int) -> list[str]:
    """Produce an interleaved +/-1..+/-N enumeration set around a numeric id.

    For id_value="42" with n=3 -> ["41","43","40","44","39","45"]. Skips
    ids <= 0 (400-prone and in some systems map to admin records). Returns
    an empty list for non-numeric input or non-positive n.
    """
    try:
        base = int(id_value)
    except (TypeError, ValueError):
        return []
    if base <= 0 or n <= 0:
        return []
    out: list[str] = []
    for delta in range(1, n + 1):
        below = base - delta
        if below > 0:
            out.append(str(below))
        out.append(str(base + delta))
    return out


def _hash_short(body: str) -> str:
    return hashlib.sha256(
        (body or "").encode("utf-8", errors="ignore")
    ).hexdigest()[:16]


__all__ = ["IdorSpecialist"]
