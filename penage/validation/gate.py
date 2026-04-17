from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.usage import UsageTracker
from penage.validation.base import EvidenceValidator, ValidationResult
from penage.validation.browser import BrowserEvidenceValidator
from penage.validation.candidate import CandidateFinding

if TYPE_CHECKING:
    from penage.agents.validation import ValidationAgent


_EXCERPT_CAP = 2000
_NOTES_TAIL = 5
_SUMMARY_CAP = 280


def _build_candidate(
    *,
    kind: str,
    action: Action,
    obs: Observation,
    state: State,
    fast_result: ValidationResult,
    source: str = "http",
) -> CandidateFinding:
    snapshot: dict[str, Any] = {
        "base_url": state.base_url,
        "last_http_url": state.last_http_url,
        "last_http_status": state.last_http_status,
        "last_http_excerpt": (state.last_http_excerpt or "")[:_EXCERPT_CAP],
        "notes_tail": list(state.notes[-_NOTES_TAIL:]),
    }
    return CandidateFinding(
        kind=kind or "unknown",
        action=action,
        obs=obs,
        state_snapshot=snapshot,
        evidence_so_far={source: fast_result.to_dict()},
    )


@dataclass(slots=True)
class ValidationGate:
    """Three-stage cascade: HTTP validator → optional browser → optional agent.

    Stage 1 (HTTP): ``await http_validator.validate(...)`` classifies the
    observation. ``None`` means no HTTP finding; ``"validated"`` means a
    fast-pass (no LLM cost); any other level is a candidate.

    Stage 2 (browser, optional): if ``browser_validator`` is configured
    AND the action is explicitly marked as a browser target
    (``action.params["browser_target"] is True``), the browser validator
    runs. A ``"validated"`` result short-circuits. A non-``None``,
    non-``validated`` result REPLACES the HTTP candidate as the input for
    stage 3 — the browser is considered a more authoritative source for
    actions that explicitly opt into browser verification. ``None`` from
    the browser leaves the HTTP candidate untouched.

    Stage 3 (agent, optional): when ``validation_mode == "agent"`` and a
    ``validation_agent`` is configured, candidates are escalated to the
    LLM role. A ``pass`` verdict upgrades the result to ``"validated"``;
    a ``fail`` verdict leaves it as the original non-validated level and
    annotates the evidence.

    All three stages run in the async cascade: the ``EvidenceValidator``
    Protocol is async so that browser-backed validators share one path
    with the HTTP reflection validator.

    The branches are written out explicitly rather than iterated over a
    generic validator list because their semantics differ (fast-path vs.
    candidate-upgrade vs. LLM-escalation) and their ordering and guards
    are load-bearing.
    """

    http_validator: EvidenceValidator
    validation_agent: Optional[ValidationAgent] = None
    browser_validator: Optional[BrowserEvidenceValidator] = None
    validation_mode: str = "http"

    async def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
        tracker: UsageTracker,
    ) -> Optional[ValidationResult]:
        http_result = await self.http_validator.validate(
            action=action, obs=obs, state=state,
        )

        if http_result is not None and http_result.level == "validated":
            return http_result

        candidate: Optional[ValidationResult] = http_result
        candidate_source: str = "http"

        browser_target = bool((action.params or {}).get("browser_target") is True)
        if self.browser_validator is not None and browser_target:
            browser_result = await self.browser_validator.validate(
                action=action, obs=obs, state=state,
            )
            if browser_result is not None and browser_result.level == "validated":
                return browser_result
            if browser_result is not None:
                candidate = browser_result
                candidate_source = "browser"

        if candidate is None:
            return None

        if self.validation_mode != "agent" or self.validation_agent is None:
            return candidate

        cand = _build_candidate(
            kind=candidate.kind,
            action=action,
            obs=obs,
            state=state,
            fast_result=candidate,
            source=candidate_source,
        )

        verdict = await self.validation_agent.validate(cand, tracker=tracker)

        if verdict.passed:
            summary = f"agent_confirmed: {verdict.reason}"[:_SUMMARY_CAP]
            evidence = {
                **candidate.evidence,
                "agent": dict(verdict.evidence),
                "agent_reason": verdict.reason,
            }
            return ValidationResult(
                level="validated",
                kind=candidate.kind,
                summary=summary,
                evidence=evidence,
            )

        summary = f"agent_rejected: {verdict.reason}"[:_SUMMARY_CAP]
        evidence = {
            **candidate.evidence,
            "agent_rejection": verdict.reason,
        }
        return ValidationResult(
            level=candidate.level,
            kind=candidate.kind,
            summary=summary,
            evidence=evidence,
        )
