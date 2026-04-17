from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.usage import UsageTracker
from penage.validation.base import EvidenceValidator, ValidationResult
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
    http_result: ValidationResult,
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
        evidence_so_far={"http": http_result.to_dict()},
    )


@dataclass(slots=True)
class ValidationGate:
    """Two-stage cascade: HTTP validator → optional ValidationAgent.

    Stage 1 (sync): ``http_validator.validate(...)`` classifies the
    observation. ``None`` means no finding; ``"validated"`` means a
    fast-pass (no LLM cost); any other level is a candidate.

    Stage 2 (async, optional): when ``validation_mode == "agent"`` and
    a ``validation_agent`` is configured, candidates are escalated to
    the LLM role. A ``pass`` verdict upgrades the result to
    ``"validated"``; a ``fail`` verdict leaves it as the original
    non-validated level and annotates the evidence.

    Browser verification is NOT done here — it remains the
    responsibility of the specialist (e.g. ``XssSpecialist`` phase 5).
    The gate is a post-hoc classifier over what specialists already
    observed.
    """

    http_validator: EvidenceValidator
    validation_agent: Optional[ValidationAgent] = None
    validation_mode: str = "http"

    async def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
        tracker: UsageTracker,
    ) -> Optional[ValidationResult]:
        http_result = self.http_validator.validate(
            action=action, obs=obs, state=state,
        )
        if http_result is None:
            return None

        if http_result.level == "validated":
            return http_result

        if self.validation_mode != "agent" or self.validation_agent is None:
            return http_result

        candidate = _build_candidate(
            kind=http_result.kind,
            action=action,
            obs=obs,
            state=state,
            http_result=http_result,
        )

        verdict = await self.validation_agent.validate(candidate, tracker=tracker)

        if verdict.passed:
            summary = f"agent_confirmed: {verdict.reason}"[:_SUMMARY_CAP]
            evidence = {
                **http_result.evidence,
                "agent": dict(verdict.evidence),
                "agent_reason": verdict.reason,
            }
            return ValidationResult(
                level="validated",
                kind=http_result.kind,
                summary=summary,
                evidence=evidence,
            )

        summary = f"agent_rejected: {verdict.reason}"[:_SUMMARY_CAP]
        evidence = {
            **http_result.evidence,
            "agent_rejection": verdict.reason,
        }
        return ValidationResult(
            level=http_result.level,
            kind=http_result.kind,
            summary=summary,
            evidence=evidence,
        )
