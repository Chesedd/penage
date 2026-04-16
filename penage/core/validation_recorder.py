from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.state_helpers import action_family
from penage.core.tracer import JsonlTracer
from penage.validation.base import EvidenceValidator, ValidationResult


@dataclass(slots=True)
class ValidationRecorder:
    tracer: JsonlTracer
    validator: Optional[EvidenceValidator] = None

    def record(self, st: State, action: Action, result: ValidationResult, *, step: int) -> None:
        item = {
            "level": result.level,
            "kind": result.kind,
            "summary": result.summary,
            "action_type": action.type.value,
            "url": str((action.params or {}).get("url") or ""),
            "family": action_family(action),
            "evidence": dict(result.evidence),
        }

        st.validation_results.append(item)
        if len(st.validation_results) > st.validation_results_limit:
            st.validation_results = st.validation_results[-st.validation_results_limit :]

        if result.level in ("evidence", "validated"):
            st.validation_evidence_count += 1
        if result.level == "validated":
            st.validation_validated_count += 1

        st.last_validation = item

        self.tracer.record_validation(item, step=step)

    def validate_and_record(self, st: State, action: Action, obs: Observation, *, step: int) -> None:
        if self.validator is None:
            return
        result = self.validator.validate(action=action, obs=obs, state=st)
        if result is None:
            return
        self.record(st, action, result, step=step)