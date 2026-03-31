from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State


@dataclass(frozen=True, slots=True)
class ValidationResult:
    level: str
    kind: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "kind": self.kind,
            "summary": self.summary,
            "evidence": dict(self.evidence),
        }


class EvidenceValidator(Protocol):
    def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
    ) -> Optional[ValidationResult]:
        ...