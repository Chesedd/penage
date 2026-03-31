from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from penage.core.actions import Action


@dataclass(frozen=True, slots=True)
class CandidateAction:
    """
    A proposed action from any source (LLM planner, specialist, scenario engine).
    `score` is relative priority (higher = better).
    `cost` is a rough estimate (lower = cheaper); can be used by policy later.
    """
    action: Action
    source: str
    score: float = 0.0
    cost: float = 1.0
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    evidence_ref: Optional[str] = None