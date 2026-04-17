from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ValidationVerdict:
    """Result of a single ``ValidationAgent.validate`` call.

    ``passed=True`` means the agent confirmed the candidate. ``passed=False``
    means the agent rejected it OR the call failed (fail-closed contract).
    ``reason`` is machine-readable when produced by the fail-closed path
    (``parse_error:...``, ``llm_exception:...``) and human-readable when
    produced by the LLM itself.
    """

    passed: bool
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def fail(cls, reason: str, **evidence: Any) -> "ValidationVerdict":
        return cls(passed=False, reason=reason, evidence=dict(evidence) if evidence else {})

    @classmethod
    def pass_(cls, reason: str, **evidence: Any) -> "ValidationVerdict":
        return cls(passed=True, reason=reason, evidence=dict(evidence) if evidence else {})
