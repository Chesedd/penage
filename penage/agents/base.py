from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from penage.core.usage import UsageTracker
from penage.llm.base import LLMClient


class AgentRole(str, Enum):
    """Roles for MAPTA-style multi-agent split.

    Uses the ``(str, Enum)`` mixin (not ``StrEnum``) for Python 3.10
    compatibility: members compare equal to their string value.
    """

    COORDINATOR = "coordinator"
    SANDBOX = "sandbox"
    VALIDATION = "validation"


@dataclass(slots=True)
class Agent:
    """Base data holder for a role-specific agent.

    Concrete interaction protocol is defined by subclasses:
    Coordinator, Sandbox, Validation. The base class intentionally
    carries no ``step``/``act``/``run`` method — each role will
    declare its own typed signature in stages 3.2–3.4.
    """

    role: AgentRole
    system_prompt: str
    llm_client: LLMClient
    usage_tracker: UsageTracker = field(default_factory=UsageTracker)
    tool_set: Any = None
    context_window: int = 0
