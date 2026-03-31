from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(str, Enum):
    HTTP = "http"
    SHELL = "shell"
    PYTHON = "python"
    NOTE = "note"
    MACRO = "macro"


@dataclass(frozen=True, slots=True)
class Action:
    type: ActionType
    params: Dict[str, Any] = field(default_factory=dict)
    timeout_s: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "params": self.params,
            "timeout_s": self.timeout_s,
            "tags": list(self.tags),
        }