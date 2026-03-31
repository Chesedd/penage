from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Set

from penage.core.actions import Action, ActionType


class RunMode(str, Enum):
    SAFE_HTTP = "safe-http"
    SANDBOXED = "sandboxed"


def allowed_action_types_for_mode(mode: RunMode) -> Set[ActionType]:
    if mode == RunMode.SAFE_HTTP:
        return {ActionType.HTTP, ActionType.NOTE}
    return {
        ActionType.HTTP,
        ActionType.NOTE,
        ActionType.SHELL,
        ActionType.PYTHON,
        ActionType.MACRO,
    }


@dataclass(slots=True)
class ExecutionGuard:
    allowed: Set[ActionType]

    def filter(self, actions: Iterable[Action]) -> list[Action]:
        return [a for a in actions if a.type in self.allowed]