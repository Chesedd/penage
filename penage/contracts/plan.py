from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, TypedDict, Literal

from penage.core.actions import ActionType


class PlanAction(TypedDict, total=False):
    type: str
    params: Dict[str, Any]
    timeout_s: float
    tags: List[str]


class ActionPlan(TypedDict, total=False):
    actions: List[PlanAction]
    note: str
    stop: bool
    stop_reason: str