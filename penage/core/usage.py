from __future__ import annotations

import contextlib
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional


KNOWN_ROLES = ("specialist", "validation", "coordinator", "sandbox")


@dataclass(slots=True)
class EarlyStopThresholds:
    max_tool_calls: int = 40
    max_cost_usd: float = 0.30
    max_wall_clock_s: float = 300.0


@dataclass(slots=True)
class RoleMetrics:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    tool_calls: int = 0
    llm_calls: int = 0
    wall_clock_seconds: float = 0.0
    dollar_cost: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
            "wall_clock_seconds": round(self.wall_clock_seconds, 3),
            "dollar_cost": round(self.dollar_cost, 6),
        }


@dataclass(slots=True)
class UsageTracker:
    _roles: Dict[str, RoleMetrics] = field(default_factory=dict)
    _specialists: Dict[str, RoleMetrics] = field(default_factory=dict)
    _episode_start: float = field(default_factory=time.perf_counter)

    def _get(self, role: str) -> RoleMetrics:
        m = self._roles.get(role)
        if m is None:
            m = RoleMetrics()
            self._roles[role] = m
        return m

    def _get_specialist(self, name: str) -> RoleMetrics:
        m = self._specialists.get(name)
        if m is None:
            m = RoleMetrics()
            self._specialists[name] = m
        return m

    def record_llm_call(
        self,
        role: str,
        provider_name: str,
        token_usage: Dict[str, int],
        cost: float = 0.0,
        *,
        specialist: Optional[str] = None,
    ) -> None:
        input_tokens = int(token_usage.get("input_tokens") or 0)
        output_tokens = int(token_usage.get("output_tokens") or 0)
        cached_tokens = int(token_usage.get("cached_tokens") or 0)
        reasoning_tokens = int(token_usage.get("reasoning_tokens") or 0)

        m = self._get(role)
        m.llm_calls += 1
        m.input_tokens += input_tokens
        m.output_tokens += output_tokens
        m.cached_tokens += cached_tokens
        m.reasoning_tokens += reasoning_tokens
        m.dollar_cost += float(cost)

        if specialist:
            sm = self._get_specialist(specialist)
            sm.llm_calls += 1
            sm.input_tokens += input_tokens
            sm.output_tokens += output_tokens
            sm.cached_tokens += cached_tokens
            sm.reasoning_tokens += reasoning_tokens

    def record_tool_call(self, role: str, duration_seconds: float) -> None:
        m = self._get(role)
        m.tool_calls += 1
        m.wall_clock_seconds += float(duration_seconds)

    @property
    def total_tool_calls(self) -> int:
        return sum(m.tool_calls for m in self._roles.values())

    @property
    def total_llm_calls(self) -> int:
        return sum(m.llm_calls for m in self._roles.values())

    @property
    def total_cost_usd(self) -> float:
        return sum(m.dollar_cost for m in self._roles.values())

    @property
    def total_input_tokens(self) -> int:
        return sum(m.input_tokens for m in self._roles.values())

    @property
    def total_output_tokens(self) -> int:
        return sum(m.output_tokens for m in self._roles.values())

    @property
    def episode_wall_clock_s(self) -> float:
        return time.perf_counter() - self._episode_start

    def check_early_stop(self, thresholds: EarlyStopThresholds) -> Optional[str]:
        tc = self.total_tool_calls
        if thresholds.max_tool_calls > 0 and tc >= thresholds.max_tool_calls:
            return f"tool_calls={tc}>={thresholds.max_tool_calls}"

        cost = self.total_cost_usd
        if thresholds.max_cost_usd > 0 and cost >= thresholds.max_cost_usd:
            return f"cost_usd={cost:.4f}>={thresholds.max_cost_usd:.4f}"

        wall = self.episode_wall_clock_s
        if thresholds.max_wall_clock_s > 0 and wall >= thresholds.max_wall_clock_s:
            return f"wall_clock_s={wall:.1f}>={thresholds.max_wall_clock_s:.1f}"

        return None

    def to_dict(self) -> Dict[str, object]:
        by_role: Dict[str, object] = {}
        for role in sorted(self._roles):
            by_role[role] = self._roles[role].to_dict()

        by_specialist: Dict[str, object] = {}
        for name in sorted(self._specialists):
            by_specialist[name] = self._specialists[name].to_dict()

        return {
            "by_role": by_role,
            "by_specialist": by_specialist,
            "totals": {
                "input_tokens": self.total_input_tokens,
                "output_tokens": self.total_output_tokens,
                "cached_tokens": sum(m.cached_tokens for m in self._roles.values()),
                "reasoning_tokens": sum(m.reasoning_tokens for m in self._roles.values()),
                "tool_calls": self.total_tool_calls,
                "llm_calls": self.total_llm_calls,
                "wall_clock_s": round(self.episode_wall_clock_s, 3),
                "api_cost_usd": round(self.total_cost_usd, 6),
            },
        }


_current_usage_tracker: ContextVar[Optional["UsageTracker"]] = ContextVar(
    "_current_usage_tracker", default=None
)


def current_usage_tracker() -> Optional["UsageTracker"]:
    """Return the tracker bound to the current task/thread, or None."""
    return _current_usage_tracker.get()


@contextlib.contextmanager
def bind_usage_tracker(tracker: "UsageTracker") -> Iterator["UsageTracker"]:
    """Bind `tracker` as the current usage tracker for the duration of the `with` block."""
    token = _current_usage_tracker.set(tracker)
    try:
        yield tracker
    finally:
        _current_usage_tracker.reset(token)
