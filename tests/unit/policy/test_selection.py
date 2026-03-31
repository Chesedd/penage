from __future__ import annotations

from penage.core.actions import Action, ActionType
from penage.core.state import State
from penage.policy.ranking import PolicyBlockStats, RankedAction
from penage.policy.selection import DiverseActionSelector


def _ranked(url: str, *, source: str, family: str, adjusted: float) -> RankedAction:
    return RankedAction(
        action=Action(type=ActionType.HTTP, params={"method": "GET", "url": url}),
        source=source,
        source_name=source,
        raw_score=adjusted,
        adjusted_score=adjusted,
        cost=1.0,
        family=family,
        path=url,
        reason=source,
    )


def test_selector_prefers_mixed_seeds_and_diverse_families():
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/spec-a", source="specialists", family="fam:a", adjusted=30.0),
        _ranked("http://localhost/spec-b", source="specialists", family="fam:b", adjusted=29.0),
        _ranked("http://localhost/llm-a", source="llm", family="fam:c", adjusted=28.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=2,
    )

    urls = [a.params["url"] for a in decision.chosen]
    assert urls == ["http://localhost/spec-a", "http://localhost/llm-a"]
    assert decision.chosen_source == "mixed"


def test_selector_forces_breakout_to_llm_when_stuck_on_specialists():
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    state = State(no_new_paths_streak=5, last_policy_source="specialists", same_policy_source_streak=4)
    ranked = [
        _ranked("http://localhost/spec", source="specialists", family="fam:a", adjusted=100.0),
        _ranked("http://localhost/llm", source="llm", family="fam:b", adjusted=20.0),
    ]

    decision = selector.choose(
        state=state,
        ranked=ranked,
        stats=PolicyBlockStats(blocked_repeat=1),
        actions_per_step=1,
    )

    assert [a.params["url"] for a in decision.chosen] == ["http://localhost/llm"]
    assert decision.chosen_source == "llm"
    assert decision.reason.startswith("forced_breakout:")