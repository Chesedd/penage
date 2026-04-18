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


# --- k=1 specialist slot reservation (stage 5 §1.2) ---
#
# At actions_per_step=1 the selector previously returned ranked[:1], which at
# realistic scoring (llm_base=24.0 vs sqli NOTE 5.0/11.0) meant specialist
# findings never committed. The k=1 branch now reserves the slot for the
# top-ranked specialist if any exists, preserving LLM-only behaviour otherwise.


def test_select_diverse_k1_llm_only_returns_top_llm():
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/llm-a", source="llm", family="fam:a", adjusted=24.0),
        _ranked("http://localhost/llm-b", source="llm", family="fam:b", adjusted=22.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=1,
    )

    assert [a.params["url"] for a in decision.chosen] == ["http://localhost/llm-a"]
    assert decision.chosen_source == "llm"


def test_select_diverse_k1_specialist_only_returns_top_specialist():
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/sqli-verified", source="specialists", family="fam:a", adjusted=11.0),
        _ranked("http://localhost/sqli-unverified", source="specialists", family="fam:b", adjusted=5.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=1,
    )

    assert [a.params["url"] for a in decision.chosen] == ["http://localhost/sqli-verified"]
    assert decision.chosen_source == "specialists"


def test_select_diverse_k1_mixed_reserves_specialist_slot():
    """k=1 core contract: even when LLM outscores specialist, specialist wins the slot."""
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/llm", source="llm", family="fam:a", adjusted=24.0),
        _ranked("http://localhost/sqli-verified", source="specialists", family="fam:b", adjusted=11.0),
        _ranked("http://localhost/sqli-unverified", source="specialists", family="fam:c", adjusted=5.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=1,
    )

    assert [a.params["url"] for a in decision.chosen] == ["http://localhost/sqli-verified"]
    assert decision.chosen_source == "specialists"


def test_select_diverse_k1_mixed_specialist_higher_score_still_specialist():
    """Consistency guard: when specialist already outscores LLM, behaviour is stable."""
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/sqli", source="specialists", family="fam:a", adjusted=30.0),
        _ranked("http://localhost/llm", source="llm", family="fam:b", adjusted=24.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=1,
    )

    assert [a.params["url"] for a in decision.chosen] == ["http://localhost/sqli"]
    assert decision.chosen_source == "specialists"


def test_select_diverse_k1_empty_returns_empty():
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)

    decision = selector.choose(
        state=State(),
        ranked=[],
        stats=PolicyBlockStats(),
        actions_per_step=1,
    )

    assert decision.chosen == []
    assert decision.chosen_source == "llm"


def test_select_diverse_k2_unchanged_diversity_seeding():
    """k>=2 path is not affected by the k=1 slot reservation: diversity seeding still
    returns best_spec + best_llm (in that order) when both exist with distinct families."""
    selector = DiverseActionSelector(force_breakout_no_new_paths=3, force_breakout_specialist_streak=4)
    ranked = [
        _ranked("http://localhost/llm-a", source="llm", family="fam:a", adjusted=24.0),
        _ranked("http://localhost/llm-b", source="llm", family="fam:b", adjusted=22.0),
        _ranked("http://localhost/sqli", source="specialists", family="fam:c", adjusted=11.0),
    ]

    decision = selector.choose(
        state=State(),
        ranked=ranked,
        stats=PolicyBlockStats(),
        actions_per_step=2,
    )

    urls = [a.params["url"] for a in decision.chosen]
    # best_spec seed then best_llm seed — unchanged pre-fix behaviour.
    assert urls == ["http://localhost/sqli", "http://localhost/llm-a"]
    assert decision.chosen_source == "mixed"