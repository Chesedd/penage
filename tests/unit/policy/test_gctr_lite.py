from __future__ import annotations

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.policy.gctr_lite import GctrLitePolicy


def _http_action(url: str) -> Action:
    return Action(type=ActionType.HTTP, params={"method": "GET", "url": url})


def _candidate(url: str, *, source: str, score: float) -> CandidateAction:
    return CandidateAction(
        action=_http_action(url),
        source=source,
        score=score,
        cost=1.0,
        reason=source,
    )


def test_gctr_lite_returns_no_actions_reason_when_everything_is_blocked():
    policy = GctrLitePolicy()
    repeated = _http_action("http://localhost/repeat")
    st = State(visited_actions_fingerprint={"http:{\"method\": \"GET\", \"url\": \"http://localhost/repeat\"}"})

    decision = policy.choose_actions(
        state=st,
        llm_actions=[repeated],
        specialist_candidates=[_candidate("http://localhost/logout", source="nav", score=10.0)],
        actions_per_step=1,
    )

    assert decision.chosen == []
    assert decision.chosen_source == "llm"
    assert "blocked_logout=1" in decision.reason
    assert "blocked_repeat=1" in decision.reason


def test_gctr_lite_prefers_mixed_diverse_candidates():
    policy = GctrLitePolicy()
    st = State()

    decision = policy.choose_actions(
        state=st,
        llm_actions=[_http_action("http://localhost/llm")],
        specialist_candidates=[
            _candidate("http://localhost/spec", source="nav", score=40.0),
            _candidate("http://localhost/spec-2", source="research", score=39.0),
        ],
        actions_per_step=2,
    )

    urls = [a.params["url"] for a in decision.chosen]
    assert urls == ["http://localhost/spec", "http://localhost/llm"]
    assert decision.chosen_source == "mixed"