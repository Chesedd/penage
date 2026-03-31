import pytest

from penage.core.actions import ActionType
from penage.core.guard import ExecutionGuard
from penage.core.planner import Planner
from penage.core.state import State
from penage.core.url_guard import UrlGuard
from penage.llm.fake import FakeLLMClient


class DummySyncer:
    def __init__(self):
        self.calls = 0

    def sync_research_memory_from_facts(self, st: State) -> None:
        self.calls += 1
        st.research_summary = "synced"


@pytest.mark.asyncio
async def test_planner_replans_after_repeated_action_and_returns_fresh_action():
    llm = FakeLLMClient(
        scripted=[
            '{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/repeat"}}],"note":"first"}',
            '{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/fresh"}}]}',
        ]
    )
    st = State()
    st.visited_actions_fingerprint.add('http:{"method": "GET", "url": "http://localhost/repeat"}')
    syncer = DummySyncer()
    planner = Planner(
        llm=llm,
        system_prompt="Return ONLY JSON",
        guard=ExecutionGuard(allowed={ActionType.HTTP}),
        url_guard=UrlGuard(),
        research_memory_syncer=syncer,
    )

    decision = await planner.choose_actions(step=1, user_prompt="probe", state=st)

    assert syncer.calls == 2
    assert st.llm_calls == 2
    assert decision.note == "first"
    assert len(decision.actions) == 1
    assert decision.actions[0].params["url"] == "http://localhost/fresh"


@pytest.mark.asyncio
async def test_planner_returns_stop_reason_without_actions():
    llm = FakeLLMClient(fixed_text='{"stop":true,"stop_reason":"budget","note":"done"}')
    planner = Planner(llm=llm, system_prompt="Return ONLY JSON")

    decision = await planner.choose_actions(step=2, user_prompt="stop", state=State())

    assert decision.actions == []
    assert decision.stop_reason == "budget"
    assert decision.reason == "planner_stop:budget"
    assert decision.note == "done"


@pytest.mark.asyncio
async def test_planner_filters_static_urls_and_negative_paths():
    llm = FakeLLMClient(
        fixed_text='{"actions":[{"type":"http","params":{"method":"GET","url":"http://localhost/static/app.js"}},{"type":"http","params":{"method":"GET","url":"http://localhost/blocked"}},{"type":"http","params":{"method":"GET","url":"http://localhost/ok"}}]}'
    )
    st = State(research_negatives=["/blocked"])
    planner = Planner(
        llm=llm,
        system_prompt="Return ONLY JSON",
        guard=ExecutionGuard(allowed={ActionType.HTTP}),
        url_guard=UrlGuard(),
    )

    decision = await planner.choose_actions(step=1, user_prompt="go", state=st)

    assert [a.params["url"] for a in decision.actions] == ["http://localhost/ok"]