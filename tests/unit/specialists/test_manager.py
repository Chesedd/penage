from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.specialists.manager import SpecialistManager


class _SyncSpecialist:
    def __init__(self, name: str, items: list[CandidateAction]):
        self.name = name
        self._items = items

    def propose(self, state: State, *, config: SpecialistConfig) -> list[CandidateAction]:
        _ = (state, config)
        return list(self._items)


class _AsyncSpecialist:
    def __init__(self, name: str, items: list[CandidateAction]):
        self.name = name
        self._items = items

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> list[CandidateAction]:
        _ = (state, config)
        return list(self._items)


class _BrokenSpecialist:
    name = "broken"

    def propose(self, state: State, *, config: SpecialistConfig) -> list[CandidateAction]:
        _ = (state, config)
        raise RuntimeError("boom")


def _http_candidate(*, url: str, source: str, score: float, cost: float = 1.0) -> CandidateAction:
    return CandidateAction(
        action=Action(type=ActionType.HTTP, params={"method": "GET", "url": url}),
        source=source,
        score=score,
        cost=cost,
        reason=f"from {source}",
    )


def test_specialist_manager_deduplicates_and_caps_source_dominance():
    duplicate_low = _http_candidate(url="http://localhost/same", source="alpha", score=5.0)
    duplicate_high = _http_candidate(url="http://localhost/same", source="beta", score=9.0)
    alpha_many = [_http_candidate(url=f"http://localhost/a{i}", source="alpha", score=20.0 - i) for i in range(6)]

    manager = SpecialistManager(
        specialists=[
            _SyncSpecialist("alpha", [duplicate_low, *alpha_many]),
            _SyncSpecialist("beta", [duplicate_high]),
        ]
    )

    out = manager.propose_all(State())

    same = [c for c in out if c.action.params["url"] == "http://localhost/same"]
    assert len(same) == 1
    assert same[0].source == "beta"

    alpha_out = [c for c in out if c.source == "alpha"]
    assert len(alpha_out) == 4


@pytest.mark.asyncio
async def test_specialist_manager_records_errors_and_runs_async_specialists():
    async_items = [_http_candidate(url="http://localhost/async", source="asyncer", score=7.0)]
    manager = SpecialistManager(
        specialists=[
            _BrokenSpecialist(),
            _AsyncSpecialist("asyncer", async_items),
        ]
    )
    state = State()

    out = await manager.propose_all_async(state)

    assert len(out) == 1
    assert out[0].source == "asyncer"
    assert state.specialist.source_counts_preview == {"asyncer": 1}
    errs = state.specialist.errors_preview
    assert len(errs) == 1
    assert errs[0]["specialist"] == "broken"
    assert errs[0]["error_type"] == "RuntimeError"