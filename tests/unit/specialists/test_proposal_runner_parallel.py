from __future__ import annotations

import asyncio
import time
from typing import List

import pytest

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.specialists.proposal_runner import SpecialistProposalRunner


def _candidate(source: str, label: str) -> CandidateAction:
    return CandidateAction(
        action=Action(type=ActionType.HTTP, params={"method": "GET", "url": f"http://localhost/{label}"}),
        source=source,
        score=1.0,
        cost=1.0,
        reason=label,
    )


class _SleepyAsync:
    """Async specialist that awaits a sleep then returns a single candidate."""

    def __init__(self, name: str, delay: float) -> None:
        self.name = name
        self._delay = delay

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        await asyncio.sleep(self._delay)
        return [_candidate(self.name, self.name)]


class _AsyncSpecialist:
    def __init__(self, name: str, items: List[CandidateAction]) -> None:
        self.name = name
        self._items = items

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        return list(self._items)


class _BrokenAsync:
    def __init__(self, name: str) -> None:
        self.name = name

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = (state, config)
        raise ValueError("boom")


@pytest.mark.asyncio
async def test_run_mixed_runs_specialists_in_parallel():
    """With parallel=True wall-clock is close to the slowest specialist,
    not the sum of their delays."""
    runner = SpecialistProposalRunner(parallel=True)
    specialists = [_SleepyAsync(f"slow{i}", delay=0.1) for i in range(3)]

    t0 = time.perf_counter()
    out = await runner.run_mixed(State(), specialists=specialists)
    parallel_wall = time.perf_counter() - t0

    runner_seq = SpecialistProposalRunner(parallel=False)
    specialists_seq = [_SleepyAsync(f"slow{i}", delay=0.1) for i in range(3)]

    t0 = time.perf_counter()
    await runner_seq.run_mixed(State(), specialists=specialists_seq)
    sequential_wall = time.perf_counter() - t0

    assert len(out) == 3
    # Parallel must be noticeably faster than sequential. Condition chosen to
    # be stable on slow CI: parallel < sequential / 1.5.
    assert parallel_wall < sequential_wall / 1.5, (
        f"parallel={parallel_wall:.3f}s sequential={sequential_wall:.3f}s"
    )


@pytest.mark.asyncio
async def test_run_mixed_preserves_ordering():
    runner = SpecialistProposalRunner(parallel=True)
    specialists = [
        _AsyncSpecialist("a", [_candidate("a", "A")]),
        _AsyncSpecialist("b", [_candidate("b", "B")]),
        _AsyncSpecialist("c", [_candidate("c", "C")]),
    ]
    state = State()

    out = await runner.run_mixed(state, specialists=specialists)

    assert [c.source for c in out] == ["a", "b", "c"]
    assert [c.reason for c in out] == ["A", "B", "C"]
    assert state.specialist.source_counts_preview == {"a": 1, "b": 1, "c": 1}


@pytest.mark.asyncio
async def test_run_mixed_isolates_errors_from_other_specialists():
    runner = SpecialistProposalRunner(parallel=True)
    specialists = [
        _AsyncSpecialist("first", [_candidate("first", "first")]),
        _BrokenAsync("middle"),
        _AsyncSpecialist("third", [_candidate("third", "third")]),
    ]
    state = State()

    out = await runner.run_mixed(state, specialists=specialists)

    # Two survivors, in order.
    assert [c.source for c in out] == ["first", "third"]
    # Broken specialist recorded via record_specialist_error.
    errs = state.specialist.errors_preview
    assert len(errs) == 1
    assert errs[0]["specialist"] == "middle"
    assert errs[0]["error_type"] == "ValueError"
    # source_counts_preview excludes the broken specialist.
    assert state.specialist.source_counts_preview == {"first": 1, "third": 1}


@pytest.mark.asyncio
async def test_run_mixed_ablation_parallel_false_matches_parallel_true():
    """With parallel=False the sequential path must produce identical
    results (same order, same payload) as parallel=True for deterministic
    specialists."""
    specialists_p = [
        _AsyncSpecialist("a", [_candidate("a", "A")]),
        _AsyncSpecialist("b", [_candidate("b", "B")]),
        _AsyncSpecialist("c", [_candidate("c", "C")]),
    ]
    specialists_s = [
        _AsyncSpecialist("a", [_candidate("a", "A")]),
        _AsyncSpecialist("b", [_candidate("b", "B")]),
        _AsyncSpecialist("c", [_candidate("c", "C")]),
    ]

    parallel_runner = SpecialistProposalRunner(parallel=True)
    sequential_runner = SpecialistProposalRunner(parallel=False)

    state_p = State()
    state_s = State()

    out_p = await parallel_runner.run_mixed(state_p, specialists=specialists_p)
    out_s = await sequential_runner.run_mixed(state_s, specialists=specialists_s)

    assert [(c.source, c.reason) for c in out_p] == [(c.source, c.reason) for c in out_s]
    assert state_p.specialist.source_counts_preview == state_s.specialist.source_counts_preview


@pytest.mark.asyncio
async def test_run_mixed_single_specialist_works_on_sequential_path():
    """With only one active specialist the gather branch is skipped
    (len(active) > 1 is False) but the result is still correct."""
    runner = SpecialistProposalRunner(parallel=True)
    state = State()

    out = await runner.run_mixed(
        state,
        specialists=[_AsyncSpecialist("only", [_candidate("only", "only")])],
    )

    assert [c.source for c in out] == ["only"]
    assert state.specialist.source_counts_preview == {"only": 1}


@pytest.mark.asyncio
async def test_run_mixed_empty_active_clears_source_counts_preview():
    runner = SpecialistProposalRunner(
        configs={"disabled": SpecialistConfig(enabled=False)},
        parallel=True,
    )
    state = State()
    state.specialist.source_counts_preview = {"stale": 1}

    out = await runner.run_mixed(
        state,
        specialists=[_AsyncSpecialist("disabled", [_candidate("disabled", "x")])],
    )

    assert out == []
    assert state.specialist.source_counts_preview == {}
