"""Golden-trace snapshot tests for the XSS specialist.

Locks down the byte shape of the JSONL trace produced by
:class:`~penage.specialists.vulns.xss.XssSpecialist` across three
deterministic scenarios:

* ``xss_reflected_evidence`` — payload reflects in the DOM but does not
  execute; validator records ``level="evidence"``; specialist emits an
  unverified finding.
* ``xss_noop`` — no reflection at phase 2; pipeline short-circuits with
  a ``specialist_phase`` event carrying ``result="not_reflected"``; no
  validation event is written.
* ``xss_execution_proof`` — payload reflects and the JS probe reports
  a dialog marker; validator records ``level="validated"``; specialist
  emits a verified finding and a ``xss:verified`` note.

The snapshot covers (a) the sequence of JSONL trace events and
(b) each event's payload. Ephemeral fields (``ts_ms``, elapsed) are
normalized to placeholders via :func:`tests.support.golden_trace.normalize_trace`.

Regenerate fixtures with ``PENAGE_UPDATE_GOLDEN=1 pytest -q tests/integration/golden/``.
"""
from __future__ import annotations

import json

import pytest

from penage.core.tracer import JsonlTracer
from penage.core.validation_recorder import ValidationRecorder
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xss import XssSpecialist
from tests.support.golden_trace import (
    assert_trace_matches_golden,
    load_jsonl_trace,
)
from tests.support.xss_fakes import (
    FakeHttp,
    PayloadAwareBrowserValidator,
    PayloadEchoBrowser,
    noop_responder,
    state_with_form,
    vulnerable_echo,
)


_BASE_URL = "http://localhost/search"
_PARAMETER = "q"


def _build_specialist(
    tmp_path,
    *,
    episode_id: str,
    responder,
    browser_executed: bool | None,
    llm_payloads: list[str],
) -> tuple[XssSpecialist, JsonlTracer]:
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id=episode_id)
    recorder = ValidationRecorder(tracer=tracer, validator=None)
    http_tool = FakeHttp(responder=responder)
    llm = FakeLLMClient(fixed_text=json.dumps(llm_payloads) if llm_payloads else "")

    if browser_executed is None:
        validator = None
    else:
        validator = PayloadAwareBrowserValidator(
            PayloadEchoBrowser(executed=browser_executed)
        )

    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_validator=validator,
        validation_recorder=recorder,
        tracer=tracer,
    )
    return specialist, tracer


@pytest.mark.asyncio
async def test_xss_reflected_evidence_golden(tmp_path):
    specialist, tracer = _build_specialist(
        tmp_path,
        episode_id="golden-xss-reflected-evidence",
        responder=vulnerable_echo(_PARAMETER),
        browser_executed=False,
        llm_payloads=[],
    )
    state = state_with_form(_BASE_URL, _PARAMETER)
    candidates = await specialist.propose_async(
        state, config=SpecialistConfig(max_candidates=1)
    )

    assert candidates, "reflection should produce an unverified finding"
    assert candidates[0].metadata["evidence"]["verified"] is False
    assert state.last_validation is not None
    assert state.last_validation["level"] == "evidence"

    events = load_jsonl_trace(tracer.path)
    assert_trace_matches_golden(events, "xss_reflected_evidence")


@pytest.mark.asyncio
async def test_xss_noop_golden(tmp_path):
    specialist, tracer = _build_specialist(
        tmp_path,
        episode_id="golden-xss-noop",
        responder=noop_responder(),
        browser_executed=False,
        llm_payloads=[],
    )
    state = state_with_form(_BASE_URL, _PARAMETER)
    candidates = await specialist.propose_async(
        state, config=SpecialistConfig(max_candidates=1)
    )

    assert candidates == []
    assert state.last_validation is None

    events = load_jsonl_trace(tracer.path)
    assert_trace_matches_golden(events, "xss_noop")


@pytest.mark.asyncio
async def test_xss_execution_proof_golden(tmp_path):
    specialist, tracer = _build_specialist(
        tmp_path,
        episode_id="golden-xss-execution-proof",
        responder=vulnerable_echo(_PARAMETER),
        browser_executed=True,
        llm_payloads=[],
    )
    state = state_with_form(_BASE_URL, _PARAMETER)
    candidates = await specialist.propose_async(
        state, config=SpecialistConfig(max_candidates=1)
    )

    assert candidates
    finding = candidates[0].metadata["evidence"]
    assert finding["verified"] is True
    assert state.last_validation is not None
    assert state.last_validation["level"] == "validated"

    events = load_jsonl_trace(tracer.path)
    assert_trace_matches_golden(events, "xss_execution_proof")
