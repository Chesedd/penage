from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.shared.oob_listener import OobHit
from penage.specialists.shared.reflection_analyzer import ReflectionContextType
from penage.specialists.vulns.ssrf import SsrfSpecialist


Responder = Callable[[Action], Observation]


@dataclass
class FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


@dataclass
class _FakeOobListener:
    """Test double for :class:`OobListener`.

    ``hit_to_return`` is the :class:`OobHit` that :meth:`wait_for_hit` yields
    (``None`` simulates timeout). ``running`` toggles :attr:`is_running`.
    """

    hit_to_return: OobHit | None = None
    running: bool = True
    token_seq: int = 0
    probe_url_template: str = "http://127.0.0.1:55555/canary/{token}"

    @property
    def is_running(self) -> bool:
        return self.running

    async def register_token(self) -> tuple[str, str]:
        self.token_seq += 1
        token = f"tok{self.token_seq:03d}" + "0" * max(0, 16 - 6)
        return token, self.probe_url_template.format(token=token)

    async def wait_for_hit(self, token: str, timeout_s: float) -> OobHit | None:
        _ = (token, timeout_s)
        return self.hit_to_return


def _param_value(action: Action, parameter: str) -> str:
    params = action.params
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _ok(text: str, *, url: str | None = None, status: int = 200) -> Observation:
    return Observation(
        ok=True,
        elapsed_ms=10,
        data={
            "status_code": status,
            "url": url,
            "headers": {"content-type": "text/html"},
            "text_full": text,
            "text_excerpt": text[:400],
        },
    )


def _state_with_query_target(base_url: str, parameter: str, value: str = "hello") -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}?{parameter}={value}"
    return st


# ---------------------------------------------------------------------------
# Phase 1 — target discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_ssrf_candidate_params_returns_empty():
    """Non-URL-ish parameter with non-URL value discovers no targets."""
    specialist = SsrfSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok("irrelevant")),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
    )
    state = _state_with_query_target("http://localhost/search", "q", value="lol")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_target_discovery_via_param_name_heuristic():
    """Parameter name ``webhook`` triggers SSRF candidacy without a URL value."""
    specialist = SsrfSpecialist()
    state = _state_with_query_target("http://localhost/app", "webhook", value="plain-text")
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].parameter == "webhook"
    assert targets[0].channel == "GET"


@pytest.mark.asyncio
async def test_target_discovery_via_url_value():
    """Parameter whose value starts with ``http://`` is a candidate even if
    the parameter name isn't on the hint list."""
    specialist = SsrfSpecialist()
    base = "http://localhost/app"
    st = State(base_url=base)
    st.last_http_url = f"{base}?foo=http%3A%2F%2Fexample.com%2F"
    targets = specialist._discover_targets(st)
    assert [t.parameter for t in targets] == ["foo"]


# ---------------------------------------------------------------------------
# Phase 2 — OOB canary probing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oob_hit_produces_verified_finding():
    """A synchronous OOB hit short-circuits into a verified ssrf_oob finding."""
    hit = OobHit(
        token="tok001" + "0" * 10,
        remote_addr="10.0.0.7",
        path="/canary/tok0010000000000000",
        headers={"User-Agent": "curl/8.0"},
        ts=time.time(),
    )
    listener = _FakeOobListener(hit_to_return=hit, running=True)

    def respond(action: Action) -> Observation:
        return _ok("<html>ok</html>", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    memory = MemoryStore(":memory:")
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=listener,  # type: ignore[arg-type]
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates, "expected a verified SSRF candidate"
    evidence = candidates[0].metadata["evidence"]
    assert evidence["verified"] is True
    assert evidence["kind"] == "ssrf_oob"
    assert evidence["mode"] == "oob"
    assert evidence["evidence"]["oob_hit"]["remote_addr"] == "10.0.0.7"
    assert candidates[0].score == 13.0


@pytest.mark.asyncio
async def test_oob_timeout_does_not_short_circuit():
    """When the OOB waiter times out, we must proceed to phase 3."""
    listener = _FakeOobListener(hit_to_return=None, running=True)

    def respond(action: Action) -> Observation:
        return _ok("<html>nothing here</html>", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        oob_listener=listener,  # type: ignore[arg-type]
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    # Phase 2 probe + at least one phase 3 probe must have been dispatched.
    assert len(http_tool.calls) >= 2


@pytest.mark.asyncio
async def test_no_listener_gracefully_skips_phase_2(tmp_path):
    """When no listener is configured, phase 2 emits a note and phase 3
    still runs."""
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-ssrf")

    http_tool = FakeHttp(responder=lambda a: _ok("no-markers-here", url=a.params.get("url")))
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        tracer=tracer,
        oob_listener=None,
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/app", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    notes = [e for e in events if e["event"] == "note"]
    assert any("ssrf:oob_listener_unavailable" in e["payload"]["text"] for e in notes)
    phases = sorted({e["payload"]["phase"] for e in events if e["event"] == "specialist_phase"})
    assert 2 not in phases  # phase 2 skipped
    assert 1 in phases and 3 in phases


# ---------------------------------------------------------------------------
# Phase 3 — internal-target probing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_internal_probe_marker_match_produces_verified_finding():
    """Response body containing ``ami-id`` on a 169.254.* probe is a
    verified metadata leak (``expected_marker`` from YAML = ``ami-id``)."""
    memory = MemoryStore(":memory:")

    def respond(action: Action) -> Observation:
        value = _param_value(action, "url")
        if "169.254.169.254" in value and "meta-data" in value:
            return _ok("ami-id\nami-launch-index\n", url=action.params.get("url"))
        return _ok("nothing", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=None,
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates
    evidence = candidates[0].metadata["evidence"]
    assert evidence["verified"] is True
    assert evidence["kind"] == "ssrf_metadata_leak"
    assert evidence["mode"] == "internal_marker"
    assert "ami-id" in evidence["evidence"]["response_markers"]
    assert candidates[0].score == 11.0


# ---------------------------------------------------------------------------
# Budget / memory / no-deps invariants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_exhaustion_short_circuits():
    """A below-minimum HTTP cap aborts cleanly without any HTTP traffic."""
    http_tool = FakeHttp(responder=lambda a: _ok("x", url="x"))
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        oob_listener=None,
        max_http_budget=4,  # below min_reserve_http default 10
    )
    state = _state_with_query_target("http://localhost/x", "url", value="http://x/")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert http_tool.calls == []


@pytest.mark.asyncio
async def test_propose_async_without_dependencies_returns_empty():
    """Missing http_tool or llm_client must yield no candidates (no crash)."""
    state = _state_with_query_target("http://localhost/x", "url", value="http://x/")
    s1 = SsrfSpecialist(http_tool=None, llm_client=FakeLLMClient(fixed_text=""))
    s2 = SsrfSpecialist(http_tool=FakeHttp(responder=lambda a: _ok("x")), llm_client=None)
    assert await s1.propose_async(state, config=SpecialistConfig()) == []
    assert await s2.propose_async(state, config=SpecialistConfig()) == []


@pytest.mark.asyncio
async def test_memory_record_attempt_called_per_outcome():
    """Every outcome must land in MemoryStore (so future runs can skip it)."""
    memory = MemoryStore(":memory:")

    def respond(action: Action) -> Observation:
        return _ok("boring", url=action.params.get("url"))

    specialist = SsrfSpecialist(
        http_tool=FakeHttp(responder=respond),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/app", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    # Any phase-2 probe_url and every phase-3 payload we sent must now be
    # recorded against this host/parameter — i.e. memory saw >=1 attempt.
    host = "localhost"
    tried_any = memory._conn.execute(
        "SELECT COUNT(*) FROM scan_state WHERE host = ? AND parameter = ?",
        (host, "url"),
    ).fetchone()[0]
    assert tried_any >= 2


# ---------------------------------------------------------------------------
# Phase 4 — payload mutation
# ---------------------------------------------------------------------------


def _latency_aware_responder(
    *,
    baseline_ms: int = 5,
    oob_ms: int = 10,
    default_ms: int = 10,
    status_by_scheme: dict[str, int] | None = None,
    body: str = "nothing interesting",
) -> Callable[[Action], Observation]:
    """Return an :class:`Observation` with variable ``elapsed_ms`` / status.

    ``baseline_ms`` is returned when the payload is ``http://0.0.0.0:1/``
    (phase-3 latency baseline). ``oob_ms`` is returned when the payload
    matches a ``/canary/`` URL (phase-2 OOB probe). ``status_by_scheme``
    lets the caller swap status codes per URL scheme to emulate
    WAF/proxy responses on ``file://``, ``gopher://`` etc.
    """

    def respond(action: Action) -> Observation:
        params = action.params
        value = _param_value(action, "url")
        status = 200
        elapsed = default_ms
        if value == "http://0.0.0.0:1/":
            elapsed = baseline_ms
        elif "/canary/" in value:
            elapsed = oob_ms
        elif status_by_scheme:
            for scheme, code in status_by_scheme.items():
                if value.startswith(scheme):
                    status = code
                    break
        return Observation(
            ok=True,
            elapsed_ms=elapsed,
            data={
                "status_code": status,
                "url": params.get("url"),
                "headers": {"content-type": "text/html"},
                "text_full": body,
                "text_excerpt": body[:400],
            },
        )

    return respond


@pytest.mark.asyncio
async def test_mutation_phase_triggered_when_phases_2_3_fail(tmp_path):
    """Phase 4 must run (and its trace fire) when phases 2 and 3 don't verify."""
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-ssrf-phase4")

    llm = FakeLLMClient(scripted=[json.dumps(["http://127.0.0.1:8080/admin"])])
    http_tool = FakeHttp(responder=_latency_aware_responder())
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=30,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phase4 = [
        e
        for e in events
        if e["event"] == "specialist_phase" and e["payload"]["phase"] == 4
    ]
    assert phase4, "phase 4 trace event missing"
    assert phase4[0]["payload"]["phase_name"] == "payload_mutation"
    assert phase4[0]["payload"]["candidates_generated"] >= 1
    assert phase4[0]["payload"]["payloads_fired"] >= 1


@pytest.mark.asyncio
async def test_mutation_payloads_fired_respects_budget():
    """``max_mutation_payloads`` caps how many mutated payloads are fired."""
    payloads = [f"http://127.0.0.1:{p}/" for p in (8080, 8081, 8082, 8083, 8084, 8085)]
    llm = FakeLLMClient(scripted=[json.dumps(payloads)])

    http_tool = FakeHttp(responder=_latency_aware_responder())
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=40,
        max_mutation_payloads=2,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    fired = [
        a for a in http_tool.calls if _param_value(a, "url").startswith("http://127.0.0.1:80")
    ]
    assert len(fired) == 2, f"expected exactly 2 mutation firings, got {len(fired)}"


@pytest.mark.asyncio
async def test_hints_outbound_latency_signal_populated():
    """OOB latency significantly above baseline → ``outbound_request_suspected``."""
    responder = _latency_aware_responder(baseline_ms=5, oob_ms=200)
    http_tool = FakeHttp(responder=responder)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=30,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates, "expected a candidate with outbound_request_suspected hint"
    evidence = candidates[0].metadata["evidence"]
    assert evidence["verified"] is False
    assert "outbound_request_suspected" in evidence["evidence"]["hints"]
    assert evidence["evidence"]["latency_ms"] == 200
    assert evidence["evidence"]["baseline_ms"] == 5


@pytest.mark.asyncio
async def test_candidate_finding_emitted_with_score_4():
    """Partial signals (5xx after scheme-bypass) produce a score-4 candidate."""
    responder = _latency_aware_responder(
        status_by_scheme={"file://": 502},
    )
    http_tool = FakeHttp(responder=responder)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=40,
        max_internal_probes=12,  # reach scheme-bypass entries in the YAML
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates, "expected a candidate finding with score=4"
    cand = candidates[0]
    assert cand.score == 4.0
    assert "unverified" in cand.action.tags
    evidence = cand.metadata["evidence"]
    assert evidence["verified"] is False
    assert evidence["kind"] == "ssrf_candidate"
    assert evidence["reason"]
    assert "5xx_after_scheme_bypass" in evidence["reason"]


@pytest.mark.asyncio
async def test_verified_oob_finding_prevents_candidate_path():
    """A verified OOB finding never downgrades to a score-4 candidate."""
    hit = OobHit(
        token="tok001" + "0" * 10,
        remote_addr="10.1.2.3",
        path="/canary/tok0010000000000000",
        headers={},
        ts=time.time(),
    )
    listener = _FakeOobListener(hit_to_return=hit, running=True)

    http_tool = FakeHttp(responder=_latency_aware_responder(baseline_ms=5, oob_ms=500))
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        oob_listener=listener,  # type: ignore[arg-type]
        max_http_budget=30,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates
    cand = candidates[0]
    assert cand.score == 13.0
    assert "verified" in cand.action.tags
    assert cand.metadata["evidence"]["verified"] is True
    assert cand.metadata["evidence"]["kind"] == "ssrf_oob"


@pytest.mark.asyncio
async def test_synthetic_filter_model_marks_blocked_schemes():
    """Phase-3 scheme-bypass probes that come back as 4xx populate the
    phase-4 ``FilterModel.transformed_chars`` with those schemes."""
    responder = _latency_aware_responder(
        status_by_scheme={"file://": 403},
    )
    http_tool = FakeHttp(responder=responder)
    llm = FakeLLMClient(fixed_text="")  # empty → mutator fires no payloads
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=40,
        max_internal_probes=12,  # reach scheme-bypass entries
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    assert llm.last_messages, "mutator should have reached the LLM"
    user_msg = next((m for m in llm.last_messages if m.role == "user"), None)
    assert user_msg is not None
    payload = json.loads(user_msg.content)
    ctx = payload["context"]
    assert ctx["type"] == ReflectionContextType.SSRF_URL_PARAM.value
    transformed = payload["filter_model"]["transformed_chars"]
    assert transformed.get("file://") == "blocked"


@pytest.mark.asyncio
async def test_phase_5_reason_populated_when_no_verification(tmp_path):
    """Phase 5 writes ``evidence_finalization`` with a non-null reason when
    at least one partial signal survived and no verification was possible."""
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-ssrf-phase5")

    responder = _latency_aware_responder(baseline_ms=5, oob_ms=120)
    http_tool = FakeHttp(responder=responder)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        tracer=tracer,
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=30,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    phase5 = [
        e
        for e in events
        if e["event"] == "specialist_phase" and e["payload"]["phase"] == 5
    ]
    assert phase5, "phase 5 trace event missing"
    final_event = phase5[-1]
    assert final_event["payload"]["verified"] is False
    assert final_event["payload"]["reason"]
    assert "outbound_request_suspected" in final_event["payload"]["reason"]
